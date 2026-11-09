##
# (c) 2021-2026
#     Cloud Ops Works LLC - https://cloudops.works/
#     Find us on:
#       GitHub: https://github.com/cloudopsworks
#       WebSite: https://cloudops.works
#     Distributed Under Apache v2.0 License
#

locals {
  api_key_rotation      = contains(["openai", "openrouter"], var.settings.type)
  management_secret_id  = try(trimspace(var.settings.management_api_key.secret_arn), null)
  management_secret_arn = local.api_key_rotation ? data.aws_secretsmanager_secret.management_api_key[0].arn : null
  multi_user            = try(var.settings.multi_user, false)
  function_name         = "secrets-rotation-${var.settings.type}-${local.system_name}${local.multi_user == true ? "-multiuser" : ""}"
  function_name_short   = "secrets-rotation-${var.settings.type}-${local.system_name_short}${local.multi_user == true ? "-mu" : ""}"
  pip_map = {
    postgres     = "\"psycopg[binary]\" typing_extensions"
    mysql        = "PyMySQL"
    mariadb      = "PyMySQL"
    mssql        = "pymssql"
    mongodb      = "pymongo"
    mongodbatlas = "[golang]"
    oracle       = "python-oracledb"
    db2          = "python-ibmdb"
    openai       = "[stdlib]"
    openrouter   = "[stdlib]"
  }
  openrouter_key_options = {
    for key, value in try(var.settings.openrouter, {}) : key => value
    if contains(["limit", "limit_reset", "include_byok_in_limit", "expires_at", "workspace_id", "creator_user_id"], key)
  }
  openai_key_options = {
    for key, value in try(var.settings.openai, {}) : key => value
    if contains(["scopes", "expires_in_seconds"], key)
  }
  variables = merge(
    { for item in try(var.settings.environment.variables, []) : item.name => item.value },
    { SECRETS_MANAGER_ENDPOINT = "https://secretsmanager.${data.aws_region.current.region}.amazonaws.com" },
    !local.api_key_rotation && try(var.settings.password_length, -1) >= 24 ? { PASSWORD_LENGTH = tostring(var.settings.password_length) } : {},
    local.api_key_rotation ? merge({
      API_PROVIDER          = var.settings.type
      MANAGEMENT_SECRET_ARN = local.management_secret_arn
      ROTATION_KEY_NAME     = coalesce(try(var.settings.api_key_name, null), "rotated-api-key")
      }, var.settings.type == "openai" ? {
      OPENAI_PROJECT_ID         = try(var.settings.openai.project_id, "")
      OPENAI_SERVICE_ACCOUNT_ID = try(var.settings.openai.service_account_id, "")
      OPENAI_KEY_OPTIONS_JSON   = jsonencode(local.openai_key_options)
      } : {
      OPENROUTER_KEY_OPTIONS_JSON = jsonencode(local.openrouter_key_options)
    }) : {}
  )
  source_root = local.api_key_rotation ? "lambda_code/api_keys/single" : "lambda_code/${var.settings.type}/${local.multi_user == true ? "multiuser" : "single"}"
  source_dir  = "${path.module}/${local.source_root}"
  files_base64sha256 = base64encode(sha256(join("", [
    for item in fileset(path.module, "${local.source_root}/**/*") : filesha256(item)
  ])))
  archive_file_name = "/tmp/lambda_rotation.zip"
}

moved {
  from = terraform_data.function_pip
  to   = terraform_data.function_pip[0]
}

resource "terraform_data" "function_pip" {
  count = !contains(["[golang]", "[stdlib]"], local.pip_map[var.settings.type]) ? 1 : 0
  triggers_replace = {
    always_run = tostring(timestamp())
  }
  input = local.files_base64sha256
  provisioner "local-exec" {
    working_dir = path.module
    command     = "pip3 install --platform manylinux2014_x86_64 --target ${local.source_dir} --python-version 3.12 --implementation cp --only-binary=:all: --upgrade ${local.pip_map[var.settings.type]} "
  }
}

resource "terraform_data" "function_golang" {
  count = local.pip_map[var.settings.type] == "[golang]" ? 1 : 0
  triggers_replace = {
    always_run = tostring(timestamp())
  }
  input = local.files_base64sha256
  provisioner "local-exec" {
    working_dir = "${local.source_dir}/"
    command     = "GOOS=linux GOARCH=amd64 go build -ldflags \"-s -w\" -o bootstrap"
  }
  provisioner "local-exec" {
    working_dir = "${local.source_dir}/"
    command     = "chmod +x bootstrap"
  }
}

resource "terraform_data" "archive_file" {
  triggers_replace = {
    always_run = tostring(timestamp())
  }
  input = local.files_base64sha256
  provisioner "local-exec" {
    command = "[ -f ${local.archive_file_name} ] && rm -f ${local.archive_file_name} || echo 'No existing archive to remove, sikipping...'"
  }
  provisioner "local-exec" {
    working_dir = local.source_dir
    command     = "zip -r ${local.archive_file_name} ."
  }
  depends_on = [terraform_data.function_pip, terraform_data.function_golang]
}

resource "aws_lambda_function" "this" {
  function_name    = local.function_name
  description      = try(var.settings.description, "Secret Rotation Lambda - ${var.settings.type} - MultiUser: ${local.multi_user == true ? "Yes" : "No"}")
  role             = aws_iam_role.default_lambda_function.arn
  handler          = var.settings.type == "mongodbatlas" ? "bootstrap" : "lambda_function.lambda_handler"
  runtime          = var.settings.type == "mongodbatlas" ? "provided.al2023" : "python3.12"
  package_type     = "Zip"
  filename         = local.archive_file_name
  source_code_hash = local.files_base64sha256
  memory_size      = try(var.settings.memory_size, 128)
  timeout          = try(var.settings.timeout, 60)
  publish          = true
  lifecycle {
    precondition {
      condition     = !local.api_key_rotation || !local.multi_user
      error_message = "API key rotation supports only the single-user strategy; set settings.multi_user to false."
    }
    precondition {
      condition = var.settings.type != "openai" || (
        try(length(trimspace(var.settings.openai.project_id)) > 0, false) &&
        try(length(trimspace(var.settings.openai.service_account_id)) > 0, false)
      )
      error_message = "OpenAI rotation requires settings.openai.project_id and settings.openai.service_account_id."
    }
    precondition {
      condition = var.settings.type != "openai" || try(var.settings.openai.expires_in_seconds, null) == null || (
        try(var.settings.openai.expires_in_seconds >= 1 && var.settings.openai.expires_in_seconds <= 31536000, false)
      )
      error_message = "settings.openai.expires_in_seconds must be between 1 and 31536000, or null."
    }
    precondition {
      condition     = !local.api_key_rotation || length(try(var.settings.allowed_secrets, [])) > 0
      error_message = "API key rotation requires the target secret ARN in settings.allowed_secrets."
    }
  }
  dynamic "vpc_config" {
    for_each = try(var.vpc.enabled, false) ? [1] : []
    content {
      security_group_ids = try(var.vpc.create_security_group, false) ? [aws_security_group.this[0].id] : var.vpc.security_groups
      subnet_ids         = var.vpc.subnets
    }
  }
  environment {
    variables = local.variables
  }
  logging_config {
    application_log_level = try(var.settings.logging.application_log_level, null)
    log_format            = try(var.settings.logging.log_format, "JSON")
    log_group             = aws_cloudwatch_log_group.logs.name
    system_log_level      = try(var.settings.logging.system_log_level, null)
  }
  tags = local.all_tags
  depends_on = [
    aws_cloudwatch_log_group.logs,
    aws_iam_role_policy.allowed_secrets,
    aws_iam_role_policy.management_api_key,
    aws_iam_role_policy.management_api_key_kms,
    terraform_data.archive_file
  ]
}
