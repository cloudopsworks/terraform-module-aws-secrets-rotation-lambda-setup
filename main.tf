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
  golang_build          = local.pip_map[var.settings.type] == "[golang]"
  python_version        = tostring(coalesce(try(var.settings.python_version, null), "3.15"))
  lambda_runtime        = local.golang_build ? "provided.al2023" : "python${local.python_version}"
  # AL2023-based runtimes ship glibc 2.34, so both legacy manylinux2014 and newer manylinux_2_28 wheels load.
  pip_platforms       = ["manylinux_2_28_x86_64", "manylinux2014_x86_64"]
  function_name       = "secrets-rotation-${var.settings.type}-${local.system_name}${local.multi_user == true ? "-multiuser" : ""}"
  function_name_short = "secrets-rotation-${var.settings.type}-${local.system_name_short}${local.multi_user == true ? "-mu" : ""}"
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
    if key == "expires_at"
  }
  variables = merge(
    { for item in try(var.settings.environment.variables, []) : item.name => item.value },
    { SECRETS_MANAGER_ENDPOINT = "https://secretsmanager.${data.aws_region.current.region}.amazonaws.com" },
    !local.api_key_rotation && try(var.settings.password_length, -1) >= 24 ? { PASSWORD_LENGTH = tostring(var.settings.password_length) } : {},
    local.api_key_rotation ? merge({
      API_PROVIDER          = var.settings.type
      MANAGEMENT_SECRET_ARN = local.management_secret_arn
      }, var.settings.type == "openai" ? {
      OPENAI_ORGANIZATION_ID = try(var.settings.openai.organization_id, "")
      } : {
      OPENROUTER_KEY_OPTIONS_JSON = jsonencode(local.openrouter_key_options)
    }) : {}
  )
  source_root = local.api_key_rotation ? "lambda_code/api_keys/single" : "lambda_code/${var.settings.type}/${local.multi_user == true ? "multiuser" : "single"}"
  source_dir  = "${path.module}/${local.source_root}"
  # The runtime is part of the hash so a runtime change re-uploads a package built for that runtime.
  files_base64sha256 = base64encode(sha256(join("", concat([local.lambda_runtime], [
    for item in fileset(path.module, "${local.source_root}/**/*") : filesha256(item)
  ]))))
  # Per-instance archive under the root module's .terraform directory instead of the world-writable /tmp,
  # so parallel units never overwrite each other's package. The hash keeps org-derived names out of the path.
  archive_file_name = "${path.root}/.terraform/lambda-build/${substr(sha256(local.function_name), 0, 16)}.zip"
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
  # Variable values reach the shell only through quoted environment variables, never by interpolation.
  # Package specs and platform tags are module-owned constants.
  provisioner "local-exec" {
    working_dir = path.module
    command     = "pip3 install ${join(" ", [for platform in local.pip_platforms : "--platform ${platform}"])} --target \"$TARGET_DIR\" --python-version \"$PYTHON_VERSION\" --implementation cp --only-binary=:all: --upgrade ${local.pip_map[var.settings.type]}"
    environment = {
      TARGET_DIR     = local.source_dir
      PYTHON_VERSION = local.python_version
    }
  }
}

resource "terraform_data" "function_golang" {
  count = local.golang_build ? 1 : 0
  triggers_replace = {
    always_run = tostring(timestamp())
  }
  input = local.files_base64sha256
  provisioner "local-exec" {
    working_dir = "${local.source_dir}/"
    command     = "CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -tags lambda.norpc -ldflags \"-s -w\" -o bootstrap"
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
    command = "mkdir -p \"$(dirname \"$ARCHIVE_FILE\")\" && rm -f \"$ARCHIVE_FILE\""
    environment = {
      ARCHIVE_FILE = abspath(local.archive_file_name)
    }
  }
  provisioner "local-exec" {
    working_dir = local.source_dir
    command     = "zip -r \"$ARCHIVE_FILE\" ."
    environment = {
      ARCHIVE_FILE = abspath(local.archive_file_name)
    }
  }
  depends_on = [terraform_data.function_pip, terraform_data.function_golang]
}

resource "aws_lambda_function" "this" {
  function_name    = local.function_name
  description      = try(var.settings.description, "Secret Rotation Lambda - ${var.settings.type} - MultiUser: ${local.multi_user == true ? "Yes" : "No"}")
  role             = aws_iam_role.default_lambda_function.arn
  handler          = local.golang_build ? "bootstrap" : "lambda_function.lambda_handler"
  runtime          = local.lambda_runtime
  package_type     = "Zip"
  filename         = local.archive_file_name
  source_code_hash = local.files_base64sha256
  memory_size      = try(var.settings.memory_size, 128)
  timeout          = try(var.settings.timeout, 60)
  publish          = true
  lifecycle {
    precondition {
      condition     = local.golang_build || length(fileset(path.module, "${local.source_root}/lambda_function.py")) > 0
      error_message = "No bundled Lambda source exists for this settings.type / settings.multi_user combination (${local.source_root})."
    }
    precondition {
      condition     = !local.api_key_rotation || !local.multi_user
      error_message = "API key rotation supports only the single-user strategy; set settings.multi_user to false."
    }
    precondition {
      condition     = var.settings.type != "openai" || try(length(trimspace(var.settings.openai.organization_id)) > 0, false)
      error_message = "OpenAI rotation requires settings.openai.organization_id."
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
