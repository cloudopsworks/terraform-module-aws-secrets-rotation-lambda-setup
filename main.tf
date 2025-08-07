##
# (c) 2021-2025
#     Cloud Ops Works LLC - https://cloudops.works/
#     Find us on:
#       GitHub: https://github.com/cloudopsworks
#       WebSite: https://cloudops.works
#     Distributed Under Apache v2.0 License
#

locals {
  multi_user          = try(var.settings.multi_user, false)
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
  }
  variables = concat(try(var.settings.environment.variables, []),
    [
      {
        name  = "SECRETS_MANAGER_ENDPOINT"
        value = "https://secretsmanager.${data.aws_region.current.name}.amazonaws.com"
      },
    ],
    try(var.settings.password_length, -1) >= 24 ? [
      {
        name  = "PASSWORD_LENGTH"
        value = tostring(var.settings.password_length)
    }] : []
  )
  source_root = "lambda_code/${var.settings.type}/${local.multi_user == true ? "multiuser" : "single"}"
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
  count = local.pip_map[var.settings.type] != "[golang]" ? 1 : 0
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
    command     = "GOOS=linux GOARCH=amd64 go build -o bootstrap"
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
  dynamic "vpc_config" {
    for_each = try(var.vpc.enabled, false) ? [1] : []
    content {
      security_group_ids = try(var.vpc.create_security_group, false) ? [aws_security_group.this[0].id] : var.vpc.security_groups
      subnet_ids         = var.vpc.subnets
    }
  }
  environment {
    variables = {
      for item in local.variables :
      item.name => item.value
    }
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
  ]
}