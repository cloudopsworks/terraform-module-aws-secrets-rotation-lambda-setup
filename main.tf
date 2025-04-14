##
# (c) 2024 - Cloud Ops Works LLC - https://cloudops.works/
#            On GitHub: https://github.com/cloudopsworks
#            Distributed Under Apache v2.0 License
#

locals {
  function_name = try(var.settings.name, "") != "" ? var.settings.name : "${var.settings.name_prefix}-${var.settings.type}-${local.system_name}"
  multi_user    = try(var.settings.multi_user, false)
}

data "archive_file" "rotate_code" {
  type        = "zip"
  source_dir  = "${path.module}/lambda_code/${var.settings.type}/${local.multi_user == true ? "multiuser" : "single"}"
  output_path = "${path.module}/lambda_rotation.zip"
}

resource "aws_lambda_function" "this" {
  function_name    = local.function_name
  description      = try(var.settings.description, "Secret Rotation Lambda - ${try(var.settings.name, "") != "" ? var.settings.name : var.settings.name_prefix} - ${var.settings.type} - MultiUser: ${local.multi_user}")
  role             = aws_iam_role.default_lambda_function.arn
  handler          = "rotation_function.lambda_handler"
  runtime          = "python3.12"
  package_type     = "Zip"
  filename         = data.archive_file.rotate_code.output_path
  source_code_hash = data.archive_file.rotate_code.output_base64sha256
  memory_size      = try(var.settings.memory_size, 128)
  timeout          = try(var.settings.timeout, 60)
  publish          = true
  dynamic "vpc_config" {
    for_each = try(var.settings.vpc.enabled, false) ? [1] : []
    content {
      security_group_ids = try(var.settings.vpc.create_security_group, false) ? [aws_security_group.this[0].id] : var.settings.vpc.security_groups
      subnet_ids         = var.settings.vpc.subnets
    }
  }
  environment {
    variables = {
      for item in var.settings.environment.variables :
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