##
# (c) 2021-2025
#     Cloud Ops Works LLC - https://cloudops.works/
#     Find us on:
#       GitHub: https://github.com/cloudopsworks
#       WebSite: https://cloudops.works
#     Distributed Under Apache v2.0 License
#
output "lambda_name" {
  value = aws_lambda_function.this.function_name
}

output "lambda_arn" {
  value = aws_lambda_function.this.arn
}

output "lambda_exec_role" {
  value = aws_iam_role.default_lambda_function.name
}

output "lambda_exec_role_arn" {
  value = aws_iam_role.default_lambda_function.arn
}

output "lambda_cloudwatch_log" {
  value = aws_cloudwatch_log_group.logs.name
}

output "lambda_cloudwatch_log_arn" {
  value = aws_cloudwatch_log_group.logs.arn
}

output "lambda_security_group_name" {
  value = try(var.vpc.create_security_group, false) && try(var.vpc.enabled, false) ? aws_security_group.this[0].name : null
}

output "lambda_security_group_id" {
  value = try(var.vpc.create_security_group, false) && try(var.vpc.enabled, false) ? aws_security_group.this[0].id : null
}