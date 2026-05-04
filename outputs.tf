##
# (c) 2021-2025
#     Cloud Ops Works LLC - https://cloudops.works/
#     Find us on:
#       GitHub: https://github.com/cloudopsworks
#       WebSite: https://cloudops.works
#     Distributed Under Apache v2.0 License
#
output "lambda_name" {
  description = "Name of the Secrets Manager rotation Lambda function."
  value       = aws_lambda_function.this.function_name
}

output "lambda_arn" {
  description = "ARN of the Secrets Manager rotation Lambda function."
  value       = aws_lambda_function.this.arn
}

output "lambda_exec_role" {
  description = "Name of the IAM execution role attached to the rotation Lambda."
  value       = aws_iam_role.default_lambda_function.name
}

output "lambda_exec_role_arn" {
  description = "ARN of the IAM execution role attached to the rotation Lambda."
  value       = aws_iam_role.default_lambda_function.arn
}

output "lambda_cloudwatch_log" {
  description = "Name of the CloudWatch Logs group used by the rotation Lambda."
  value       = aws_cloudwatch_log_group.logs.name
}

output "lambda_cloudwatch_log_arn" {
  description = "ARN of the CloudWatch Logs group used by the rotation Lambda."
  value       = aws_cloudwatch_log_group.logs.arn
}

output "lambda_security_group_name" {
  description = "Name of the security group created for the rotation Lambda when VPC mode is enabled and create_security_group is true."
  value       = try(var.vpc.create_security_group, false) && try(var.vpc.enabled, false) ? aws_security_group.this[0].name : null
}

output "lambda_security_group_id" {
  description = "ID of the security group created for the rotation Lambda when VPC mode is enabled and create_security_group is true."
  value       = try(var.vpc.create_security_group, false) && try(var.vpc.enabled, false) ? aws_security_group.this[0].id : null
}