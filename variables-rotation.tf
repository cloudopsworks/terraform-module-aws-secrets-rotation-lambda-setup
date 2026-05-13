##
# (c) 2021-2025
#     Cloud Ops Works LLC - https://cloudops.works/
#     Find us on:
#       GitHub: https://github.com/cloudopsworks
#       WebSite: https://cloudops.works
#     Distributed Under Apache v2.0 License
#

## YAML Specification Settings
# settings:
#   type: postgres | mysql | mariadb | mssql | mongodb | mongodbatlas | oracle | db2  # (Required) Database engine used by the rotation Lambda.
#   description: "<description>"  # (Optional) Custom Lambda description. Default: Terraform builds one from type and multi_user.
#   multi_user: true | false      # (Optional) Enable alternating-users rotation strategy. Default: false.
#   timeout: 60                   # (Optional) Lambda timeout in seconds. Default: 60.
#   memory_size: 128              # (Optional) Lambda memory size in MB. Default: 128.
#   password_length: 30           # (Optional) Generated password length. Default: 30. Must be >= 24.
#   log_retention_days: 14        # (Optional) CloudWatch Logs retention in days. Default: 14.
#   logging:                      # (Optional) Lambda advanced logging configuration.
#     log_format: JSON | Text     # (Optional) Log output format. Default: JSON.
#     application_log_level: TRACE | DEBUG | INFO | WARN | ERROR | FATAL  # (Optional) Application log threshold. Default: INFO.
#     system_log_level: DEBUG | INFO | WARN  # (Optional) System log threshold. Default: INFO.
#   environment:                  # (Optional) Additional Lambda environment variables.
#     variables:
#       - name: VAR_NAME          # (Required) Environment variable name.
#         value: var_value        # (Required) Environment variable value.
#   allowed_secrets:              # (Optional) Secrets Manager secret ARNs the rotation function may read and update.
#     - arn:aws:secretsmanager:<region>:<account>:secret:<name>
#   allowed_kms:                  # (Optional) KMS key ARNs used to decrypt the allowed secrets.
#     - arn:aws:kms:<region>:<account>:key/<key-id>
#   iam:                          # (Optional) Additional IAM policy statements to attach to the Lambda execution role.
#     statements:
#       - effect: Allow | Deny    # (Required) IAM statement effect.
#         action:                 # (Required) IAM actions to allow or deny.
#           - <service:action>
#         resource:               # (Required) ARNs the statement applies to.
#           - <arn>
variable "settings" {
  description = "Settings for the module"
  type        = any
  default     = {}
}

## VPC Settings yaml Specification
# vpc:
#   enabled: true | false              # (Optional) Attach the Lambda function to a VPC. Default: false.
#   subnets:                           # (Required when vpc.enabled is true) Private subnet IDs for Lambda ENIs.
#     - subnet-12345678
#   create_security_group: true | false # (Optional) Create a dedicated security group for the Lambda. Default: false.
#   security_groups:                   # (Required when vpc.enabled is true and create_security_group is false) Existing SG IDs to attach.
#     - sg-12345678
variable "vpc" {
  description = "VPC settings for the module"
  type        = any
  default     = {}
}