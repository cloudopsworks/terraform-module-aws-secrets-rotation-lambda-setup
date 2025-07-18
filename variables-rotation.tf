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
#   description: "<description>" # (optional) Description of the Lambda function
#   type: mongodb | postgres | mysql | mariadb | mssql | mongodbatlas
#   multi_user: true | false # Defaults to false
#   timeout: 30 # (optional) Timeout in seconds, defaults to 60
#   memory_size: 128 # (optional) Memory size in MB, defaults to 128
#   password_length: 30 # Defaults to 30, and must be greater than 24
#   logging:       # (optional) Logging settings
#     log_format: JSON | TEXT # Defaults to json
#     application_log_level: INFO | DEBUG | ERROR # Defaults to INFO
#     system_log_level: INFO | DEBUG | ERROR # Defaults to INFO
#   environment:
#     variables:
#       - name: ANOTHER_ENV_VAR
#         value: some_value
#       - name: ANOTHER_ENV_VAR2
#         value: some_value2
variable "settings" {
  description = "Settings for the module"
  type        = any
  default     = {}
}

## VPC Settings yaml Specification
# vpc:
#   enabled: true | false # Defaults to false
#   subnet_ids: # (optional) List of subnet IDs to attach to the Lambda function
#     - subnet-12345678
#   create_security_group: true | false # (optional) Defaults to false, required if security_groups are not provided
#   security_groups: # (optional) List of security groups to attach to the Lambda function, required if create_security_group is false
#     - sg-12345678
variable "vpc" {
  description = "VPC settings for the module"
  type        = any
  default     = {}
}