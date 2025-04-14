##
# (c) 2024 - Cloud Ops Works LLC - https://cloudops.works/
#            On GitHub: https://github.com/cloudopsworks
#            Distributed Under Apache v2.0 License
#

## YAML Specification Settings
# settings:
#   name: <name>
#   name_prefix: <name_prefix>
#   type: mongodb | postgres(ql) | mysql | mariadb | mssql | mongodbatlas
#   multi_user: true | false # Defaults to false
variable "settings" {
  description = "Settings for the module"
  type        = any
  default     = {}
}

variable "vpc" {
  description = "VPC settings for the module"
  type        = any
  default     = {}
}