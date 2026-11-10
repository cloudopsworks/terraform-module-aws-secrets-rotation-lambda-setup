##
# (c) 2021-2026
#     Cloud Ops Works LLC - https://cloudops.works/
#     Find us on:
#       GitHub: https://github.com/cloudopsworks
#       WebSite: https://cloudops.works
#     Distributed Under Apache v2.0 License
#

## YAML Specification Settings
# settings:
#   type: postgres | mysql | mariadb | mssql | mongodb | mongodbatlas | oracle | db2 | openai | openrouter  # (Required) Rotation target.
#   description: "<description>"  # (Optional) Custom Lambda description. Default: Terraform builds one from type and multi_user.
#   multi_user: true | false      # (Optional) Enable alternating-users rotation strategy. Default: false. Must be false for API-key types.
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
#   # For type: openai or openrouter, supply a pre-existing AWS Secrets Manager management secret.
#   # OpenAI requires JSON {"api_key":"<admin management key>","organization_id":"<organization ID>"}.
#   # OpenRouter requires JSON {"api_key":"<management key>"}. This module never manages either secret.
#   # Never put the management key value in Terraform inputs.
#   # Seed the external target secret separately. Both API-key providers require
#   # a versioned TFCONFIG with schema_version: 1 and an AWSCURRENT credential.
#   # A new admin/OpenRouter target has AWSCURRENT and TFBOOTSTRAP on the same version,
#   # holding api_key: null and api_key_id: "__CREATE_NEW__". A new OpenAI project
#   # target may use the same null/key-ID marker in its six-field project payload.
#   # Project bootstrap identity must match TFCONFIG; Lambda creates the first key.
#   # Lambda reads TFCONFIG,
#   # never writes either Terraform-owned label, and pins configuration and
#   # predecessor details in a Lambda-owned ROTATIONINTENT version until finish.
#   # Provider selection comes only from settings.type; no provider field is needed.
#   # This Lambda module never accepts a workload-key value. Legacy real-key project
#   # bootstraps remain supported; keyless bootstrap avoids Terraform-owned credentials.
#   # api_key_name: rotated-api-key # (Optional) Legacy setting ignored for API-key rotation; TFCONFIG supplies the resolved name.
#   # management_api_key: # (Required for openai/openrouter) Pre-existing management key secret.
#   #   secret_arn: app/management # (Required) Existing secret name or ARN. The module resolves its ARN and KMS key automatically.
#   # openai: # (Required when type is openai) Organization binding for the external admin key.
#   #   organization_id: org_123 # (Required) Organization ID; must match management secret JSON.
#   # openrouter: # (Optional when type is openrouter) Legacy inputs ignored by the OpenRouter Lambda; TFCONFIG is authoritative.
#   #   limit: 10.0 # (Optional) Legacy setting ignored; resolved limit comes from TFCONFIG.
#   #   limit_reset: daily # (Optional) Legacy setting ignored; resolved reset interval comes from TFCONFIG.
#   #   include_byok_in_limit: false # (Optional) Legacy setting ignored; resolved BYOK option comes from TFCONFIG.
#   #   expires_at: "2027-01-01T00:00:00Z" # (Optional) Legacy setting ignored; resolved expiration comes from TFCONFIG.
#   #   workspace_id: 00000000-0000-0000-0000-000000000000 # (Optional) Legacy setting ignored; resolved workspace comes from TFCONFIG.
#   #   creator_user_id: user_123 # (Optional) Legacy setting ignored; resolved creator comes from TFCONFIG.
#   # OpenRouter external keys are not supported: never put an external API key in Terraform inputs.
#   allowed_kms:                  # (Optional) KMS key ARNs used to decrypt the allowed target secrets.
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

  validation {
    condition     = !contains(["openai", "openrouter"], try(var.settings.type, "")) || try(length(trimspace(var.settings.management_api_key.secret_arn)) > 0, false)
    error_message = "For OpenAI or OpenRouter, settings.management_api_key.secret_arn must be an existing Secrets Manager secret name or ARN."
  }

  validation {
    condition     = !contains(["openai", "openrouter"], try(var.settings.type, "")) || try(var.settings.management_api_key.kms_key_arn, null) == null
    error_message = "settings.management_api_key.kms_key_arn is not supported; the module resolves the management secret's KMS key automatically."
  }

  validation {
    condition     = try(var.settings.openrouter.external, null) == null
    error_message = "settings.openrouter.external is not supported; do not put external API keys in Terraform inputs."
  }
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
