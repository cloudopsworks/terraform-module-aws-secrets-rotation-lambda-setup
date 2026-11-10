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
#   # The external target secret must contain api_key and api_key_id. Provider selection comes only from
#   # settings.type; no provider field is needed in the secret. OpenAI targets also require
#   # project_id, service_account_id, name, and scopes matching the current OpenAI key. OpenRouter targets
#   # can seed non-expiration key options (name, limit, limit_reset, include_byok_in_limit,
#   # creator_user_id, workspace_id); missing options are read by hash from the management API.
#   # Explicit secret values win, including null/false/0. Workspace null is omitted from the create request.
#   # Lookup failure or incomplete metadata fails rotation; old expiration is not copied.
#   api_key_name: "rotated-api-key"  # (Optional) Legacy setting ignored for API-key rotation; OpenAI reads name from the target secret and OpenRouter can retrieve it by hash.
#   management_api_key:             # (Required for openai/openrouter) Pre-existing management credential secret; this module never creates or updates it. SecretString must contain JSON {"api_key":"<upstream management key>"}.
#     secret_arn: "arn:aws:secretsmanager:<region>:<account>:secret:<name>" # (Required) Plan-time-known name or ARN of the existing AWS Secrets Manager secret. Its ARN and KMS key are resolved automatically.
#   openai:                        # (Required when type is openai) Existing OpenAI project and service-account identifiers.
#     project_id: "proj_..."       # (Required) OpenAI project that owns the workload API key.
#     service_account_id: "svc_acct_..." # (Required) Existing service account for replacement-key creation.
#     scopes: ["<scope>"]        # (Optional) Legacy setting ignored; required scopes come from the target secret.
#     expires_in_seconds: 2592000 # (Optional) New key lifetime in seconds, 1 through 31536000, or null for no expiry. Default: OpenAI API default.
#   openrouter:                    # (Optional when type is openrouter) New expiration and legacy key settings.
#     limit: 10.0                  # (Optional) Legacy setting ignored; effective limit comes from the target secret or OpenRouter key metadata.
#     limit_reset: daily           # (Optional) Legacy setting ignored; effective reset interval comes from the target secret or OpenRouter key metadata.
#     include_byok_in_limit: false # (Optional) Legacy setting ignored; effective value comes from the target secret or OpenRouter key metadata.
#     expires_at: "2027-01-01T00:00:00Z" # (Optional) UTC ISO-8601 expiration with seconds. Default: provider default.
#     workspace_id: "<uuid>"       # (Optional) Legacy setting ignored; workspace_id comes from the target secret or OpenRouter key metadata.
#     creator_user_id: "user_..."  # (Optional) Legacy setting ignored; creator_user_id comes from the target secret or OpenRouter key metadata.
#   # OpenRouter external keys are not supported because they may contain a credential; do not put them in Terraform inputs.
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
