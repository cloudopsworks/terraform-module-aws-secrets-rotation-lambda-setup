mock_provider "aws" {
  mock_data "aws_region" {
    defaults = { region = "us-east-1" }
  }

  mock_data "aws_caller_identity" {
    defaults = { account_id = "111122223333" }
  }

  mock_data "aws_secretsmanager_secret" {
    defaults = {
      arn        = "arn:aws:secretsmanager:us-east-1:111122223333:secret:app/management-AbCdEf"
      kms_key_id = null
    }
  }

  mock_data "aws_kms_key" {
    defaults = { arn = "arn:aws:kms:us-east-1:111122223333:key/12345678-1234-1234-1234-123456789012" }
  }

  mock_data "aws_iam_policy_document" {
    defaults = { json = "{\"Version\":\"2012-10-17\",\"Statement\":[]}" }
  }

  mock_resource "aws_iam_role" {
    defaults = { arn = "arn:aws:iam::111122223333:role/rotation-test" }
  }
}

variables {
  org = {
    organization_name = "example"
    organization_unit = "platform"
    environment_type  = "staging"
    environment_name  = "test"
  }
}

run "management_secret_by_name_with_default_kms" {
  command = plan

  variables {
    settings = {
      type               = "openrouter"
      management_api_key = { secret_arn = "app/management" }
      allowed_secrets    = ["arn:aws:secretsmanager:us-east-1:111122223333:secret:app/workload-AbCdEf"]
    }
  }

  assert {
    condition     = data.aws_secretsmanager_secret.management_api_key[0].name == "app/management"
    error_message = "Management secret name lookup was not selected."
  }
  assert {
    condition     = local.variables.MANAGEMENT_SECRET_ARN == data.aws_secretsmanager_secret.management_api_key[0].arn
    error_message = "Lambda must receive the resolved management secret ARN."
  }
  assert {
    condition     = length(data.aws_kms_key.management_api_key) == 0
    error_message = "Default Secrets Manager encryption must not create a KMS lookup or grant."
  }
}

run "management_secret_by_arn_with_customer_kms" {
  command = plan

  override_data {
    target = data.aws_secretsmanager_secret.management_api_key
    values = {
      kms_key_id = "alias/management"
    }
  }

  variables {
    settings = {
      type               = "openai"
      management_api_key = { secret_arn = "arn:aws:secretsmanager:us-east-1:111122223333:secret:app/management-AbCdEf" }
      openai             = { project_id = "proj_123", service_account_id = "svc_123" }
      allowed_secrets    = ["arn:aws:secretsmanager:us-east-1:111122223333:secret:app/workload-AbCdEf"]
    }
  }

  assert {
    condition     = data.aws_secretsmanager_secret.management_api_key[0].arn == local.management_secret_id
    error_message = "Management secret ARN lookup was not selected."
  }
  assert {
    condition     = length(data.aws_kms_key.management_api_key) == 1
    error_message = "Customer-managed encryption must resolve the KMS key."
  }
  assert {
    condition     = data.aws_kms_key.management_api_key[0].key_id == "alias/management"
    error_message = "KMS lookup must use the identifier returned by the secret data source."
  }
  assert {
    condition     = length(aws_iam_role_policy.management_api_key_kms) == 1
    error_message = "Customer-managed encryption must grant decrypt to the Lambda."
  }
}

run "reject_manual_management_kms_override" {
  command = plan

  variables {
    settings = {
      type = "openrouter"
      management_api_key = {
        secret_arn  = "app/management"
        kms_key_arn = "arn:aws:kms:us-east-1:111122223333:key/other"
      }
      allowed_secrets = ["arn:aws:secretsmanager:us-east-1:111122223333:secret:app/workload-AbCdEf"]
    }
  }

  expect_failures = [var.settings]
}
