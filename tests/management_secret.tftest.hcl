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
      openai             = { organization_id = "org_123" }
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
  assert {
    condition     = local.variables.OPENAI_ORGANIZATION_ID == "org_123"
    error_message = "OpenAI Lambda must receive its intended organization."
  }
  assert {
    condition     = !contains(keys(local.variables), "ENROLLED_SECRET_ARNS_JSON")
    error_message = "OpenAI enrollment belongs to IAM, not a second Lambda allowlist."
  }
}

run "reject_openai_without_organization" {
  command = plan

  variables {
    settings = {
      type               = "openai"
      management_api_key = { secret_arn = "app/management" }
      allowed_secrets    = ["arn:aws:secretsmanager:us-east-1:111122223333:secret:app/workload-AbCdEf"]
    }
  }

  expect_failures = [aws_lambda_function.this]
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

run "python_runtime_defaults_to_latest" {
  command = plan

  variables {
    settings = {
      type               = "openrouter"
      management_api_key = { secret_arn = "app/management" }
      allowed_secrets    = ["arn:aws:secretsmanager:us-east-1:111122223333:secret:app/workload-AbCdEf"]
    }
  }

  assert {
    condition     = aws_lambda_function.this.runtime == "python3.15"
    error_message = "Python-based rotation must default to the python3.15 runtime."
  }
  assert {
    condition     = aws_lambda_function.this.handler == "lambda_function.lambda_handler"
    error_message = "Python-based rotation must use the Python handler."
  }
}

run "python_runtime_override" {
  command = plan

  variables {
    settings = {
      type               = "openrouter"
      python_version     = "3.13"
      management_api_key = { secret_arn = "app/management" }
      allowed_secrets    = ["arn:aws:secretsmanager:us-east-1:111122223333:secret:app/workload-AbCdEf"]
    }
  }

  assert {
    condition     = aws_lambda_function.this.runtime == "python3.13"
    error_message = "settings.python_version must select the Lambda Python runtime."
  }
}

run "python_runtime_change_changes_package_hash" {
  command = plan

  variables {
    settings = {
      type               = "openrouter"
      python_version     = "3.14"
      management_api_key = { secret_arn = "app/management" }
      allowed_secrets    = ["arn:aws:secretsmanager:us-east-1:111122223333:secret:app/workload-AbCdEf"]
    }
  }

  assert {
    condition = alltrue([
      aws_lambda_function.this.source_code_hash == base64encode(sha256(join("", concat(["python3.14"], [
        for item in fileset(path.module, "${local.source_root}/**/*") : filesha256(item)
      ])))),
      aws_lambda_function.this.source_code_hash != base64encode(sha256(join("", concat(["python3.13"], [
        for item in fileset(path.module, "${local.source_root}/**/*") : filesha256(item)
      ])))),
    ])
    error_message = "A runtime change must change source_code_hash so the package is rebuilt and re-uploaded."
  }
}

run "reject_unsupported_python_runtime" {
  command = plan

  variables {
    settings = {
      type               = "openrouter"
      python_version     = "3.11"
      management_api_key = { secret_arn = "app/management" }
      allowed_secrets    = ["arn:aws:secretsmanager:us-east-1:111122223333:secret:app/workload-AbCdEf"]
    }
  }

  expect_failures = [var.settings]
}

run "golang_runtime_uses_al2023_bootstrap" {
  command = plan

  variables {
    settings = {
      type            = "mongodbatlas"
      python_version  = "3.12"
      allowed_secrets = ["arn:aws:secretsmanager:us-east-1:111122223333:secret:app/atlas-AbCdEf"]
    }
  }

  assert {
    condition     = aws_lambda_function.this.runtime == "provided.al2023"
    error_message = "Go-based rotation must run on the provided.al2023 OS-only runtime."
  }
  assert {
    condition     = aws_lambda_function.this.handler == "bootstrap"
    error_message = "Go-based rotation must use the bootstrap handler."
  }
}

run "python_runtime_null_falls_back_to_default" {
  command = plan

  variables {
    settings = {
      type               = "openrouter"
      python_version     = null
      management_api_key = { secret_arn = "app/management" }
      allowed_secrets    = ["arn:aws:secretsmanager:us-east-1:111122223333:secret:app/workload-AbCdEf"]
    }
  }

  assert {
    condition     = aws_lambda_function.this.runtime == "python3.15"
    error_message = "A null settings.python_version must fall back to the python3.15 default."
  }
}

run "python_runtime_numeric_yaml_value" {
  command = plan

  variables {
    settings = {
      type               = "openrouter"
      python_version     = 3.14
      management_api_key = { secret_arn = "app/management" }
      allowed_secrets    = ["arn:aws:secretsmanager:us-east-1:111122223333:secret:app/workload-AbCdEf"]
    }
  }

  assert {
    condition     = aws_lambda_function.this.runtime == "python3.14"
    error_message = "An unquoted numeric settings.python_version must still select the matching runtime."
  }
}

run "reject_unknown_rotation_type" {
  command = plan

  variables {
    settings = {
      type            = "postgres; touch /tmp/pwned"
      allowed_secrets = ["arn:aws:secretsmanager:us-east-1:111122223333:secret:app/db-AbCdEf"]
    }
  }

  expect_failures = [var.settings]
}

run "reject_shell_metacharacters_in_python_version" {
  command = plan

  variables {
    settings = {
      type            = "postgres"
      python_version  = "3.15 $(touch /tmp/pwned)"
      allowed_secrets = ["arn:aws:secretsmanager:us-east-1:111122223333:secret:app/db-AbCdEf"]
    }
  }

  expect_failures = [var.settings]
}

run "archive_is_private_and_per_instance" {
  command = plan

  variables {
    settings = {
      type            = "postgres"
      allowed_secrets = ["arn:aws:secretsmanager:us-east-1:111122223333:secret:app/db-AbCdEf"]
    }
  }

  assert {
    condition     = !startswith(aws_lambda_function.this.filename, "/tmp/")
    error_message = "The deployment package must not be staged in the shared, world-writable /tmp directory."
  }
  assert {
    condition     = strcontains(aws_lambda_function.this.filename, "/.terraform/lambda-build/") && strcontains(aws_lambda_function.this.filename, substr(sha256(local.function_name), 0, 16))
    error_message = "The deployment package path must be private to the root module and unique per function."
  }
}

run "python_version_ignored_for_golang" {
  command = plan

  variables {
    settings = {
      type            = "mongodbatlas"
      python_version  = "3.11"
      allowed_secrets = ["arn:aws:secretsmanager:us-east-1:111122223333:secret:app/atlas-AbCdEf"]
    }
  }

  assert {
    condition     = aws_lambda_function.this.runtime == "provided.al2023"
    error_message = "settings.python_version must not affect or block the Go runtime."
  }
}

run "reject_list_python_version" {
  command = plan

  variables {
    settings = {
      type            = "postgres"
      python_version  = ["3.15"]
      allowed_secrets = ["arn:aws:secretsmanager:us-east-1:111122223333:secret:app/db-AbCdEf"]
    }
  }

  expect_failures = [var.settings]
}

run "reject_type_without_bundled_source" {
  command = plan

  variables {
    settings = {
      type            = "postgres"
      multi_user      = true
      allowed_secrets = ["arn:aws:secretsmanager:us-east-1:111122223333:secret:app/db-AbCdEf"]
    }
  }

  expect_failures = [aws_lambda_function.this]
}
