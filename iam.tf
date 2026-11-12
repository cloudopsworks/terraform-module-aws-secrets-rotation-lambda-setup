##
# (c) 2021-2026
#     Cloud Ops Works LLC - https://cloudops.works/
#     Find us on:
#       GitHub: https://github.com/cloudopsworks
#       WebSite: https://cloudops.works
#     Distributed Under Apache v2.0 License
#
data "aws_caller_identity" "current" {}

data "aws_iam_policy_document" "assume_role" {
  statement {
    effect = "Allow"
    principals {
      type = "Service"
      identifiers = [
        "lambda.amazonaws.com"
      ]
    }
    actions = [
      "sts:AssumeRole"
    ]
  }
}

resource "aws_iam_role" "default_lambda_function" {
  name               = "${local.function_name_short}-role"
  assume_role_policy = data.aws_iam_policy_document.assume_role.json
  tags               = local.all_tags
  lifecycle {
    create_before_destroy = true
  }
}

# See also the following AWS managed policy: AWSLambdaBasicExecutionRole
data "aws_iam_policy_document" "lambda_function_logs" {
  statement {
    sid    = "CreateLogGroup"
    effect = "Allow"
    actions = [
      "logs:CreateLogGroup",
    ]
    resources = [
      "${aws_cloudwatch_log_group.logs.arn}"
    ]
  }
  statement {
    sid    = "WriteLogs"
    effect = "Allow"
    actions = [
      "logs:CreateLogStream",
      "logs:PutLogEvents",
    ]
    resources = [
      "${aws_cloudwatch_log_group.logs.arn}:*"
    ]
  }
}


resource "aws_iam_role_policy" "lambda_function_logs" {
  name   = "${local.function_name_short}-logs-policy"
  role   = aws_iam_role.default_lambda_function.name
  policy = data.aws_iam_policy_document.lambda_function_logs.json
}


data "aws_iam_policy_document" "vpc_ec2" {
  count   = try(var.vpc.enabled, false) ? 1 : 0
  version = "2012-10-17"
  statement {
    effect = "Allow"
    actions = [
      "ec2:CreateNetworkInterface",
      "ec2:DescribeNetworkInterfaces",
      "ec2:DescribeSubnets",
      "ec2:DeleteNetworkInterface",
      "ec2:AssignPrivateIpAddresses",
      "ec2:UnassignPrivateIpAddresses",
    ]
    resources = ["*"]
  }
}

resource "aws_iam_role_policy" "vpc_ec2" {
  count  = try(var.vpc.enabled, false) ? 1 : 0
  name   = "${local.function_name_short}-vpc-policy"
  role   = aws_iam_role.default_lambda_function.name
  policy = data.aws_iam_policy_document.vpc_ec2[0].json
}

data "aws_iam_policy_document" "allowed_secrets" {
  count = length(try(var.settings.allowed_secrets, [])) > 0 ? 1 : 0
  statement {
    sid    = "ReadListUpdateSecrets"
    effect = "Allow"
    actions = [
      "secretsmanager:DescribeSecret",
      "secretsmanager:GetSecretValue",
      "secretsmanager:PutSecretValue",
      "secretsmanager:UpdateSecretVersionStage"
    ]
    resources = var.settings.allowed_secrets
  }
  dynamic "statement" {
    for_each = local.api_key_rotation ? [] : [1]
    content {
      sid    = "RandomPassword"
      effect = "Allow"
      actions = [
        "secretsmanager:GetRandomPassword",
        "secretsmanager:UpdateSecretVersionStage",
      ]
      resources = ["*"]
    }
  }
}

resource "aws_iam_role_policy" "allowed_secrets" {
  count  = length(try(var.settings.allowed_secrets, [])) > 0 ? 1 : 0
  name   = "${local.function_name_short}-allow-secret-policy"
  role   = aws_iam_role.default_lambda_function.name
  policy = data.aws_iam_policy_document.allowed_secrets[0].json
}

data "aws_secretsmanager_secret" "management_api_key" {
  count = local.api_key_rotation ? 1 : 0

  arn  = startswith(local.management_secret_id, "arn:") ? local.management_secret_id : null
  name = startswith(local.management_secret_id, "arn:") ? null : local.management_secret_id
}

data "aws_kms_key" "management_api_key" {
  count = local.api_key_rotation && try(trimspace(data.aws_secretsmanager_secret.management_api_key[0].kms_key_id), "") != "" ? 1 : 0

  key_id = data.aws_secretsmanager_secret.management_api_key[0].kms_key_id
}

data "aws_iam_policy_document" "management_api_key" {
  count = local.api_key_rotation ? 1 : 0

  statement {
    sid    = "ReadManagementApiKey"
    effect = "Allow"
    actions = [
      "secretsmanager:GetSecretValue",
      "secretsmanager:DescribeSecret",
    ]
    resources = [local.management_secret_arn]
  }
}

resource "aws_iam_role_policy" "management_api_key" {
  count  = local.api_key_rotation ? 1 : 0
  name   = "${local.function_name_short}-management-key-policy"
  role   = aws_iam_role.default_lambda_function.name
  policy = data.aws_iam_policy_document.management_api_key[0].json
}

data "aws_iam_policy_document" "management_api_key_kms" {
  count = length(data.aws_kms_key.management_api_key)

  statement {
    sid       = "DecryptManagementApiKey"
    effect    = "Allow"
    actions   = ["kms:Decrypt"]
    resources = [data.aws_kms_key.management_api_key[0].arn]
    condition {
      test     = "StringEquals"
      variable = "kms:EncryptionContext:SecretARN"
      values   = [local.management_secret_arn]
    }
  }
}

resource "aws_iam_role_policy" "management_api_key_kms" {
  count  = length(data.aws_kms_key.management_api_key)
  name   = "${local.function_name_short}-management-key-kms-policy"
  role   = aws_iam_role.default_lambda_function.name
  policy = data.aws_iam_policy_document.management_api_key_kms[0].json
}

data "aws_iam_policy_document" "allowed_kms" {
  count = length(try(var.settings.allowed_kms, [])) > 0 ? 1 : 0
  statement {
    sid    = "KMS"
    effect = "Allow"
    actions = [
      "kms:Decrypt",
      "kms:DescribeKey",
      "kms:GenerateDataKey"
    ]
    resources = var.settings.allowed_kms
    condition {
      test     = "StringLike" # This allows for wildcards in the secret ARN, which is useful for multi-account deployments
      variable = "kms:EncryptionContext:SecretARN"
      values   = var.settings.allowed_secrets
    }
  }
}

resource "aws_iam_role_policy" "allowed_kms" {
  count  = length(try(var.settings.allowed_kms, [])) > 0 ? 1 : 0
  name   = "${local.function_name_short}-allow-kms-policy"
  role   = aws_iam_role.default_lambda_function.name
  policy = data.aws_iam_policy_document.allowed_kms[0].json
}

data "aws_iam_policy_document" "custom" {
  count = length(try(var.settings.iam.statements, [])) > 0 ? 1 : 0
  dynamic "statement" {
    for_each = var.settings.iam.statements
    content {
      effect    = statement.value.effect
      actions   = statement.value.action
      resources = statement.value.resource
    }
  }
}

resource "aws_iam_role_policy" "custom" {
  count  = length(try(var.settings.iam.statements, [])) > 0 ? 1 : 0
  name   = "${local.function_name_short}-custom-policy"
  role   = aws_iam_role.default_lambda_function.name
  policy = data.aws_iam_policy_document.custom[0].json
}
