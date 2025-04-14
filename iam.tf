##
# (c) 2022-2024 - Cloud Ops Works LLC - https://cloudops.works/
#            On GitHub: https://github.com/cloudopsworks
#            Distributed Under Apache v2.0 License
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
  statement {
    sid    = "RandomPassword"
    effect = "Allow"
    actions = [
      "secretsmanager:GetRandomPassword",
      "secretsmanager:UpdateSecretVersionStage",
    ]
    resources = ["*"]
  }
}

resource "aws_iam_role_policy" "allowed_secrets" {
  count  = length(try(var.settings.allowed_secrets, [])) > 0 ? 1 : 0
  name   = "${local.function_name_short}-allow-secret-policy"
  role   = aws_iam_role.default_lambda_function.name
  policy = data.aws_iam_policy_document.allowed_secrets[0].json
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
      test     = "StringEquals"
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
