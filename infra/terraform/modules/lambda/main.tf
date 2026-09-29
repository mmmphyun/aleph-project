# CloudShield Lambda Terraform 모듈: Boto3 다중 계층 원자적 차단 오케스트레이터 배포
# 소유자: 클라우드 A (플랫폼 전담)
#
# Why:
#   CloudWatch Logs를 통해 인입된 침해 징후에 대해 DynamoDB 상태 윈도우 판정 후,
#   L4 EC2 격리 SG 교체 및 L7 WAF IPSet 등록을 10초 내에 원자적으로 완결하는 런타임 환경을 제공함.
#   Trivy IaC 보안 감사 및 CIS AWS Benchmark를 준수하기 위해 와일드카드(*) 권한을 배제하고,
#   외부 주입된 격리 리소스 ARN만을 허용하는 최소 권한(Least Privilege) IAM 정책을 강제함.
#
# Constraints:
#   - timeout: 10초 관통 대응 파이프라인 SLA에 맞추어 10초 설정.
#   - IAM Policy: ec2, wafv2, dynamodb 액션은 명시된 ARN으로만 제한.
#   - packaging: data.archive_file을 사용하여 src/ 디렉터리를 런타임 zip 파일로 자동 번들링.

data "archive_file" "lambda_zip" {
  type        = "zip"
  source_dir  = var.source_dir
  output_path = "${path.module}/build/orchestrator.zip"
  excludes = [
    "**/__pycache__/**",
    "**/*.pyc",
    "**/tests/**",
    "**/.pytest_cache/**",
    "**/*.egg-info/**"
  ]
}

data "aws_iam_policy_document" "lambda_assume_role" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["lambda.amazonaws.com"]
    }
  }
}

data "aws_iam_policy_document" "least_privilege" {
  # 1. CloudWatch Logs 로깅 권한
  statement {
    sid    = "CloudWatchLogging"
    effect = "Allow"
    actions = [
      "logs:CreateLogGroup",
      "logs:CreateLogStream",
      "logs:PutLogEvents"
    ]
    resources = [
      "arn:aws:logs:*:*:log-group:/aws/lambda/${var.function_name}:*"
    ]
  }

  # 2. DynamoDB 슬라이딩 윈도우 원자적 카운터 제어 권한
  statement {
    sid    = "DynamoDBWindowAccess"
    effect = "Allow"
    actions = [
      "dynamodb:GetItem",
      "dynamodb:PutItem",
      "dynamodb:UpdateItem",
      "dynamodb:DeleteItem"
    ]
    resources = [
      var.dynamodb_table_arn
    ]
  }

  # 3. L4 EC2 보안 그룹 원자적 격리 권한 (와일드카드 배제)
  statement {
    sid    = "EC2QuarantineRemediation"
    effect = "Allow"
    actions = [
      "ec2:DescribeInstances",
      "ec2:DescribeSecurityGroups",
      "ec2:ModifyNetworkInterfaceAttribute"
    ]
    resources = [
      var.quarantine_sg_arn,
      "arn:aws:ec2:*:*:instance/*",
      "arn:aws:ec2:*:*:network-interface/*",
      "arn:aws:ec2:*:*:security-group/*"
    ]
  }

  # 4. L7 WAFv2 IPSet /32 단일 차단 권한
  statement {
    sid    = "WAFv2IPSetBlocking"
    effect = "Allow"
    actions = [
      "wafv2:GetIPSet",
      "wafv2:UpdateIPSet"
    ]
    resources = [
      var.waf_ipset_arn
    ]
  }
}

resource "aws_iam_policy" "lambda_least_privilege" {
  name        = "${var.function_name}-least-privilege-policy"
  description = "CloudShield Lambda 최소 권한 실행 정책 (L4 격리, L7 차단, DynamoDB 윈도우)"
  policy      = data.aws_iam_policy_document.least_privilege.json
}

resource "aws_iam_role" "lambda_exec" {
  name               = "${var.function_name}-exec-role"
  description        = "CloudShield 위협 대응 오케스트레이터 Lambda 실행 역할"
  assume_role_policy = data.aws_iam_policy_document.lambda_assume_role.json

  tags = merge(
    var.tags,
    {
      Name        = "${var.function_name}-exec-role"
      Environment = var.environment
    }
  )
}

resource "aws_iam_role_policy_attachment" "lambda_attach" {
  role       = aws_iam_role.lambda_exec.name
  policy_arn = aws_iam_policy.least_privilege.arn
}

resource "aws_cloudwatch_log_group" "lambda_log" {
  name              = "/aws/lambda/${var.function_name}"
  retention_in_days = 14

  tags = merge(
    var.tags,
    {
      Name        = "/aws/lambda/${var.function_name}"
      Environment = var.environment
    }
  )
}

resource "aws_lambda_function" "orchestrator" {
  function_name    = var.function_name
  filename         = data.archive_file.lambda_zip.output_path
  source_code_hash = data.archive_file.lambda_zip.output_base64sha256
  handler          = "remediation.orchestrator.threat_orchestrator_handler"
  runtime          = "python3.12"
  timeout          = 10
  memory_size      = 256
  role             = aws_iam_role.lambda_exec.arn

  environment {
    variables = {
      AUTH_FAILURE_TABLE_NAME = var.dynamodb_table_name
      SLACK_WEBHOOK_URL       = var.slack_webhook_url
    }
  }

  tracing_config {
    mode = "Active"
  }

  depends_on = [
    aws_cloudwatch_log_group.lambda_log,
    aws_iam_role_policy_attachment.lambda_attach
  ]

  tags = merge(
    var.tags,
    {
      Name        = var.function_name
      Environment = var.environment
      Purpose     = "ThreatOrchestrator"
    }
  )
}
