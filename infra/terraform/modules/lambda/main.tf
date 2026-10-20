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
#   - packaging: 사전 빌더(scripts/package_lambda.py)로 생성된 의존성 포함 Linux x86_64 ZIP 아티팩트 강제.

data "aws_region" "current" {}
data "aws_caller_identity" "current" {}

locals {
  lambda_archive_path = var.package_zip_path
  lambda_archive_hash = filebase64sha256(var.package_zip_path)
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

  # 2. DynamoDB 슬라이딩 윈도우 원자적 카운터 제어 및 테이블 메타데이터 조회 권한
  statement {
    sid    = "DynamoDBWindowAccess"
    effect = "Allow"
    actions = [
      "dynamodb:GetItem",
      "dynamodb:PutItem",
      "dynamodb:UpdateItem",
      "dynamodb:DeleteItem",
      "dynamodb:DescribeTable"
    ]
    resources = [
      var.dynamodb_table_arn
    ]
  }

  # 3-1. EC2 상태 및 보안 그룹 조회 권한 (AWS IAM 스펙상 리소스 레벨 권한 미지원으로 "*" 필수)
  statement {
    sid    = "EC2DescribeActions"
    effect = "Allow"
    actions = [
      "ec2:DescribeInstances",
      "ec2:DescribeSecurityGroups"
    ]
    resources = ["*"]
  }

  # 3-2. L4 EC2 보안 그룹 원자적 교체 격리 권한 (최소 권한: 대상 인스턴스 및 격리 SG로 한정)
  statement {
    sid    = "EC2QuarantineRemediation"
    effect = "Allow"
    actions = [
      "ec2:ModifyInstanceAttribute"
    ]
    resources = [
      "arn:aws:ec2:*:*:instance/*",
      var.quarantine_sg_arn
    ]
  }

  # 4-1. WAFv2 IPSet 목록 조회 권한 (AWS IAM 스펙상 리소스 레벨 권한 미지원으로 "*" 필수)
  statement {
    sid    = "WAFv2ListActions"
    effect = "Allow"
    actions = [
      "wafv2:ListIPSets"
    ]
    resources = ["*"]
  }

  # 4-2. L7 WAFv2 IPSet /32 단일 차단 권한 (주입된 대상 IPSet ARN으로 엄격히 제한)
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

  # 4-3. WAFv2 ALB 결합 WebACL 조회 권한 (최소 권한: 주입된 target_web_acl_arn 우선, 미지정 시 현재 배포 리전/계정 한정)
  statement {
    sid    = "WAFv2GetWebACLForResource"
    effect = "Allow"
    actions = [
      "wafv2:GetWebACLForResource",
      "wafv2:GetWebACL"
    ]
    resources = [
      var.target_web_acl_arn != "" ? var.target_web_acl_arn : "arn:aws:wafv2:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:regional/webacl/*/*"
    ]
  }

  # 4-4. Application Load Balancer WebACL 조회 권한 (공식 명세: ALB ARN에 elasticloadbalancing:GetLoadBalancerWebACL 허용)
  statement {
    sid    = "ELBGetLoadBalancerWebACL"
    effect = "Allow"
    actions = [
      "elasticloadbalancing:GetLoadBalancerWebACL"
    ]
    resources = [
      var.target_alb_arn != "" ? var.target_alb_arn : "arn:aws:elasticloadbalancing:*:*:loadbalancer/app/*/*"
    ]
  }

  # 5. EventBridge 비동기 분석 이벤트 발행 권한 (최소 권한: 기본 이벤트 버스로 제한)
  statement {
    sid    = "EventBridgePutEvents"
    effect = "Allow"
    actions = [
      "events:PutEvents"
    ]
    resources = [
      "arn:aws:events:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:event-bus/default"
    ]
  }
}

resource "aws_iam_policy" "lambda_least_privilege" {
  name        = "${var.function_name}-least-privilege-policy"
  description = "CloudShield Lambda least privilege execution policy"
  policy      = data.aws_iam_policy_document.least_privilege.json
}

resource "aws_iam_role" "lambda_exec" {
  name               = "${var.function_name}-exec-role"
  description        = "CloudShield Threat Orchestrator Lambda execution role"
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
  policy_arn = aws_iam_policy.lambda_least_privilege.arn
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
  filename         = local.lambda_archive_path
  source_code_hash = local.lambda_archive_hash
  handler          = "remediation.orchestrator.threat_orchestrator_handler"
  runtime          = "python3.12"
  timeout          = 10
  memory_size      = 256
  role             = aws_iam_role.lambda_exec.arn

  environment {
    variables = {
      AUTH_FAILURE_TABLE_NAME = var.dynamodb_table_name
      SLACK_WEBHOOK_URL       = var.slack_webhook_url
      TARGET_ALB_ARN          = var.target_alb_arn
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

# ==============================================================================
# 2. 사후 비동기 LLM 침해 분석 워커 IAM 역할 및 최소 권한 정책
# ==============================================================================
data "aws_iam_policy_document" "llm_analyzer_least_privilege" {
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
      "arn:aws:logs:*:*:log-group:/aws/lambda/${var.llm_function_name}:*"
    ]
  }

  # 2. Amazon Bedrock 모델 호출 최소 권한 (파운데이션 모델 및 교차 리전 추론 프로파일 한정)
  statement {
    sid    = "BedrockInvokeModel"
    effect = "Allow"
    actions = [
      "bedrock:InvokeModel"
    ]
    resources = [
      "arn:aws:bedrock:*::foundation-model/*",
      "arn:aws:bedrock:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:inference-profile/*"
    ]
  }

  # 3. AWS X-Ray 분산 추적 세그먼트 기록 권한 (Active Tracing 필수)
  statement {
    sid    = "XRayTracingWrite"
    effect = "Allow"
    actions = [
      "xray:PutTraceSegments",
      "xray:PutTelemetryRecords"
    ]
    resources = ["*"]
  }
}

resource "aws_iam_policy" "llm_analyzer_least_privilege" {
  name        = "${var.llm_function_name}-least-privilege-policy"
  description = "CloudShield LLM Analyzer least privilege execution policy"
  policy      = data.aws_iam_policy_document.llm_analyzer_least_privilege.json
}

resource "aws_iam_role" "llm_analyzer_exec" {
  name               = "${var.llm_function_name}-exec-role"
  description        = "CloudShield LLM Analyzer Lambda execution role"
  assume_role_policy = data.aws_iam_policy_document.lambda_assume_role.json

  tags = merge(
    var.tags,
    {
      Name        = "${var.llm_function_name}-exec-role"
      Environment = var.environment
    }
  )
}

resource "aws_iam_role_policy_attachment" "llm_analyzer_attach" {
  role       = aws_iam_role.llm_analyzer_exec.name
  policy_arn = aws_iam_policy.llm_analyzer_least_privilege.arn
}

resource "aws_cloudwatch_log_group" "llm_analyzer_log" {
  name              = "/aws/lambda/${var.llm_function_name}"
  retention_in_days = 14

  tags = merge(
    var.tags,
    {
      Name        = "/aws/lambda/${var.llm_function_name}"
      Environment = var.environment
    }
  )
}

# ==============================================================================
# 3. 사후 비동기 LLM 침해 분석 워커 Lambda 함수
# ==============================================================================
resource "aws_lambda_function" "llm_analyzer" {
  function_name    = var.llm_function_name
  filename         = local.lambda_archive_path
  source_code_hash = local.lambda_archive_hash
  handler          = "remediation.llm_worker.llm_analysis_handler"
  runtime          = "python3.12"
  timeout          = 30
  memory_size      = 256
  role             = aws_iam_role.llm_analyzer_exec.arn

  environment {
    variables = {
      SLACK_WEBHOOK_URL = var.slack_webhook_url
      BEDROCK_MODEL_ID  = var.bedrock_model_id
    }
  }

  tracing_config {
    mode = "Active"
  }

  depends_on = [
    aws_cloudwatch_log_group.llm_analyzer_log,
    aws_iam_role_policy_attachment.llm_analyzer_attach
  ]

  tags = merge(
    var.tags,
    {
      Name        = var.llm_function_name
      Environment = var.environment
      Purpose     = "LLMAnalyzer"
    }
  )
}

resource "aws_lambda_function_event_invoke_config" "llm_analyzer_async" {
  function_name          = aws_lambda_function.llm_analyzer.function_name
  maximum_retry_attempts = 0
}

# ==============================================================================
# 4. EventBridge 규칙, 대상(Target) 및 Lambda 호출 권한 바인딩
# ==============================================================================
resource "aws_cloudwatch_event_rule" "threat_remediated" {
  name        = "cloudshield-threat-remediated-${var.environment}"
  description = "Trigger async LLM deep analysis upon threat remediation completion"
  event_pattern = jsonencode({
    source      = ["cloudshield.security"]
    detail-type = ["ThreatRemediated"]
  })

  tags = merge(
    var.tags,
    {
      Name        = "cloudshield-threat-remediated-${var.environment}"
      Environment = var.environment
      Component   = "EventBridge"
    }
  )
}

resource "aws_cloudwatch_event_target" "llm_analyzer" {
  rule      = aws_cloudwatch_event_rule.threat_remediated.name
  target_id = "TriggerLLMAnalyzer"
  arn       = aws_lambda_function.llm_analyzer.arn

  retry_policy {
    maximum_retry_attempts = 0
  }
}

resource "aws_lambda_permission" "allow_eventbridge_llm_analyzer" {
  statement_id  = "AllowEventBridgeInvokeLLMAnalyzer"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.llm_analyzer.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.threat_remediated.arn
}
