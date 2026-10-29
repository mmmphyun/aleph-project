# CloudShield Terraform 루트 오케스트레이션 모듈
# 소유자: 클라우드 A (플랫폼 전담)
#
# Why:
#   마이크로 모듈(VPC, EC2, WAF, DynamoDB, Lambda)의 생명주기를 단일 루트에서 결합하여
#   인프라 전체의 프로비저닝 순서와 리소스 간 의존성 파이프라인을 선언함.
#
# Phase 분리 원칙 (점진적 결합 파이프라인):
#   - Phase 1 (현재): 클라우드 A 고유 모듈(DynamoDB, Lambda) 및 루트 인터페이스 선언 완료.
#   - Phase 2 (후속): 타 직무 모듈(VPC, EC2, WAF) 머지 후 하단 주석 블록을 활성화하여
#     출력값(SG ID, WAF IPSet ARN)을 Lambda 및 EC2 모듈로 상호 와이어링함.

# ==============================================================================
# 1. DynamoDB 상태 윈도우 모듈 (클라우드 A 전담)
# ==============================================================================
module "dynamodb" {
  source = "./modules/dynamodb"

  table_name  = var.dynamodb_table_name
  environment = var.environment
}

# ==============================================================================
# 2. VPC 및 라우팅 네트워크 모듈 (네트워크 전담)
# ==============================================================================
module "vpc" {
  source = "./modules/vpc"

  environment = var.environment
  topology    = var.vpc_topology
}

# ==============================================================================
# 3. 기본 및 격리 보안 그룹 모듈 (네트워크 전담)
# ==============================================================================
module "quarantine_sg" {
  source = "./modules/quarantine_sg"

  vpc_id      = module.vpc.vpc_id
  environment = var.environment
  traffic     = var.quarantine_traffic
}

# ==============================================================================
# 4. AWS WAFv2 WebACL 및 차단 IPSet 모듈 (보안 전담)
# ==============================================================================
module "waf" {
  source = "./modules/waf"

  environment = var.environment
}

# ==============================================================================
# 5. Lambda 위협 분석 및 원자적 차단 오케스트레이터 모듈 (클라우드 A 전담)
# ==============================================================================
module "lambda" {
  source = "./modules/lambda"

  function_name          = var.lambda_function_name
  llm_function_name      = var.lambda_llm_function_name
  bedrock_model_id       = var.bedrock_model_id
  environment            = var.environment
  dynamodb_table_arn     = module.dynamodb.table_arn
  dynamodb_table_name    = module.dynamodb.table_name
  quarantine_sg_arn      = module.quarantine_sg.quarantine_sg_arn
  waf_ipset_arn          = module.waf.ipset_arn
  slack_webhook_url      = var.slack_webhook_url
  target_alb_arn         = module.alb.alb_arn
  target_web_acl_arn     = module.waf.web_acl_arn
  reports_s3_bucket_arn  = module.s3_reports.bucket_arn
  reports_s3_bucket_name = module.s3_reports.bucket_name
  package_zip_path = var.lambda_package_zip_path != "" ? (
    startswith(var.lambda_package_zip_path, "/") || can(regex("^[A-Za-z]:", var.lambda_package_zip_path)) ?
    var.lambda_package_zip_path :
    "${path.module}/${var.lambda_package_zip_path}"
  ) : "${path.module}/modules/lambda/build/orchestrator.zip"
}

# ==============================================================================
# 6. 타깃 EC2 및 CW Agent 모듈 (클라우드 B 전담)
# ==============================================================================
module "ec2_target" {
  source = "./modules/ec2"

  environment                 = var.environment
  subnet_id                   = module.vpc.public_subnet_ids["public-2a"]
  security_group_ids          = [module.quarantine_sg.baseline_sg_id]
  ami_id                      = var.ec2_ami_id
  lambda_function_arn         = module.lambda.function_arn
  instance_type               = var.ec2_instance_type
  associate_public_ip_address = var.ec2_associate_public_ip
  log_retention_days          = var.ec2_log_retention_days
}

# ==============================================================================
# 7. Application Load Balancer 및 Target Group 모듈 (클라우드 A 전담)
# ==============================================================================
module "alb" {
  source = "./modules/alb"

  environment        = var.environment
  vpc_id             = module.vpc.vpc_id
  subnet_ids         = values(module.vpc.public_subnet_ids)
  target_instance_id = module.ec2_target.instance_id
}

# ==============================================================================
# 8. AWS WAFv2 WebACL - ALB 영구 바인딩 (클라우드 A 전담)
# ==============================================================================
resource "aws_wafv2_web_acl_association" "alb" {
  resource_arn = module.alb.alb_arn
  web_acl_arn  = module.waf.web_acl_arn
}

# ==============================================================================
# 9. AWS WAFv2 원본 로그 저장 파이프라인 (클라우드 A 전담)
# ==============================================================================
# Why:
#   보안 담당(P3-8)의 WAF 차단 원본 로그 분석 및 탐지 정확도/오탐 평가를 위해
#   AWS WAFv2 WebACL의 실시간 트래픽 로그를 CloudWatch Logs로 원자적 스트리밍함.
#
# Constraints:
#   - AWS WAFv2 로깅 대상 CloudWatch Log Group 이름은 반드시 'aws-waf-logs-' 접두사로 시작해야 함.
#   - 리텐션은 비용 절감을 위해 7일로 제한함.
resource "aws_cloudwatch_log_group" "waf_logs" {
  name              = "aws-waf-logs-cloudshield-${var.environment}"
  retention_in_days = 7

  tags = {
    Project     = "CloudShield"
    Environment = var.environment
    ManagedBy   = "Terraform"
    Component   = "WAF-Logging"
  }
}

resource "aws_wafv2_web_acl_logging_configuration" "waf_logs" {
  log_destination_configs = [aws_cloudwatch_log_group.waf_logs.arn]
  resource_arn            = module.waf.web_acl_arn
}

# ==============================================================================
# 10. Grafana 관제용 CloudWatch 최소 권한 IAM 정책 (클라우드 A 전담)
# ==============================================================================
# Why:
#   Grafana 컨테이너가 CloudWatch Logs Insights 쿼리 및 메트릭 조회를 수행할 수 있도록
#   최소 권한(CloudWatch Logs/Metrics ReadOnly)만을 정의하여 인프라 변경 권한 노출을 원천 차단함.
#
# Constraints:
#   - 로그 및 메트릭 조회 액션만 허용하고, 쓰기/삭제 및 타 AWS 서비스 접근은 전면 차단.
data "aws_iam_policy_document" "grafana_cloudwatch_readonly" {
  statement {
    sid    = "CloudWatchMetricsReadOnly"
    effect = "Allow"
    actions = [
      "cloudwatch:DescribeAlarmsForMetric",
      "cloudwatch:DescribeAlarmHistory",
      "cloudwatch:DescribeAlarms",
      "cloudwatch:ListMetrics",
      "cloudwatch:GetMetricData",
      "cloudwatch:GetMetricStatistics"
    ]
    resources = ["*"]
  }

  statement {
    sid    = "CloudWatchLogsReadOnly"
    effect = "Allow"
    actions = [
      "logs:DescribeLogGroups",
      "logs:DescribeLogStreams",
      "logs:GetLogEvents",
      "logs:GetLogGroupFields",
      "logs:GetLogRecord",
      "logs:GetQueryResults",
      "logs:FilterLogEvents",
      "logs:StartQuery",
      "logs:StopQuery"
    ]
    resources = ["*"]
  }

  statement {
    sid    = "EC2RegionsReadOnly"
    effect = "Allow"
    actions = [
      "ec2:DescribeRegions"
    ]
    resources = ["*"]
  }
}

resource "aws_iam_policy" "grafana_cloudwatch_readonly" {
  name        = "CloudShield-Grafana-CloudWatch-ReadOnly-${var.environment}"
  description = "Read-only CloudWatch access policy for CloudShield Grafana dashboards"
  policy      = data.aws_iam_policy_document.grafana_cloudwatch_readonly.json

  tags = {
    Project     = "CloudShield"
    Environment = var.environment
    ManagedBy   = "Terraform"
    Component   = "Observability"
  }
}



# ==============================================================================
# 8. 침해 보고서 S3 저장소 및 사내 IP 격리 모듈 (클라우드 A 전담)
# ==============================================================================
module "s3_reports" {
  source = "./modules/s3"

  environment          = var.environment
  allowed_report_cidrs = var.allowed_report_cidrs
}
