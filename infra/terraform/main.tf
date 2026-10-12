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

  function_name       = var.lambda_function_name
  environment         = var.environment
  dynamodb_table_arn  = module.dynamodb.table_arn
  dynamodb_table_name = module.dynamodb.table_name
  quarantine_sg_arn   = module.quarantine_sg.quarantine_sg_arn
  waf_ipset_arn       = module.waf.ipset_arn
  slack_webhook_url   = var.slack_webhook_url
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
