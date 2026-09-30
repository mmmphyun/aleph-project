# CloudShield Terraform 루트 모듈 입력 변수 명세
# 소유자: 클라우드 A (플랫폼 전담)

variable "aws_region" {
  description = "AWS 기본 배포 리전"
  type        = string
  default     = "ap-northeast-2"
}

variable "environment" {
  description = "배포 환경 (dev, staging, prod)"
  type        = string
  default     = "dev"
}

variable "dynamodb_table_name" {
  description = "인증 실패 집계 슬라이딩 윈도우용 DynamoDB 테이블 명칭"
  type        = string
  default     = "CloudShield-AuthFailure-Window"
}

variable "lambda_function_name" {
  description = "오케스트레이터 Lambda 함수명"
  type        = string
  default     = "CloudShield-Threat-Orchestrator"
}

variable "quarantine_sg_arn" {
  description = "L4 격리에 사용할 Security Group ARN (Phase 2에서 네트워크 모듈 출력값 바인딩)"
  type        = string
  default     = "arn:aws:ec2:ap-northeast-2:123456789012:security-group/sg-0123456789abcdef0"
}

variable "waf_ipset_arn" {
  description = "L7 차단에 사용할 WAFv2 IPSet ARN (Phase 2에서 보안 모듈 출력값 바인딩)"
  type        = string
  default     = "arn:aws:wafv2:ap-northeast-2:123456789012:regional/ipset/CloudShield-Block-IPSet/12345678-1234-1234-1234-123456789012"
}

variable "slack_webhook_url" {
  description = "SecOps 상황 전파를 위한 Slack Incoming Webhook URL"
  type        = string
  default     = ""
  sensitive   = true
}

variable "lambda_package_zip_path" {
  description = "사전 빌드된 Lambda ZIP 아티팩트 경로 (pydantic 등 런타임 종속성 포함 ZIP)"
  type        = string
  default     = ""
}

