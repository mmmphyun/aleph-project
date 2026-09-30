# CloudShield Lambda Terraform 모듈 변수 명세
# 소유자: 클라우드 A (플랫폼 전담)

variable "function_name" {
  description = "위협 탐지 및 복합 차단 오케스트레이터 Lambda 함수명"
  type        = string
  default     = "CloudShield-Threat-Orchestrator"
}

variable "environment" {
  description = "배포 환경 구분 (dev, stage, prod)"
  type        = string
  default     = "dev"
}

variable "dynamodb_table_arn" {
  description = "인증 실패 누적 상태 관리를 위한 DynamoDB 테이블 ARN"
  type        = string
}

variable "dynamodb_table_name" {
  description = "인증 실패 누적 상태 관리를 위한 DynamoDB 테이블 명칭"
  type        = string
}

variable "quarantine_sg_arn" {
  description = "L4 제로 트러스트 격리에 사용할 EC2 Security Group ARN"
  type        = string
}

variable "waf_ipset_arn" {
  description = "L7 공격자 IP 단일 차단에 사용할 AWS WAFv2 IPSet ARN"
  type        = string
}

variable "slack_webhook_url" {
  description = "SecOps 상황 전파를 위한 Slack Incoming Webhook URL"
  type        = string
  default     = ""
  sensitive   = true
}

variable "package_zip_path" {
  description = "사전 빌드된 Lambda ZIP 아티팩트 경로 (pydantic 등 런타임 종속성 포함 ZIP)"
  type        = string

  validation {
    condition     = var.package_zip_path != "" && fileexists(var.package_zip_path)
    error_message = "Lambda 배포 아티팩트(ZIP)를 찾을 수 없습니다. 배포 전 'uv run python scripts/package_lambda.py'를 실행하여 빌드 아티팩트를 먼저 생성해야 합니다."
  }
}

variable "tags" {
  description = "추가 리소스 태그 매핑"
  type        = map(string)
  default     = {}
}
