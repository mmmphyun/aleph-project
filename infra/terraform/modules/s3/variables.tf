# CloudShield S3 모듈 변수 정의
# 소유자: 클라우드 A (플랫폼 전담)

variable "environment" {
  description = "배포 환경 식별자 (예: dev, prod)"
  type        = string
}

variable "bucket_name_prefix" {
  description = "침해 보고서 S3 버킷 이름 접두사"
  type        = string
  default     = "cloudshield-secops-reports"
}

variable "allowed_report_cidrs" {
  description = "보고서 열람이 허용된 사내 공인 IP CIDR 목록"
  type        = list(string)
  default     = ["1.245.252.171/32"]
}

variable "tags" {
  description = "리소스에 부착할 기본 태그 맵"
  type        = map(string)
  default     = {}
}
