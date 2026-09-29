# CloudShield DynamoDB Terraform 모듈 변수 명세
# 소유자: 클라우드 A (플랫폼 전담)

variable "table_name" {
  description = "인증 실패 누적 슬라이딩 윈도우용 DynamoDB 테이블 명칭"
  type        = string
  default     = "CloudShield-AuthFailure-Window"
}

variable "environment" {
  description = "배포 환경 구분 (dev, stage, prod)"
  type        = string
  default     = "dev"
}

variable "tags" {
  description = "추가 리소스 태그 매핑"
  type        = map(string)
  default     = {}
}
