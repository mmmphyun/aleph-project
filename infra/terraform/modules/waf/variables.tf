variable "environment" {
  description = "배포 환경 태그 및 CloudWatch 메트릭 구분자 (영문·숫자·하이픈, 1~32자)"
  type        = string
  default     = "dev"
  nullable    = false

  validation {
    condition     = can(regex("^[A-Za-z0-9-]{1,32}$", var.environment))
    error_message = "environment는 영문·숫자·하이픈으로 구성된 1~32자 값이어야 합니다."
  }
}

variable "tags" {
  description = "추가 태그. Project/Environment/ManagedBy는 모듈이 관리하는 값으로 유지한다."
  type        = map(string)
  default     = {}
  nullable    = false
}
