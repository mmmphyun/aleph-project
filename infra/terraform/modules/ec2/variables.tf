variable "environment" {
  type    = string
  default = "dev"
  validation {
    condition     = can(regex("^[a-z][a-z0-9-]{0,19}$", var.environment))
    error_message = "환경명은 소문자로 시작하는 1~20자 영문/숫자/하이픈입니다."
  }
}

variable "subnet_id" {
  type = string
  validation {
    condition     = can(regex("^subnet-([0-9a-f]{8}|[0-9a-f]{17})$", var.subnet_id))
    error_message = "유효한 타깃 서브넷 ID가 필요합니다."
  }
}

variable "security_group_ids" {
  type = list(string)
  validation {
    condition     = length(var.security_group_ids) > 0 && alltrue([for id in var.security_group_ids : can(regex("^sg-([0-9a-f]{8}|[0-9a-f]{17})$", id))])
    error_message = "네트워크 담당이 제공한 보안 그룹 ID가 하나 이상 필요합니다."
  }
}

variable "ami_id" {
  description = "Ubuntu 22.04/24.04 LTS amd64 AMI (배포 리전에서 검증된 ID)"
  type        = string
  validation {
    condition     = can(regex("^ami-([0-9a-f]{8}|[0-9a-f]{17})$", var.ami_id))
    error_message = "유효한 Ubuntu amd64 AMI ID가 필요합니다."
  }
}

variable "instance_type" {
  description = "amd64 AMI와 호환되는 테스트 인스턴스 타입"
  type        = string
  default     = "t3.micro"
  validation {
    condition     = contains(["t3.micro", "t3.small", "t3.medium"], var.instance_type)
    error_message = "지원 타입: t3.micro, t3.small, t3.medium"
  }
}

variable "lambda_function_arn" {
  description = "동일 리전/계정의 오케스트레이터 Lambda ARN"
  type        = string
  validation {
    condition     = can(regex("^arn:aws:lambda:[a-z0-9-]+:[0-9]{12}:function:[A-Za-z0-9_-]+$", var.lambda_function_arn))
    error_message = "별칭 없는 Lambda 함수 ARN이 필요합니다."
  }
}

variable "associate_public_ip_address" {
  description = "기본 비활성. 사설 서브넷은 APT/S3/CloudWatch 접근 경로 필요"
  type        = bool
  default     = false
}

variable "log_retention_days" {
  type    = number
  default = 7
  validation {
    condition     = contains([1, 3, 5, 7, 14, 30, 60, 90, 120, 150, 180, 365], var.log_retention_days)
    error_message = "지원되는 유한 로그 보존 기간을 지정하세요."
  }
}
