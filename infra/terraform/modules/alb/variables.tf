# CloudShield ALB 모듈 변수 명세
# 소유자: 클라우드 A (플랫폼 전담)

variable "environment" {
  description = "배포 환경 (dev, staging, prod)"
  type        = string
  default     = "dev"
}

variable "vpc_id" {
  description = "ALB 및 Target Group이 위치할 VPC ID"
  type        = string
}

variable "subnet_ids" {
  description = "ALB가 배치될 최소 2개 이상의 퍼블릭 서브넷 ID 목록"
  type        = list(string)
}

variable "target_instance_id" {
  description = "Target Group에 등록할 타깃 EC2 인스턴스 ID"
  type        = string
}

variable "target_port" {
  description = "타깃 EC2 Nginx 서비스 포트"
  type        = number
  default     = 80
}

variable "tags" {
  description = "추가 리소스 태그"
  type        = map(string)
  default     = {}
}
