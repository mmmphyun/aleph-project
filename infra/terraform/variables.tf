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
  default     = "modules/lambda/build/orchestrator.zip"
}

variable "vpc_topology" {
  description = "VPC CIDR, AZ 목록 및 서브넷 매핑 토폴로지"
  type = object({
    vpc_cidr           = string
    availability_zones = set(string)
    public_subnets     = map(object({ cidr = string, availability_zone = string }))
    private_subnets    = map(object({ cidr = string, availability_zone = string }))
  })
  default = {
    vpc_cidr           = "10.42.0.0/16"
    availability_zones = ["ap-northeast-2a", "ap-northeast-2c"]
    public_subnets = {
      "public-2a" = {
        cidr              = "10.42.0.0/24"
        availability_zone = "ap-northeast-2a"
      }
    }
    private_subnets = {
      "private-2a" = {
        cidr              = "10.42.10.0/24"
        availability_zone = "ap-northeast-2a"
      }
    }
  }
}

variable "quarantine_traffic" {
  description = "기본 SG의 ingress/egress 트래픽 허용 명세 (격리 SG는 항상 빈 규칙 유지)"
  type = object({
    ingress = map(object({ cidr = string, protocol = string, from_port = number, to_port = number, description = string }))
    egress  = map(object({ cidr = string, protocol = string, from_port = number, to_port = number, description = string }))
  })
  default = {
    ingress = {
      "ssh" = {
        cidr        = "10.42.0.0/16"
        protocol    = "tcp"
        from_port   = 22
        to_port     = 22
        description = "Internal SSH access"
      }
      "http" = {
        cidr        = "10.42.0.0/16"
        protocol    = "tcp"
        from_port   = 80
        to_port     = 80
        description = "Internal HTTP access"
      }
    }
    egress = {
      "all-vpc" = {
        cidr        = "10.42.0.0/16"
        protocol    = "tcp"
        from_port   = 1
        to_port     = 65535
        description = "Allow VPC outbound TCP"
      }
    }
  }
}

variable "ec2_ami_id" {
  description = "타깃 EC2에 사용할 Ubuntu amd64 AMI ID"
  type        = string
  default     = "ami-0123456789abcdef0"
}

variable "ec2_instance_type" {
  description = "타깃 EC2 인스턴스 타입"
  type        = string
  default     = "t3.micro"
}

variable "ec2_associate_public_ip" {
  description = "타깃 EC2 공인 IP 할당 여부"
  type        = bool
  default     = true
}

variable "ec2_log_retention_days" {
  description = "CloudWatch 로그 그룹 보존 기간 (일)"
  type        = number
  default     = 7
}

