# CloudShield Terraform 프로바이더 및 버전 고정 명세
# 소유자: 클라우드 A (플랫폼 전담)
#
# Why:
#   팀원 간 프로바이더 버전 불일치로 인한 Lock 파일 충돌 및 비결정론적 배포(Non-deterministic Plan)를
#   방지하기 위해 Terraform CLI 최소 버전 및 AWS/Archive 프로바이더 버전을 엄격히 제약함.

terraform {
  required_version = ">= 1.6.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
    archive = {
      source  = "hashicorp/archive"
      version = "~> 2.4"
    }
  }

  # NOTE: 원격 협업 시 S3/DynamoDB Remote State 백엔드를 설정합니다.
  # backend "s3" {
  #   bucket         = "cloudshield-tfstate-<account_id>"
  #   key            = "live/terraform.tfstate"
  #   region         = "ap-northeast-2"
  #   dynamodb_table = "cloudshield-tflocks"
  #   encrypt        = true
  # }
}
