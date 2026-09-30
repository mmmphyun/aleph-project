# CloudShield Terraform 프로바이더 기본 설정
# 소유자: 클라우드 A (플랫폼 전담)
#
# Why:
#   모든 인프라 리소스에 일관된 프로젝트 거버넌스 태그(Project, Environment, ManagedBy)를
#   default_tags 블록을 통해 일괄 강제하여 비용 추적 및 리소스 식별성을 보장함.

provider "aws" {
  region = var.aws_region

  default_tags {
    tags = {
      Project   = "CloudShield"
      ManagedBy = "Terraform"
      Env       = var.environment
    }
  }
}
