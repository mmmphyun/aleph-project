# 루트 소유권을 유지하면서 기존 Lambda와 네트워크 출력에 연결하는 독립 실행 예제.
terraform {
  required_version = ">= 1.7.0"
  required_providers {
    aws = { source = "hashicorp/aws", version = "~> 5.0" }
  }
}
provider "aws" {
  region = "ap-northeast-2"
}
variable "ami_id" { type = string }
variable "subnet_id" { type = string }
variable "security_group_ids" { type = list(string) }
variable "lambda_function_arn" { type = string }

module "ec2_target" {
  source              = "../.."
  ami_id              = var.ami_id
  subnet_id           = var.subnet_id
  security_group_ids  = var.security_group_ids
  lambda_function_arn = var.lambda_function_arn
}
output "instance_id" {
  value = module.ec2_target.instance_id
}
