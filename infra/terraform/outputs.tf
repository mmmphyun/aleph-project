# CloudShield Terraform 루트 모듈 출력 명세
# 소유자: 클라우드 A (플랫폼 전담)

output "dynamodb_table_name" {
  description = "인증 실패 집계 DynamoDB 테이블 명칭"
  value       = module.dynamodb.table_name
}

output "dynamodb_table_arn" {
  description = "인증 실패 집계 DynamoDB 테이블 ARN"
  value       = module.dynamodb.table_arn
}

output "lambda_function_name" {
  description = "배포된 오케스트레이터 Lambda 함수명"
  value       = module.lambda.function_name
}

output "lambda_function_arn" {
  description = "배포된 오케스트레이터 Lambda 함수 ARN"
  value       = module.lambda.function_arn
}

output "lambda_role_arn" {
  description = "오케스트레이터 Lambda 실행 IAM Role ARN"
  value       = module.lambda.role_arn
}

output "vpc_id" {
  description = "프로비저닝된 CloudShield VPC ID"
  value       = module.vpc.vpc_id
}

output "baseline_sg_id" {
  description = "타깃 EC2 초기 부착 기본 Security Group ID"
  value       = module.quarantine_sg.baseline_sg_id
}

output "quarantine_sg_id" {
  description = "침해 시 교체 격리 Security Group ID"
  value       = module.quarantine_sg.quarantine_sg_id
}

output "quarantine_sg_arn" {
  description = "격리 Security Group ARN (Lambda 정책 바인딩)"
  value       = module.quarantine_sg.quarantine_sg_arn
}

output "waf_ipset_arn" {
  description = "L7 차단 WAFv2 IPSet ARN"
  value       = module.waf.ipset_arn
}

output "waf_web_acl_arn" {
  description = "Web 타깃 보호 WAFv2 WebACL ARN"
  value       = module.waf.web_acl_arn
}

output "target_instance_id" {
  description = "타깃 EC2 인스턴스 ID"
  value       = module.ec2_target.instance_id
}

output "target_private_ip" {
  description = "타깃 EC2 프라이빗 IP 주소"
  value       = module.ec2_target.private_ip
}

output "target_public_ip" {
  description = "타깃 EC2 퍼블릭 IP 주소"
  value       = module.ec2_target.public_ip
}
