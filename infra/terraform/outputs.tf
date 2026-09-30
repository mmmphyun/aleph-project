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
