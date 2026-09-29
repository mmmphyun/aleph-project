# CloudShield DynamoDB Terraform 모듈 출력 명세
# 소유자: 클라우드 A (플랫폼 전담)

output "table_name" {
  description = "생성된 DynamoDB 상태 테이블 명칭"
  value       = aws_dynamodb_table.auth_window.name
}

output "table_arn" {
  description = "생성된 DynamoDB 상태 테이블 ARN (Lambda IAM 정책 바인딩용)"
  value       = aws_dynamodb_table.auth_window.arn
}
