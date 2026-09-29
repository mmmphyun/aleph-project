# CloudShield Lambda Terraform 모듈 출력 명세
# 소유자: 클라우드 A (플랫폼 전담)

output "function_name" {
  description = "배포된 오케스트레이터 Lambda 함수명"
  value       = aws_lambda_function.orchestrator.function_name
}

output "function_arn" {
  description = "배포된 오케스트레이터 Lambda 함수 ARN"
  value       = aws_lambda_function.orchestrator.arn
}

output "role_arn" {
  description = "Lambda 실행 IAM Role ARN"
  value       = aws_iam_role.lambda_exec.arn
}
