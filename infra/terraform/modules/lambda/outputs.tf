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

output "llm_function_name" {
  description = "배포된 사후 비동기 LLM 분석 워커 Lambda 함수명"
  value       = aws_lambda_function.llm_analyzer.function_name
}

output "llm_function_arn" {
  description = "배포된 사후 비동기 LLM 분석 워커 Lambda 함수 ARN"
  value       = aws_lambda_function.llm_analyzer.arn
}

output "llm_role_arn" {
  description = "LLM 분석 워커 Lambda 실행 IAM Role ARN"
  value       = aws_iam_role.llm_analyzer_exec.arn
}

output "eventbridge_rule_name" {
  description = "사후 비동기 분석 트리거용 EventBridge 규칙 명칭"
  value       = aws_cloudwatch_event_rule.threat_remediated.name
}

output "eventbridge_rule_arn" {
  description = "사후 비동기 분석 트리거용 EventBridge 규칙 ARN"
  value       = aws_cloudwatch_event_rule.threat_remediated.arn
}
