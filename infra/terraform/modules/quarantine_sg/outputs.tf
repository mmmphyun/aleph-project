output "vpc_id" {
  description = "두 SG에 지정한 VPC; EC2 VPC 일치 확인용"
  value       = var.vpc_id
}

output "baseline_sg_id" {
  description = "일반 테스트 트래픽용 SG ID; EC2 초기 연결 후보"
  value       = aws_security_group.baseline.id
}

output "quarantine_sg_id" {
  description = "허용 규칙 없는 격리 SG ID; 런타임 교체 담당자에게 전달"
  value       = aws_security_group.quarantine.id
}

output "quarantine_sg_arn" {
  description = "Lambda IAM 최소 권한 정책의 quarantine_sg_arn 입력에 연결"
  value       = aws_security_group.quarantine.arn
}

output "quarantine_sg_name" {
  description = "엔진의 VPC별 이름 탐색 계약 확인용"
  value       = aws_security_group.quarantine.name
}
