# CloudShield ALB 모듈 출력값 명세
# 소유자: 클라우드 A (플랫폼 전담)

output "alb_arn" {
  description = "WAFv2 WebACL Association에 사용할 ALB ARN"
  value       = aws_lb.this.arn
}

output "alb_id" {
  description = "ALB 리소스 ID"
  value       = aws_lb.this.id
}

output "alb_dns_name" {
  description = "브라우저 및 클라이언트 접근용 ALB 공용 DNS 이름"
  value       = aws_lb.this.dns_name
}

output "target_group_arn" {
  description = "타깃 그룹 ARN"
  value       = aws_lb_target_group.this.arn
}

output "alb_security_group_id" {
  description = "ALB 전용 보안 그룹 ID"
  value       = aws_security_group.alb.id
}
