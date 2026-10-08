output "ipset_arn" {
  description = "Lambda 최소 권한 정책의 waf_ipset_arn 입력에 연결할 IPSet ARN"
  value       = aws_wafv2_ip_set.blocked.arn
}

output "ipset_id" {
  description = "WAFv2 조회·갱신 API에 사용할 IPSet ID"
  value       = aws_wafv2_ip_set.blocked.id
}

output "ipset_name" {
  description = "기존 차단 엔진의 DEFAULT_WAF_IPSET_NAME과 일치하는 이름"
  value       = aws_wafv2_ip_set.blocked.name
}

output "scope" {
  description = "기존 차단 엔진의 DEFAULT_WAF_SCOPE와 일치하는 범위"
  value       = aws_wafv2_ip_set.blocked.scope
}

output "web_acl_arn" {
  description = "플랫폼에서 대상 ALB의 WebACL 연결에 사용할 ARN"
  value       = aws_wafv2_web_acl.this.arn
}

output "web_acl_id" {
  description = "운영 검증에 사용할 WebACL ID"
  value       = aws_wafv2_web_acl.this.id
}

output "expected_rule_wcu" {
  description = "출발지 IP 직접 비교 문장 1개의 설계 WCU (AWS 실측 capacity와 구별)"
  value       = local.expected_rule_wcu
}

output "web_acl_capacity" {
  description = "AWS가 리소스 생성 후 반환한 실제 WebACL capacity"
  value       = aws_wafv2_web_acl.this.capacity
}
