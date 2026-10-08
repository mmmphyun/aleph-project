# CloudShield L7 차단 정책 모듈 (보안 담당)
# Why: 기존 Lambda 엔진이 이름으로 찾는 REGIONAL IPv4 IPSet을 WebACL에 연결한다.
# Constraints: 단일 계정·리전의 CloudShield 스택을 대상으로 하며 차단은 IPv4 /32 단위다.
# Side-effects: 리소스 생성만 담당한다. 대상 ALB 연결과 Lambda IAM 결합은 루트 모듈 소관이다.
locals {
  ipset_name        = "CloudShield-Block-IPSet"
  block_rule_name   = "CloudShield-Block-IP"
  expected_rule_wcu = 1
  resource_tags = merge(var.tags, {
    Project     = "CloudShield"
    Environment = var.environment
    ManagedBy   = "Terraform"
  })
}

resource "aws_wafv2_ip_set" "blocked" {
  name               = local.ipset_name
  description        = "CloudShield runtime-managed IPv4 host block list"
  scope              = "REGIONAL"
  ip_address_version = "IPV4"
  addresses          = []
  tags               = local.resource_tags

  lifecycle {
    # 차단 목록은 Lambda가 LockToken으로 갱신한다. 재적용 시 빈 초기값으로 덮어쓰면
    # 공격자의 차단이 풀리므로 Terraform은 생성 이후 주소 변경을 소유하지 않는다.
    # 삭제·교체는 이 보호 범위 밖이며, 차단 해제는 기존 플랫폼 운영 절차를 따른다.
    ignore_changes = [addresses]
  }
}

resource "aws_wafv2_web_acl" "this" {
  name        = "CloudShield-WebACL"
  description = "CloudShield incident-driven IP blocking"
  scope       = "REGIONAL"
  tags        = local.resource_tags

  # 정상 요청을 허용하고 탐지 엔진이 확정한 IP만 차단하여 오탐의 영향 범위를 줄인다.
  default_action {
    allow {}
  }

  rule {
    name     = local.block_rule_name
    priority = 0

    action {
      block {}
    }

    statement {
      # 임의 X-Forwarded-For 헤더를 신뢰하지 않는다. 직접 관측된 출발지 IP를 비교하는
      # 단일 IPSet 문장은 1 WCU이며, 헤더 기반 확장은 별도 신뢰 경계 검토가 필요하다.
      ip_set_reference_statement {
        arn = aws_wafv2_ip_set.blocked.arn
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "CloudShieldBlockedIPs-${var.environment}"
      # 샘플 요청의 민감 헤더·쿼리 저장을 피한다. 전체 WAF 로깅은 플랫폼에서 별도 결합한다.
      sampled_requests_enabled = false
    }
  }

  visibility_config {
    cloudwatch_metrics_enabled = true
    metric_name                = "CloudShieldWebACL-${var.environment}"
    sampled_requests_enabled   = false
  }
}
