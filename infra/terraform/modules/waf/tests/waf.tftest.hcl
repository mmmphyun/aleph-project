# mock provider의 apply는 AWS를 호출하지 않는다. 리소스 연결과 입력 제약을 검증하며
# 실제 HTTP 차단, 전파 시간, WCU 실측은 배포 후 별도 관통 검증 대상이다.
mock_provider "aws" {
  mock_resource "aws_wafv2_ip_set" {
    defaults = {
      arn = "arn:aws:wafv2:ap-northeast-2:123456789012:regional/ipset/CloudShield-Block-IPSet/11111111-1111-1111-1111-111111111111"
      id  = "11111111-1111-1111-1111-111111111111"
    }
  }

  mock_resource "aws_wafv2_web_acl" {
    defaults = {
      arn      = "arn:aws:wafv2:ap-northeast-2:123456789012:regional/webacl/CloudShield-WebACL/22222222-2222-2222-2222-222222222222"
      id       = "22222222-2222-2222-2222-222222222222"
      capacity = 1
    }
  }
}

run "empty_list_and_block_policy" {
  assert {
    condition     = length(aws_wafv2_ip_set.blocked.addresses) == 0
    error_message = "초기 차단 목록은 비어 있어야 합니다."
  }

  assert {
    condition     = output.ipset_name == "CloudShield-Block-IPSet" && output.scope == "REGIONAL" && aws_wafv2_ip_set.blocked.ip_address_version == "IPV4"
    error_message = "기존 Lambda 차단 엔진의 이름·범위·IPv4 계약과 일치해야 합니다."
  }

  assert {
    condition     = length(aws_wafv2_web_acl.this.default_action[0].allow) == 1 && length(aws_wafv2_web_acl.this.default_action[0].block) == 0
    error_message = "차단 목록에 없는 요청의 기본 동작은 Allow여야 합니다."
  }

  assert {
    condition     = length(aws_wafv2_web_acl.this.rule) == 1 && one(aws_wafv2_web_acl.this.rule).priority == 0 && length(one(aws_wafv2_web_acl.this.rule).action[0].block) == 1
    error_message = "IPSet 차단 규칙이 우선순위 0의 Block 동작이어야 합니다."
  }

  assert {
    condition     = one(aws_wafv2_web_acl.this.rule).statement[0].ip_set_reference_statement[0].arn == output.ipset_arn && length(one(aws_wafv2_web_acl.this.rule).statement[0].ip_set_reference_statement[0].ip_set_forwarded_ip_config) == 0
    error_message = "WebACL은 생성한 IPSet을 직접 참조하고 임의 전달 헤더를 신뢰하지 않아야 합니다."
  }

  assert {
    condition     = output.expected_rule_wcu == 1 && aws_wafv2_web_acl.this.visibility_config[0].cloudwatch_metrics_enabled && !aws_wafv2_web_acl.this.visibility_config[0].sampled_requests_enabled && one(aws_wafv2_web_acl.this.rule).visibility_config[0].cloudwatch_metrics_enabled && !one(aws_wafv2_web_acl.this.rule).visibility_config[0].sampled_requests_enabled
    error_message = "직접 IP 비교의 설계 WCU는 1이며 메트릭은 활성화하고 요청 샘플은 저장하지 않아야 합니다."
  }
}

run "environment_and_reserved_tags" {
  command = plan

  variables {
    environment = "stage"
    tags = {
      Owner       = "security"
      Project     = "other"
      Environment = "prod"
      ManagedBy   = "manual"
    }
  }

  assert {
    condition     = aws_wafv2_ip_set.blocked.tags["Project"] == "CloudShield" && aws_wafv2_ip_set.blocked.tags["Environment"] == "stage" && aws_wafv2_ip_set.blocked.tags["ManagedBy"] == "Terraform" && aws_wafv2_ip_set.blocked.tags["Owner"] == "security" && aws_wafv2_web_acl.this.tags == aws_wafv2_ip_set.blocked.tags
    error_message = "추가 태그는 유지하되 필수 식별 태그를 덮어쓸 수 없어야 합니다."
  }

  assert {
    condition     = aws_wafv2_web_acl.this.visibility_config[0].metric_name == "CloudShieldWebACL-stage"
    error_message = "메트릭 구분자에 검증된 환경값이 반영되어야 합니다."
  }
}

run "reject_empty_environment" {
  command = plan
  variables {
    environment = ""
  }
  expect_failures = [var.environment]
}

run "reject_metric_separator" {
  command = plan
  variables {
    environment = "dev/prod"
  }
  expect_failures = [var.environment]
}

run "reject_oversized_environment" {
  command = plan
  variables {
    environment = "abcdefghijklmnopqrstuvwxyz1234567"
  }
  expect_failures = [var.environment]
}
