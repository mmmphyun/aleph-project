# 정책 값을 테스트 입력에 복제하지 않는다. 순수 HCL 산출물을 먼저 평가하고
# 그 출력을 기존 SG 모듈의 입력으로 전달해 정책 변경이 실제 리소스 검증에 반영된다.
# 모든 SG 실행은 mock plan이며 실제 AWS 호출·SG 부착을 수행하지 않는다.
mock_provider "aws" {
  override_during = plan
}

run "external_policy" {
  command = plan
  module {
    source = "./policies/external_bootstrap"
  }
}

run "external_policy_with_approved_ingress" {
  command = plan
  variables {
    vpc_id = "vpc-0123456789abcdef0"
    traffic = {
      ingress = {
        ssh = {
          cidr        = "198.51.100.10/32"
          protocol    = "tcp"
          from_port   = 22
          to_port     = 22
          description = "Approved SSH test source"
        }
      }
      egress = run.external_policy.egress
    }
  }
  assert {
    condition = length(aws_security_group.baseline.egress) == 2 && toset([
      for r in aws_security_group.baseline.egress : r.from_port
      ]) == toset([80, 443]) && alltrue([
      for r in aws_security_group.baseline.egress :
      r.protocol == "tcp" && r.from_port == r.to_port &&
      r.cidr_blocks == tolist(["0.0.0.0/0"]) &&
      length(r.ipv6_cidr_blocks) == 0 && length(r.prefix_list_ids) == 0 &&
      length(r.security_groups) == 0 && r.self == false
    ])
    error_message = "외부 정책은 전체 IPv4 대상 TCP 80/443 단일 포트 두 규칙만 생성해야 합니다."
  }
  assert {
    condition = length(aws_security_group.baseline.ingress) == 1 && alltrue([
      for r in aws_security_group.baseline.ingress :
      r.protocol == "tcp" && r.from_port == 22 && r.to_port == 22 &&
      r.cidr_blocks == tolist(["198.51.100.10/32"]) &&
      length(r.ipv6_cidr_blocks) == 0 && length(r.prefix_list_ids) == 0 &&
      length(r.security_groups) == 0 && r.self == false
    ])
    error_message = "외부 송신 정책 선택으로 승인된 ingress가 확대되면 안 됩니다."
  }
  assert {
    condition     = length(aws_security_group.quarantine.ingress) == 0 && length(aws_security_group.quarantine.egress) == 0
    error_message = "외부 정책을 사용해도 격리 SG는 양방향 빈 규칙이어야 합니다."
  }
}

run "external_policy_with_empty_ingress" {
  command = plan
  variables {
    vpc_id  = "vpc-0123456789abcdef0"
    traffic = { ingress = {}, egress = run.external_policy.egress }
  }
  assert {
    condition     = length(aws_security_group.baseline.ingress) == 0 && length(aws_security_group.baseline.egress) == 2 && length(aws_security_group.quarantine.ingress) == 0 && length(aws_security_group.quarantine.egress) == 0
    error_message = "외부 정책은 빈 ingress를 개방하거나 격리 SG를 변경하면 안 됩니다."
  }
}
