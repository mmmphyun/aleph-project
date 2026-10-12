mock_provider "aws" {
  override_during = plan
}
variables {
  vpc_id  = "vpc-0123456789abcdef0"
  traffic = { "ingress" = { "ssh" = { "cidr" = "198.51.100.10/32", "protocol" = "tcp", "from_port" = 22, "to_port" = 22, "description" = "Approved SSH test source" } }, "egress" = { "collector" = { "cidr" = "10.42.20.0/24", "protocol" = "tcp", "from_port" = 443, "to_port" = 443, "description" = "Example collector only" } } }
}

run "allow_world_egress" {
  command = plan
  variables { traffic = { "ingress" = { "ssh" = { "cidr" = "198.51.100.10/32", "protocol" = "tcp", "from_port" = 22, "to_port" = 22, "description" = "Approved SSH test source" } }, "egress" = { "collector" = { "cidr" = "0.0.0.0/0", "protocol" = "tcp", "from_port" = 443, "to_port" = 443, "description" = "Example collector only" } } } }
  assert {
    condition = length(aws_security_group.baseline.egress) == 1 && alltrue([
      for r in aws_security_group.baseline.egress :
      r.cidr_blocks == tolist(["0.0.0.0/0"]) && r.protocol == "tcp" &&
      r.from_port == 443 && r.to_port == 443 && r.description == "Example collector only" &&
      length(r.ipv6_cidr_blocks) == 0 && length(r.security_groups) == 0
    ])
    error_message = "명시적 baseline egress /0의 CIDR·프로토콜·포트·설명을 유지해야 합니다."
  }
  assert {
    condition     = length(aws_security_group.baseline.ingress) == 1 && one(aws_security_group.baseline.ingress).cidr_blocks == tolist(["198.51.100.10/32"])
    error_message = "egress /0 입력이 baseline ingress를 확장하면 안 됩니다."
  }
  assert {
    condition     = length(aws_security_group.quarantine.ingress) == 0 && length(aws_security_group.quarantine.egress) == 0
    error_message = "baseline egress /0 입력에도 격리 SG는 양방향 빈 규칙이어야 합니다."
  }
}

run "reject_rule_saturation" {
  command = plan
  variables {
    traffic = {
      ingress = { for i in range(1, 62) : "rule${i}" => {
        cidr        = "198.51.100.${i}/32"
        protocol    = "tcp"
        from_port   = 22
        to_port     = 22
        description = "Quota test"
      } }
      egress = {}
    }
  }
  expect_failures = [var.traffic]
}
run "reject_same_sg_names" {
  command = plan
  variables { names = { "baseline" = "CloudShield-SG", "quarantine" = "CloudShield-SG" } }
  expect_failures = [var.names]
}
