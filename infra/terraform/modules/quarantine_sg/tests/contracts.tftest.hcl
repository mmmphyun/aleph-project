# 실제 AWS 호출 없이 mock provider로 검증한다. 모든 실행은 plan 전용이다.
mock_provider "aws" {
  override_during = plan
}
override_resource {
  override_during = plan
  target          = aws_security_group.baseline
  values          = { "id" = "sg-0123456789abcdef0" }
}
override_resource {
  override_during = plan
  target          = aws_security_group.quarantine
  values          = { "id" = "sg-1123456789abcdef0", "arn" = "arn:aws:ec2:ap-northeast-2:123456789012:security-group/sg-1123456789abcdef0" }
}
variables {
  vpc_id  = "vpc-0123456789abcdef0"
  traffic = { "ingress" = { "ssh" = { "cidr" = "198.51.100.10/32", "protocol" = "tcp", "from_port" = 22, "to_port" = 22, "description" = "Approved SSH test source" } }, "egress" = { "collector" = { "cidr" = "10.42.20.0/24", "protocol" = "tcp", "from_port" = 443, "to_port" = 443, "description" = "Example collector only" } } }
}
run "security_group_contract" {
  command = plan
  assert {
    condition     = length(aws_security_group.quarantine.ingress) == 0 && length(aws_security_group.quarantine.egress) == 0
    error_message = "Quarantine must manage empty permissions"
  }
  assert {
    condition     = aws_security_group.baseline.vpc_id == var.vpc_id && aws_security_group.quarantine.vpc_id == var.vpc_id
    error_message = "Both SGs must use the input VPC"
  }
  assert {
    condition     = aws_security_group.quarantine.name == "CloudShield-Quarantine-SG"
    error_message = "Engine lookup name must match"
  }
  assert {
    condition     = output.baseline_sg_id == aws_security_group.baseline.id && output.quarantine_sg_id == aws_security_group.quarantine.id && output.baseline_sg_id != output.quarantine_sg_id
    error_message = "SG outputs must be distinct and referenced correctly"
  }
  assert {
    condition     = output.quarantine_sg_arn == aws_security_group.quarantine.arn
    error_message = "Lambda policy must consume the quarantine ARN"
  }
  assert {
    condition     = length(aws_security_group.baseline.ingress) == 1 && one(aws_security_group.baseline.ingress).from_port == 22 && one(aws_security_group.baseline.ingress).cidr_blocks == tolist(["198.51.100.10/32"])
    error_message = "Baseline must retain only explicit inbound traffic"
  }
  assert {
    condition     = length(aws_security_group.baseline.egress) == 1 && one(aws_security_group.baseline.egress).to_port == 443 && one(aws_security_group.baseline.egress).cidr_blocks == tolist(["10.42.20.0/24"])
    error_message = "Egress must be explicit"
  }
}
run "empty_baseline" {
  command = plan
  variables { traffic = { "ingress" = {}, "egress" = {} } }
  assert {
    condition     = length(aws_security_group.baseline.ingress) == 0 && length(aws_security_group.baseline.egress) == 0
    error_message = "Empty input must manage zero rules"
  }
}
run "reject_world" {
  command = plan
  variables { traffic = { "ingress" = { "ssh" = { "cidr" = "0.0.0.0/0", "protocol" = "tcp", "from_port" = 22, "to_port" = 22, "description" = "Approved SSH test source" } }, "egress" = { "collector" = { "cidr" = "10.42.20.0/24", "protocol" = "tcp", "from_port" = 443, "to_port" = 443, "description" = "Example collector only" } } } }
  expect_failures = [var.traffic]
}
run "reject_invalid_cidr" {
  command = plan
  variables { traffic = { "ingress" = { "ssh" = { "cidr" = "bad", "protocol" = "tcp", "from_port" = 22, "to_port" = 22, "description" = "Approved SSH test source" } }, "egress" = { "collector" = { "cidr" = "10.42.20.0/24", "protocol" = "tcp", "from_port" = 443, "to_port" = 443, "description" = "Example collector only" } } } }
  expect_failures = [var.traffic]
}
run "reject_ipv6" {
  command = plan
  variables { traffic = { "ingress" = { "ssh" = { "cidr" = "::/0", "protocol" = "tcp", "from_port" = 22, "to_port" = 22, "description" = "Approved SSH test source" } }, "egress" = { "collector" = { "cidr" = "10.42.20.0/24", "protocol" = "tcp", "from_port" = 443, "to_port" = 443, "description" = "Example collector only" } } } }
  expect_failures = [var.traffic]
}
run "reject_host_bits" {
  command = plan
  variables { traffic = { "ingress" = { "ssh" = { "cidr" = "198.51.100.1/24", "protocol" = "tcp", "from_port" = 22, "to_port" = 22, "description" = "Approved SSH test source" } }, "egress" = { "collector" = { "cidr" = "10.42.20.0/24", "protocol" = "tcp", "from_port" = 443, "to_port" = 443, "description" = "Example collector only" } } } }
  expect_failures = [var.traffic]
}
run "reject_protocol" {
  command = plan
  variables { traffic = { "ingress" = { "ssh" = { "cidr" = "198.51.100.10/32", "protocol" = "-1", "from_port" = 22, "to_port" = 22, "description" = "Approved SSH test source" } }, "egress" = { "collector" = { "cidr" = "10.42.20.0/24", "protocol" = "tcp", "from_port" = 443, "to_port" = 443, "description" = "Example collector only" } } } }
  expect_failures = [var.traffic]
}
run "reject_fractional_port" {
  command = plan
  variables { traffic = { "ingress" = { "ssh" = { "cidr" = "198.51.100.10/32", "protocol" = "tcp", "from_port" = 1.5, "to_port" = 22, "description" = "Approved SSH test source" } }, "egress" = { "collector" = { "cidr" = "10.42.20.0/24", "protocol" = "tcp", "from_port" = 443, "to_port" = 443, "description" = "Example collector only" } } } }
  expect_failures = [var.traffic]
}
run "reject_zero_port" {
  command = plan
  variables { traffic = { "ingress" = { "ssh" = { "cidr" = "198.51.100.10/32", "protocol" = "tcp", "from_port" = 0, "to_port" = 22, "description" = "Approved SSH test source" } }, "egress" = { "collector" = { "cidr" = "10.42.20.0/24", "protocol" = "tcp", "from_port" = 443, "to_port" = 443, "description" = "Example collector only" } } } }
  expect_failures = [var.traffic]
}
run "reject_reversed_ports" {
  command = plan
  variables { traffic = { "ingress" = { "ssh" = { "cidr" = "198.51.100.10/32", "protocol" = "tcp", "from_port" = 23, "to_port" = 22, "description" = "Approved SSH test source" } }, "egress" = { "collector" = { "cidr" = "10.42.20.0/24", "protocol" = "tcp", "from_port" = 443, "to_port" = 443, "description" = "Example collector only" } } } }
  expect_failures = [var.traffic]
}
run "reject_large_port" {
  command = plan
  variables { traffic = { "ingress" = { "ssh" = { "cidr" = "198.51.100.10/32", "protocol" = "tcp", "from_port" = 22, "to_port" = 65536, "description" = "Approved SSH test source" } }, "egress" = { "collector" = { "cidr" = "10.42.20.0/24", "protocol" = "tcp", "from_port" = 443, "to_port" = 443, "description" = "Example collector only" } } } }
  expect_failures = [var.traffic]
}
run "reject_blank_description" {
  command = plan
  variables { traffic = { "ingress" = { "ssh" = { "cidr" = "198.51.100.10/32", "protocol" = "tcp", "from_port" = 22, "to_port" = 22, "description" = "" } }, "egress" = { "collector" = { "cidr" = "10.42.20.0/24", "protocol" = "tcp", "from_port" = 443, "to_port" = 443, "description" = "Example collector only" } } } }
  expect_failures = [var.traffic]
}
run "reject_duplicate" {
  command = plan
  variables { traffic = { "ingress" = { "ssh" = { "cidr" = "198.51.100.10/32", "protocol" = "tcp", "from_port" = 22, "to_port" = 22, "description" = "Approved SSH test source" }, "duplicate" = { "cidr" = "198.51.100.10/32", "protocol" = "tcp", "from_port" = 22, "to_port" = 22, "description" = "Approved SSH test source" } }, "egress" = { "collector" = { "cidr" = "10.42.20.0/24", "protocol" = "tcp", "from_port" = 443, "to_port" = 443, "description" = "Example collector only" } } } }
  expect_failures = [var.traffic]
}
run "reject_invalid_vpc" {
  command = plan
  variables { vpc_id = "vpc-wrong" }
  expect_failures = [var.vpc_id]
}
