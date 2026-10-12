# egress /0 허용으로 공통 제약이 누락되지 않도록 실제 HCL을 평가한다. AWS 호출 없는 mock plan만 실행한다.

mock_provider "aws" {
  override_during = plan
}

variables {
  vpc_id = "vpc-0123456789abcdef0"
}

# CIDR 주소뿐 아니라 prefix 표기도 정규화해야 동일 목적지의 별칭 입력을 거부할 수 있다.
run "reject_egress_zero_padded_world_prefix" {
  command = plan
  variables {
    traffic = {
      ingress = {}
      egress = {
        outbound = {
          cidr        = "0.0.0.0/00"
          protocol    = "tcp"
          from_port   = 443
          to_port     = 443
          description = "Noncanonical world prefix"
        }
      }
    }
  }
  expect_failures = [var.traffic]
}

run "reject_egress_zero_padded_host_prefix" {
  command = plan
  variables {
    traffic = {
      ingress = {}
      egress = {
        outbound = {
          cidr        = "198.51.100.10/032"
          protocol    = "tcp"
          from_port   = 443
          to_port     = 443
          description = "Noncanonical host prefix"
        }
      }
    }
  }
  expect_failures = [var.traffic]
}

run "reject_ingress_zero_padded_host_prefix" {
  command = plan
  variables {
    traffic = {
      ingress = {
        ssh = {
          cidr        = "198.51.100.10/032"
          protocol    = "tcp"
          from_port   = 22
          to_port     = 22
          description = "Noncanonical inbound prefix"
        }
      }
      egress = {}
    }
  }
  expect_failures = [var.traffic]
}

run "reject_egress_mixed_world_prefix_aliases" {
  command = plan
  variables {
    traffic = {
      ingress = {}
      egress = {
        for key, cidr in { canonical = "0.0.0.0/0", alias = "0.0.0.0/00" } : key => {
          cidr                       = cidr
          protocol                   = "tcp"
          from_port                  = 443
          to_port                    = 443
          description                = "Same destination and service"
        }
      }
    }
  }
  expect_failures = [var.traffic]
}

run "empty_egress_keeps_ingress" {
  command = plan
  variables { traffic = { "ingress" : { "ssh" : { "cidr" : "198.51.100.10/32", "protocol" : "tcp", "from_port" : 22, "to_port" : 22, "description" : "Approved SSH test source" } }, "egress" : {} } }
  assert {
    condition     = length(aws_security_group.baseline.egress) == 0 && length(aws_security_group.baseline.ingress) == 1 && length(aws_security_group.quarantine.ingress) == 0 && length(aws_security_group.quarantine.egress) == 0
    error_message = "빈 baseline egress 입력은 기본 개방 없이 ingress와 격리 계약을 유지해야 합니다."
  }
}


run "reject_egress_invalid_cidr" {
  command = plan
  variables { traffic = { "ingress" : { "ssh" : { "cidr" : "198.51.100.10/32", "protocol" : "tcp", "from_port" : 22, "to_port" : 22, "description" : "Approved SSH test source" } }, "egress" : { "outbound" : { "cidr" : "bad", "protocol" : "tcp", "from_port" : 443, "to_port" : 443, "description" : "Input validation only" } } } }
  expect_failures = [var.traffic]
}


run "reject_egress_invalid_prefix" {
  command = plan
  variables { traffic = { "ingress" : { "ssh" : { "cidr" : "198.51.100.10/32", "protocol" : "tcp", "from_port" : 22, "to_port" : 22, "description" : "Approved SSH test source" } }, "egress" : { "outbound" : { "cidr" : "10.42.20.0/33", "protocol" : "tcp", "from_port" : 443, "to_port" : 443, "description" : "Input validation only" } } } }
  expect_failures = [var.traffic]
}


run "reject_egress_ipv6" {
  command = plan
  variables { traffic = { "ingress" : { "ssh" : { "cidr" : "198.51.100.10/32", "protocol" : "tcp", "from_port" : 22, "to_port" : 22, "description" : "Approved SSH test source" } }, "egress" : { "outbound" : { "cidr" : "::/0", "protocol" : "tcp", "from_port" : 443, "to_port" : 443, "description" : "Input validation only" } } } }
  expect_failures = [var.traffic]
}


run "reject_egress_host_bits" {
  command = plan
  variables { traffic = { "ingress" : { "ssh" : { "cidr" : "198.51.100.10/32", "protocol" : "tcp", "from_port" : 22, "to_port" : 22, "description" : "Approved SSH test source" } }, "egress" : { "outbound" : { "cidr" : "10.42.20.1/24", "protocol" : "tcp", "from_port" : 443, "to_port" : 443, "description" : "Input validation only" } } } }
  expect_failures = [var.traffic]
}


run "reject_egress_noncanonical_world" {
  command = plan
  variables { traffic = { "ingress" : { "ssh" : { "cidr" : "198.51.100.10/32", "protocol" : "tcp", "from_port" : 22, "to_port" : 22, "description" : "Approved SSH test source" } }, "egress" : { "outbound" : { "cidr" : "198.51.100.10/0", "protocol" : "tcp", "from_port" : 443, "to_port" : 443, "description" : "Input validation only" } } } }
  expect_failures = [var.traffic]
}


run "reject_egress_protocol" {
  command = plan
  variables { traffic = { "ingress" : { "ssh" : { "cidr" : "198.51.100.10/32", "protocol" : "tcp", "from_port" : 22, "to_port" : 22, "description" : "Approved SSH test source" } }, "egress" : { "outbound" : { "cidr" : "0.0.0.0/0", "protocol" : "-1", "from_port" : 443, "to_port" : 443, "description" : "Input validation only" } } } }
  expect_failures = [var.traffic]
}


run "reject_egress_icmp" {
  command = plan
  variables { traffic = { "ingress" : { "ssh" : { "cidr" : "198.51.100.10/32", "protocol" : "tcp", "from_port" : 22, "to_port" : 22, "description" : "Approved SSH test source" } }, "egress" : { "outbound" : { "cidr" : "0.0.0.0/0", "protocol" : "icmp", "from_port" : 443, "to_port" : 443, "description" : "Input validation only" } } } }
  expect_failures = [var.traffic]
}


run "reject_egress_fractional_port" {
  command = plan
  variables { traffic = { "ingress" : { "ssh" : { "cidr" : "198.51.100.10/32", "protocol" : "tcp", "from_port" : 22, "to_port" : 22, "description" : "Approved SSH test source" } }, "egress" : { "outbound" : { "cidr" : "0.0.0.0/0", "protocol" : "tcp", "from_port" : 1.5, "to_port" : 443, "description" : "Input validation only" } } } }
  expect_failures = [var.traffic]
}


run "reject_egress_zero_port" {
  command = plan
  variables { traffic = { "ingress" : { "ssh" : { "cidr" : "198.51.100.10/32", "protocol" : "tcp", "from_port" : 22, "to_port" : 22, "description" : "Approved SSH test source" } }, "egress" : { "outbound" : { "cidr" : "0.0.0.0/0", "protocol" : "tcp", "from_port" : 0, "to_port" : 443, "description" : "Input validation only" } } } }
  expect_failures = [var.traffic]
}


run "reject_egress_reversed_ports" {
  command = plan
  variables { traffic = { "ingress" : { "ssh" : { "cidr" : "198.51.100.10/32", "protocol" : "tcp", "from_port" : 22, "to_port" : 22, "description" : "Approved SSH test source" } }, "egress" : { "outbound" : { "cidr" : "0.0.0.0/0", "protocol" : "tcp", "from_port" : 444, "to_port" : 443, "description" : "Input validation only" } } } }
  expect_failures = [var.traffic]
}


run "reject_egress_large_port" {
  command = plan
  variables { traffic = { "ingress" : { "ssh" : { "cidr" : "198.51.100.10/32", "protocol" : "tcp", "from_port" : 22, "to_port" : 22, "description" : "Approved SSH test source" } }, "egress" : { "outbound" : { "cidr" : "0.0.0.0/0", "protocol" : "tcp", "from_port" : 443, "to_port" : 65536, "description" : "Input validation only" } } } }
  expect_failures = [var.traffic]
}


run "reject_egress_blank_description" {
  command = plan
  variables { traffic = { "ingress" : { "ssh" : { "cidr" : "198.51.100.10/32", "protocol" : "tcp", "from_port" : 22, "to_port" : 22, "description" : "Approved SSH test source" } }, "egress" : { "outbound" : { "cidr" : "0.0.0.0/0", "protocol" : "tcp", "from_port" : 443, "to_port" : 443, "description" : "" } } } }
  expect_failures = [var.traffic]
}


run "reject_egress_long_description" {
  command = plan
  variables { traffic = { "ingress" : { "ssh" : { "cidr" : "198.51.100.10/32", "protocol" : "tcp", "from_port" : 22, "to_port" : 22, "description" : "Approved SSH test source" } }, "egress" : { "outbound" : { "cidr" : "0.0.0.0/0", "protocol" : "tcp", "from_port" : 443, "to_port" : 443, "description" : "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx" } } } }
  expect_failures = [var.traffic]
}


run "reject_egress_non_ascii_description" {
  command = plan
  variables { traffic = { "ingress" : { "ssh" : { "cidr" : "198.51.100.10/32", "protocol" : "tcp", "from_port" : 22, "to_port" : 22, "description" : "Approved SSH test source" } }, "egress" : { "outbound" : { "cidr" : "0.0.0.0/0", "protocol" : "tcp", "from_port" : 443, "to_port" : 443, "description" : "한글" } } } }
  expect_failures = [var.traffic]
}


run "reject_egress_duplicate" {
  command = plan
  variables { traffic = { "ingress" : { "ssh" : { "cidr" : "198.51.100.10/32", "protocol" : "tcp", "from_port" : 22, "to_port" : 22, "description" : "Approved SSH test source" } }, "egress" : { "first" : { "cidr" : "0.0.0.0/0", "protocol" : "tcp", "from_port" : 443, "to_port" : 443, "description" : "Input validation only" }, "second" : { "cidr" : "0.0.0.0/0", "protocol" : "tcp", "from_port" : 443, "to_port" : 443, "description" : "Different description" } } } }
  expect_failures = [var.traffic]
}


run "allow_egress_60_rules" {
  command = plan
  variables {
    traffic = { ingress = { "ssh" : { "cidr" : "198.51.100.10/32", "protocol" : "tcp", "from_port" : 22, "to_port" : 22, "description" : "Approved SSH test source" } }, egress = { for i in range(1, 61) : "rule${i}" => { cidr = "0.0.0.0/0", protocol = "udp", from_port = i, to_port = 65535, description = "Quota boundary" } } }
  }
  assert {
    condition     = length(aws_security_group.baseline.egress) == 60 && alltrue([for r in aws_security_group.baseline.egress : r.protocol == "udp" && r.to_port == 65535 && r.cidr_blocks == tolist(["0.0.0.0/0"])]) && length(aws_security_group.quarantine.ingress) == 0 && length(aws_security_group.quarantine.egress) == 0
    error_message = "60개 정규 UDP /0 입력과 정수 포트 경계를 허용하되 격리 SG는 비어 있어야 합니다."
  }
}


run "reject_egress_61_rules" {
  command = plan
  variables {
    traffic = { ingress = { "ssh" : { "cidr" : "198.51.100.10/32", "protocol" : "tcp", "from_port" : 22, "to_port" : 22, "description" : "Approved SSH test source" } }, egress = { for i in range(1, 62) : "rule${i}" => { cidr = "0.0.0.0/0", protocol = "udp", from_port = i, to_port = 65535, description = "Quota boundary" } } }
  }
  expect_failures = [var.traffic]
}
