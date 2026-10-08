mock_provider "aws" {
  override_during = plan
}
variables {
  vpc_id  = "vpc-0123456789abcdef0"
  traffic = { "ingress" = { "ssh" = { "cidr" = "198.51.100.10/32", "protocol" = "tcp", "from_port" = 22, "to_port" = 22, "description" = "Approved SSH test source" } }, "egress" = { "collector" = { "cidr" = "10.42.20.0/24", "protocol" = "tcp", "from_port" = 443, "to_port" = 443, "description" = "Example collector only" } } }
}

run "reject_world_egress" {
  command = plan
  variables { traffic = { "ingress" = { "ssh" = { "cidr" = "198.51.100.10/32", "protocol" = "tcp", "from_port" = 22, "to_port" = 22, "description" = "Approved SSH test source" } }, "egress" = { "collector" = { "cidr" = "0.0.0.0/0", "protocol" = "tcp", "from_port" = 443, "to_port" = 443, "description" = "Example collector only" } } } }
  expect_failures = [var.traffic]
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
