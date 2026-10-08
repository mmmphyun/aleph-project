# 실제 AWS 호출 없이 mock provider로 검증한다. 모든 실행은 plan 전용이다.
mock_provider "aws" {
  override_during = plan
}
override_resource {
  override_during = plan
  target          = aws_vpc.this
  values          = { "id" = "vpc-0123456789abcdef0" }
}
override_resource {
  override_during = plan
  target          = aws_internet_gateway.this
  values          = { "id" = "igw-0123456789abcdef0" }
}
override_resource {
  override_during = plan
  target          = aws_subnet.public["a"]
  values          = { "id" = "subnet-0123456789abcdef0" }
}
override_resource {
  override_during = plan
  target          = aws_subnet.private["a"]
  values          = { "id" = "subnet-1123456789abcdef0" }
}
override_resource {
  override_during = plan
  target          = aws_route_table.public
  values          = { "id" = "rtb-0123456789abcdef0" }
}
override_resource {
  override_during = plan
  target          = aws_route_table.private
  values          = { "id" = "rtb-1123456789abcdef0" }
}
variables { topology = { "vpc_cidr" = "10.42.0.0/16", "availability_zones" = ["ap-northeast-2a", "ap-northeast-2c"], "public_subnets" = { "a" = { "cidr" = "10.42.0.0/24", "availability_zone" = "ap-northeast-2a" } }, "private_subnets" = { "a" = { "cidr" = "10.42.10.0/24", "availability_zone" = "ap-northeast-2a" } } } }
run "routing_contract" {
  command = plan
  assert {
    condition     = output.vpc_id == aws_vpc.this.id && aws_subnet.public["a"].vpc_id == output.vpc_id && aws_subnet.private["a"].vpc_id == output.vpc_id
    error_message = "Subnets must share the output VPC"
  }
  assert {
    condition     = length(aws_route_table.public.route) == 1 && one(aws_route_table.public.route).cidr_block == "0.0.0.0/0" && one(aws_route_table.public.route).gateway_id == aws_internet_gateway.this.id
    error_message = "Public default route must use this IGW"
  }
  assert {
    condition     = length(aws_route_table.private.route) == 0
    error_message = "Private must have no explicit internet route"
  }
  assert {
    condition     = aws_route_table_association.public["a"].route_table_id == output.route_table_ids.public && aws_route_table_association.private["a"].route_table_id == output.route_table_ids.private
    error_message = "Routes must not cross tiers"
  }
  assert {
    condition     = aws_route_table_association.public["a"].subnet_id == output.public_subnet_ids.a && aws_route_table_association.private["a"].subnet_id == output.private_subnet_ids.a
    error_message = "Subnet outputs must match associations"
  }
  assert {
    condition     = !aws_subnet.public["a"].map_public_ip_on_launch && !aws_subnet.private["a"].map_public_ip_on_launch
    error_message = "Public IP assignment must be deliberate"
  }
  assert {
    condition     = length(aws_default_security_group.this.ingress) == 0 && length(aws_default_security_group.this.egress) == 0
    error_message = "Unused default SG must be empty"
  }
}
run "reject_invalid_cidr" {
  command = plan
  variables { topology = { "vpc_cidr" = "10.42.0.0/16", "availability_zones" = ["ap-northeast-2a", "ap-northeast-2c"], "public_subnets" = { "a" = { "cidr" = "10.42.0.0/24", "availability_zone" = "ap-northeast-2a" } }, "private_subnets" = { "a" = { "cidr" = "bad", "availability_zone" = "ap-northeast-2a" } } } }
  expect_failures = [var.topology]
}
run "reject_ipv6" {
  command = plan
  variables { topology = { "vpc_cidr" = "10.42.0.0/16", "availability_zones" = ["ap-northeast-2a", "ap-northeast-2c"], "public_subnets" = { "a" = { "cidr" = "10.42.0.0/24", "availability_zone" = "ap-northeast-2a" } }, "private_subnets" = { "a" = { "cidr" = "fd00::/64", "availability_zone" = "ap-northeast-2a" } } } }
  expect_failures = [var.topology]
}
run "reject_host_bits" {
  command = plan
  variables { topology = { "vpc_cidr" = "10.42.0.0/16", "availability_zones" = ["ap-northeast-2a", "ap-northeast-2c"], "public_subnets" = { "a" = { "cidr" = "10.42.0.0/24", "availability_zone" = "ap-northeast-2a" } }, "private_subnets" = { "a" = { "cidr" = "10.42.10.1/24", "availability_zone" = "ap-northeast-2a" } } } }
  expect_failures = [var.topology]
}
run "reject_too_small" {
  command = plan
  variables { topology = { "vpc_cidr" = "10.42.0.0/16", "availability_zones" = ["ap-northeast-2a", "ap-northeast-2c"], "public_subnets" = { "a" = { "cidr" = "10.42.0.0/24", "availability_zone" = "ap-northeast-2a" } }, "private_subnets" = { "a" = { "cidr" = "10.42.10.0/29", "availability_zone" = "ap-northeast-2a" } } } }
  expect_failures = [var.topology]
}
run "reject_outside_vpc" {
  command = plan
  variables { topology = { "vpc_cidr" = "10.42.0.0/16", "availability_zones" = ["ap-northeast-2a", "ap-northeast-2c"], "public_subnets" = { "a" = { "cidr" = "10.42.0.0/24", "availability_zone" = "ap-northeast-2a" } }, "private_subnets" = { "a" = { "cidr" = "10.43.0.0/24", "availability_zone" = "ap-northeast-2a" } } } }
  expect_failures = [aws_vpc.this]
}
run "reject_duplicate" {
  command = plan
  variables { topology = { "vpc_cidr" = "10.42.0.0/16", "availability_zones" = ["ap-northeast-2a", "ap-northeast-2c"], "public_subnets" = { "a" = { "cidr" = "10.42.0.0/24", "availability_zone" = "ap-northeast-2a" } }, "private_subnets" = { "a" = { "cidr" = "10.42.0.0/24", "availability_zone" = "ap-northeast-2a" } } } }
  expect_failures = [aws_vpc.this]
}
run "reject_overlap" {
  command = plan
  variables { topology = { "vpc_cidr" = "10.42.0.0/16", "availability_zones" = ["ap-northeast-2a", "ap-northeast-2c"], "public_subnets" = { "a" = { "cidr" = "10.42.0.0/24", "availability_zone" = "ap-northeast-2a" } }, "private_subnets" = { "a" = { "cidr" = "10.42.0.0/23", "availability_zone" = "ap-northeast-2a" } } } }
  expect_failures = [aws_vpc.this]
}
run "reject_unknown_az" {
  command = plan
  variables { topology = { "vpc_cidr" = "10.42.0.0/16", "availability_zones" = ["ap-northeast-2a", "ap-northeast-2c"], "public_subnets" = { "a" = { "cidr" = "10.42.0.0/24", "availability_zone" = "ap-northeast-2a" } }, "private_subnets" = { "a" = { "cidr" = "10.42.10.0/24", "availability_zone" = "ap-northeast-2b" } } } }
  expect_failures = [var.topology]
}
run "reject_missing_private" {
  command = plan
  variables { topology = { "vpc_cidr" = "10.42.0.0/16", "availability_zones" = ["ap-northeast-2a", "ap-northeast-2c"], "public_subnets" = { "a" = { "cidr" = "10.42.0.0/24", "availability_zone" = "ap-northeast-2a" } }, "private_subnets" = {} } }
  expect_failures = [var.topology]
}
