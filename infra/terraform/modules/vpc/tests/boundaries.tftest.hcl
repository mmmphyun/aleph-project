mock_provider "aws" {
  override_during = plan
}
variables {
  topology = { "vpc_cidr" = "10.42.0.0/16", "availability_zones" = ["ap-northeast-2a", "ap-northeast-2c"], "public_subnets" = { "a" = { "cidr" = "10.42.0.0/24", "availability_zone" = "ap-northeast-2a" } }, "private_subnets" = { "a" = { "cidr" = "10.42.10.0/24", "availability_zone" = "ap-northeast-2a" } } }
}

run "reject_invalid_vpc" {
  command = plan
  variables { topology = { "vpc_cidr" = "invalid", "availability_zones" = ["ap-northeast-2a", "ap-northeast-2c"], "public_subnets" = { "a" = { "cidr" = "10.42.0.0/24", "availability_zone" = "ap-northeast-2a" } }, "private_subnets" = { "a" = { "cidr" = "10.42.10.0/24", "availability_zone" = "ap-northeast-2a" } } } }
  expect_failures = [var.topology]
}

run "reject_vpc_host_bits" {
  command = plan
  variables { topology = { "vpc_cidr" = "10.42.1.0/16", "availability_zones" = ["ap-northeast-2a", "ap-northeast-2c"], "public_subnets" = { "a" = { "cidr" = "10.42.0.0/24", "availability_zone" = "ap-northeast-2a" } }, "private_subnets" = { "a" = { "cidr" = "10.42.10.0/24", "availability_zone" = "ap-northeast-2a" } } } }
  expect_failures = [var.topology]
}

run "adjacent_subnets" {
  command = plan
  variables { topology = { "vpc_cidr" = "10.42.0.0/16", "availability_zones" = ["ap-northeast-2a", "ap-northeast-2c"], "public_subnets" = { "a" = { "cidr" = "10.42.0.0/24", "availability_zone" = "ap-northeast-2a" } }, "private_subnets" = { "a" = { "cidr" = "10.42.1.0/24", "availability_zone" = "ap-northeast-2a" } } } }
}

run "two_az_topology" {
  command = plan
  variables { topology = { "vpc_cidr" = "10.42.0.0/16", "availability_zones" = ["ap-northeast-2a", "ap-northeast-2c"], "public_subnets" = { "a" = { "cidr" = "10.42.0.0/24", "availability_zone" = "ap-northeast-2a" }, "c" = { "cidr" = "10.42.2.0/24", "availability_zone" = "ap-northeast-2c" } }, "private_subnets" = { "a" = { "cidr" = "10.42.10.0/24", "availability_zone" = "ap-northeast-2a" }, "c" = { "cidr" = "10.42.12.0/24", "availability_zone" = "ap-northeast-2c" } } } }
  assert {
    condition     = length(output.public_subnet_ids) == 2 && length(output.private_subnet_ids) == 2
    error_message = "Every named subnet must have an output"
  }
}
