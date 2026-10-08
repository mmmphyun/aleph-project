terraform {
  required_version = ">= 1.6.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

locals {
  tags    = merge(var.tags, { Environment = var.environment })
  subnets = concat(values(var.topology.public_subnets), values(var.topology.private_subnets))
  # Terraform 1.6에는 cidrcontains가 없으므로 IPv4 양 끝을 정수로 비교한다.
  # 잘못된 CIDR은 변수 검증에서 거부하며 try는 선행 식 평가의 부수 오류만 방지한다.
  vpc_bounds = [for host in [0, -1] : try(sum([for i, octet in split(".", cidrhost(var.topology.vpc_cidr, host)) : tonumber(octet) * pow(256, 3 - i)]), 0)]
  subnet_bounds = [for s in local.subnets : [
    for host in [0, -1] : try(sum([for i, octet in split(".", cidrhost(s.cidr, host)) : tonumber(octet) * pow(256, 3 - i)]), 0)
  ]]
}

resource "aws_vpc" "this" {
  cidr_block           = var.topology.vpc_cidr
  enable_dns_support   = true
  enable_dns_hostnames = true
  tags                 = merge(local.tags, { Name = "${var.name}-${var.environment}-VPC" })

  lifecycle {
    precondition {
      condition     = alltrue([for b in local.subnet_bounds : b[0] >= local.vpc_bounds[0] && b[1] <= local.vpc_bounds[1]])
      error_message = "모든 서브넷 CIDR은 VPC CIDR 범위 안에 있어야 합니다."
    }
    precondition {
      condition = alltrue(flatten([for i, a in local.subnet_bounds : [
        for j, b in local.subnet_bounds : i >= j || a[1] < b[0] || b[1] < a[0]
      ]]))
      error_message = "Public/Private 전체에서 서브넷 CIDR 중복 및 겹침을 허용하지 않습니다."
    }
  }
}

# VPC 생성 시 생기는 default SG도 빈 규칙으로 관리하여 실수로 부착될 때 개방되지 않게 한다.
# 이 리소스는 대상 EC2 연결이나 격리 SG를 대신하지 않는다.
resource "aws_default_security_group" "this" {
  vpc_id  = aws_vpc.this.id
  ingress = []
  egress  = []
  tags    = merge(local.tags, { Name = "${var.name}-${var.environment}-Unused-Default-SG" })
}

resource "aws_internet_gateway" "this" {
  vpc_id = aws_vpc.this.id
  tags   = merge(local.tags, { Name = "${var.name}-${var.environment}-IGW" })
}

resource "aws_subnet" "public" {
  for_each                = var.topology.public_subnets
  vpc_id                  = aws_vpc.this.id
  cidr_block              = each.value.cidr
  availability_zone       = each.value.availability_zone
  map_public_ip_on_launch = false
  tags                    = merge(local.tags, { Name = "${var.name}-${var.environment}-Public-${each.key}" })
}

resource "aws_subnet" "private" {
  for_each                = var.topology.private_subnets
  vpc_id                  = aws_vpc.this.id
  cidr_block              = each.value.cidr
  availability_zone       = each.value.availability_zone
  map_public_ip_on_launch = false
  tags                    = merge(local.tags, { Name = "${var.name}-${var.environment}-Private-${each.key}" })
}

resource "aws_route_table" "public" {
  vpc_id = aws_vpc.this.id
  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.this.id
  }
  tags = merge(local.tags, { Name = "${var.name}-${var.environment}-Public-RT" })
}

# Private은 VPC local 경로만 유지한다. 빈 목록으로 선언해 IGW/NAT 경로 혼입도 감지한다.
resource "aws_route_table" "private" {
  vpc_id = aws_vpc.this.id
  route  = []
  tags   = merge(local.tags, { Name = "${var.name}-${var.environment}-Private-RT" })
}

resource "aws_route_table_association" "public" {
  for_each       = aws_subnet.public
  subnet_id      = each.value.id
  route_table_id = aws_route_table.public.id
}

resource "aws_route_table_association" "private" {
  for_each       = aws_subnet.private
  subnet_id      = each.value.id
  route_table_id = aws_route_table.private.id
}
