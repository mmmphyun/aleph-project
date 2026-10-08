terraform {
  required_version = ">= 1.6.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

# 전체 규칙 집합을 모듈 하나가 소유한다. 빈 목록 전환 시에도 기존 규칙을 제거하기 위해
# attribute-as-blocks를 명시하며 같은 SG에 독립 rule 리소스를 혼용하면 안 된다.
# provider 5.x는 생성 시 AWS 기본 allow-all egress를 제거한다. 실제 효력은 배포 후 별도 검증한다.
resource "aws_security_group" "baseline" {
  name        = var.names.baseline
  description = "Explicitly approved CloudShield test traffic"
  vpc_id      = var.vpc_id
  ingress = [for r in values(var.traffic.ingress) : {
    description      = r.description
    from_port        = r.from_port
    to_port          = r.to_port
    protocol         = r.protocol
    cidr_blocks      = [r.cidr]
    ipv6_cidr_blocks = []
    prefix_list_ids  = []
    security_groups  = []
    self             = false
  }]
  egress = [for r in values(var.traffic.egress) : {
    description      = r.description
    from_port        = r.from_port
    to_port          = r.to_port
    protocol         = r.protocol
    cidr_blocks      = [r.cidr]
    ipv6_cidr_blocks = []
    prefix_list_ids  = []
    security_groups  = []
    self             = false
  }]
  tags = merge(var.tags, { Name = var.names.baseline, Environment = var.environment })
}

# 생략과 빈 집합은 다르다. []를 고정해 허용 규칙 잔존을 방지한다.
# SG를 만드는 것만으로 EC2에 적용되지 않으며 기존 tracked TCP 연결 종료도 보장하지 않는다.
resource "aws_security_group" "quarantine" {
  name        = var.names.quarantine
  description = "CloudShield quarantine with no ingress or egress permissions"
  vpc_id      = var.vpc_id
  ingress     = []
  egress      = []
  tags        = merge(var.tags, { Name = var.names.quarantine, Environment = var.environment })
}
