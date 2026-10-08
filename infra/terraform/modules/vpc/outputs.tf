output "vpc_id" {
  description = "EC2 및 두 SG가 공유해야 하는 VPC ID"
  value       = aws_vpc.this.id
}

output "vpc_cidr" {
  description = "선언한 IPv4 VPC CIDR"
  value       = aws_vpc.this.cidr_block
}

output "public_subnet_ids" {
  description = "입력 이름별 Public 서브넷 ID; 대상 선택은 루트에서 명시"
  value       = { for k, s in aws_subnet.public : k => s.id }
}

output "private_subnet_ids" {
  description = "입력 이름별 Private 서브넷 ID"
  value       = { for k, s in aws_subnet.private : k => s.id }
}

output "internet_gateway_id" {
  description = "Public 기본 경로의 IGW ID"
  value       = aws_internet_gateway.this.id
}

output "route_table_ids" {
  description = "Public/Private 라우팅 테이블 ID"
  value       = { public = aws_route_table.public.id, private = aws_route_table.private.id }
}

output "route_table_association_ids" {
  description = "계층 및 서브넷 이름별 명시적 라우팅 연결 ID"
  value = {
    public  = { for k, a in aws_route_table_association.public : k => a.id }
    private = { for k, a in aws_route_table_association.private : k => a.id }
  }
}
