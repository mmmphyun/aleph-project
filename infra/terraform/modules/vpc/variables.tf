variable "name" {
  description = "VPC 및 하위 리소스 Name 태그 접두어"
  type        = string
  default     = "CloudShield"
  validation {
    condition     = can(regex("^[A-Za-z][A-Za-z0-9-]{0,63}$", var.name))
    error_message = "name은 영문자로 시작하는 1~64자 영문/숫자/하이픈이어야 합니다."
  }
}

variable "environment" {
  description = "환경 식별 태그; 실제 배포 환경은 루트 소유자가 확정"
  type        = string
  default     = "dev"
}

variable "tags" {
  description = "추가 태그; Name/Environment는 모듈 식별값을 우선 적용"
  type        = map(string)
  default     = {}
}

# CIDR와 AZ를 한 객체로 검증하여 Terraform 1.6에서도 교차 변수 검증 없이 동작한다.
# AZ의 계정 내 실제 가용 여부는 AWS 조회 없이 확인할 수 없으므로 배포 전 별도 검증한다.
variable "topology" {
  description = "승인할 IPv4 VPC, 허용 AZ 집합과 이름별 Public/Private 서브넷; 기본 배포값 없음"
  type = object({
    vpc_cidr           = string
    availability_zones = set(string)
    public_subnets     = map(object({ cidr = string, availability_zone = string }))
    private_subnets    = map(object({ cidr = string, availability_zone = string }))
  })
  nullable = false

  validation {
    condition = try(alltrue([
      for cidr in concat([var.topology.vpc_cidr], [for s in values(var.topology.public_subnets) : s.cidr], [for s in values(var.topology.private_subnets) : s.cidr]) :
      cidrnetmask(cidr) != "" && cidr == "${cidrhost(cidr, 0)}/${split("/", cidr)[1]}" &&
      tonumber(split("/", cidr)[1]) >= 16 && tonumber(split("/", cidr)[1]) <= 28
    ]), false)
    error_message = "VPC/서브넷은 네트워크 주소로 정규화된 IPv4 CIDR /16~/28이어야 합니다."
  }
  validation {
    condition = try(
      length(var.topology.public_subnets) > 0 && length(var.topology.private_subnets) > 0 &&
      length(var.topology.public_subnets) + length(var.topology.private_subnets) <= 200 &&
      length(var.topology.availability_zones) > 0 &&
      alltrue([for az in var.topology.availability_zones : can(regex("^[a-z]{2}(-[a-z]+)+-[0-9][a-z]$", az))]) &&
      alltrue([for s in concat(values(var.topology.public_subnets), values(var.topology.private_subnets)) : contains(var.topology.availability_zones, s.availability_zone)]), false
    )
    error_message = "Public/Private은 각각 최소 1개, 합계 최대 200개이며 모든 서브넷 AZ는 명시한 AZ 집합에 속해야 합니다."
  }
}
