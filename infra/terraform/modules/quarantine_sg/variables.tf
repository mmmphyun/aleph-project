variable "vpc_id" {
  description = "대상 EC2와 일치해야 하는 VPC ID; module.vpc.vpc_id로 연결"
  type        = string
  nullable    = false
  validation {
    condition     = can(regex("^vpc-([0-9a-f]{8}|[0-9a-f]{17})$", var.vpc_id))
    error_message = "vpc_id는 vpc- 뒤에 8자리 또는 17자리 16진수가 필요합니다."
  }
}

variable "environment" {
  description = "환경 식별 태그"
  type        = string
  default     = "dev"
}

variable "tags" {
  description = "추가 태그; Name/Environment는 모듈 식별값 우선"
  type        = map(string)
  default     = {}
}

variable "names" {
  description = "기본/격리 SG 이름; 격리 기본 이름은 엔진 자동 탐색 계약과 일치"
  type        = object({ baseline = string, quarantine = string })
  default = {
    baseline   = "CloudShield-Target-SG"
    quarantine = "CloudShield-Quarantine-SG"
  }
  nullable = false
  validation {
    condition = try(var.names.baseline != var.names.quarantine && alltrue([
      for name in [var.names.baseline, var.names.quarantine] :
      can(regex("^[A-Za-z][A-Za-z0-9-]{0,127}$", name)) && !startswith(lower(name), "sg-")
    ]), false)
    error_message = "서로 다른 영문 시작 1~128자 이름이 필요하며 sg- 접두어는 금지합니다."
  }
}

# 승인된 출발지/목적지와 서비스 포트를 루트에서 입력한다. HTTP/SSH도 기본 개방하지 않는다.
# TCP/UDP IPv4만 지원하며 ICMP, IPv6, SG 참조 및 전체 프로토콜은 후속 협업 범위다.
variable "traffic" {
  description = "기본 SG의 명시적 ingress/egress 허용 목록; 빈 map은 해당 방향 허용 없음"
  type = object({
    ingress = map(object({ cidr = string, protocol = string, from_port = number, to_port = number, description = string }))
    egress  = map(object({ cidr = string, protocol = string, from_port = number, to_port = number, description = string }))
  })
  nullable = false
  validation {
    condition = try(alltrue([
      for r in concat(values(var.traffic.ingress), values(var.traffic.egress)) :
      cidrnetmask(r.cidr) != "" && r.cidr == "${cidrhost(r.cidr, 0)}/${split("/", r.cidr)[1]}" &&
      tonumber(split("/", r.cidr)[1]) > 0 &&
      contains(["tcp", "udp"], r.protocol) &&
      r.from_port >= 1 && r.to_port <= 65535 && r.from_port <= r.to_port &&
      floor(r.from_port) == r.from_port && floor(r.to_port) == r.to_port &&
      can(regex("^[A-Za-z0-9 ._:/()-]{1,255}$", r.description))
    ]), false)
    error_message = "규칙은 정규 IPv4 CIDR(/0 금지), tcp/udp, 정수 포트 1~65535의 유효 범위 및 ASCII 설명(1~255자)이 필요합니다."
  }
  validation {
    condition = try(alltrue([for rules in [var.traffic.ingress, var.traffic.egress] :
      length(rules) <= 60 && length(distinct([for r in values(rules) : jsonencode([r.cidr, r.protocol, r.from_port, r.to_port])])) == length(rules)
    ]), false)
    error_message = "방향별 최대 60개 규칙이며 동일 CIDR/프로토콜/포트 조합은 중복할 수 없습니다. 실제 계정 quota는 배포 전 확인합니다."
  }
}
