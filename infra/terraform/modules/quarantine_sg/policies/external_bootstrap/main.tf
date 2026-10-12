terraform {
  required_version = ">= 1.6.0"
}

# 부트스트랩과 로그 전송에 필요한 서비스 포트만 명시적 선택으로 전달한다.
# 목적지는 전체 IPv4이므로 목적지 최소화 정책은 아니다. AWS 리소스나 SG 입력을
# 참조하지 않는 순수 값 모듈로 만들어 호출 SG의 자기참조·자동 개방을 방지한다.
# 기존 egress와 자동 병합하지 않는다. 추가 결합은 호출자가 키 충돌을 먼저 거부하고
# 최종 map의 중복·방향별 60개 상한을 SG 모듈 검증으로 확인해야 한다.
locals {
  egress = {
    package_http = {
      cidr        = "0.0.0.0/0"
      protocol    = "tcp"
      from_port   = 80
      to_port     = 80
      description = "HTTP package repositories"
    }
    agent_logs_https = {
      cidr        = "0.0.0.0/0"
      protocol    = "tcp"
      from_port   = 443
      to_port     = 443
      description = "HTTPS agent download and CloudWatch Logs"
    }
  }
}

output "egress" {
  description = "traffic.egress에 명시적으로 입력할 TCP 80/443 IPv4 외부 송신 정책; 자동 부착 없음"
  value       = local.egress
}
