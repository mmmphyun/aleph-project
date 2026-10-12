# CloudShield 기본 / 격리 SG 모듈

P3-1B의 선택형 외부 송신 정책은 `policies/external_bootstrap/main.tf`에 있다.
기존 SG 모듈의 기본값이나 빈 egress 동작을 변경하지 않는다.

| 정책 키 | 목적 | 프로토콜 / from_port / to_port | 목적지 |
| --- | --- | --- | --- |
| `package_http` | HTTP APT 저장소의 패키지 설치 | tcp / 80 / 80 | `0.0.0.0/0` |
| `agent_logs_https` | HTTPS Agent 다운로드 및 CloudWatch Logs 전송 | tcp / 443 / 443 | `0.0.0.0/0` |

정책 원본 HCL은 다음과 같다. 아래 값은 설명용이며 테스트는 원본 정책 모듈의 출력을 소비한다.

```hcl
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
```

P3-2 루트 소유자가 명시적으로 선택할 예시다. 이번 작업에서 루트 파일은 수정하지 않는다.
정책 모듈은 AWS 리소스·입력 없이 `egress` map만 출력하므로 SG 자신의 출력을 입력에
연결하는 자기참조가 없다. 기존 `quarantine_traffic.ingress`는 그대로 전달한다.

```hcl
module "baseline_external_policy" {
  source = "./modules/quarantine_sg/policies/external_bootstrap"
}

module "quarantine_sg" {
  source      = "./modules/quarantine_sg"
  vpc_id      = module.vpc.vpc_id
  environment = var.environment
  traffic = {
    ingress = var.quarantine_traffic.ingress
    egress  = module.baseline_external_policy.egress
  }
}
```

일반 `traffic.egress = {}`는 계속 빈 규칙이며 TCP/UDP·포트 지원을 제한하지 않는다.
정책을 기존 map에 자동 병합하지 않는다. P3-2는 현재 루트의 `all-vpc`
(`10.42.0.0/16`, TCP 1~65535)를 교체·정리해야 한다. 별도 병합이 필요하면 키 충돌을
먼저 거부하고 최종 map의 규칙 중복·60개 상한을 검증해야 하며 조용한 `merge` 덮어쓰기는 피한다.

`0.0.0.0/0`은 목적지를 전체 IPv4로 허용한다. 서비스 포트만 제한하며 목적지까지
최소화한 정책이 아니다. 80~443 연속 범위, UDP 53, IPv6, ICMP, SG 참조 규칙은 추가하지 않는다.
ingress `/0` 금지와 격리 SG의 빈 양방향 계약은 유지한다.

`init_target_server.sh`는 `apt-get update/install`을 호출하지만 저장소 URL은 정하지 않는다.
실제 HTTP/HTTPS 저장소와 프록시 사용 여부는 AMI 담당자와 확인한다.
EC2 `user_data.sh.tftpl`은
`https://amazoncloudwatch-agent.s3.amazonaws.com/ubuntu/amd64/latest/amazon-cloudwatch-agent.deb`
에서 다운로드한다. 마지막 `http://127.0.0.1/health`는 로컬 헬스체크이며 외부 TCP 80의 근거가 아니다.
Agent 설정은 auth.log와 nginx/access.log를 CloudWatch Logs로 전송한다.

실제 통신에는 DNS, 라우팅, 공인 IP/IGW 또는 NAT, NACL/OS 방화벽, TLS, IAM instance profile과
로그 그룹/리전 구성이 필요하다. 현재 VPC는 DNS를 활성화하지만 public subnet의 자동 공인 IP가
꺼져 있고 private route table에 NAT 경로가 없다. 외부 인터넷 성공을 보장하지 않는다.
[AmazonProvidedDNS는 SG 필터 대상이 아니다](https://docs.aws.amazon.com/vpc/latest/userguide/security-group-rules.html).
사용자 DNS 서버를 쓰면 별도 DNS 정책 협의가 필요하다. CloudWatch Logs Interface Endpoint를
사용해도 패키지 저장소와 S3 Agent 다운로드 경로는 별도로 확인한다.
[Agent 사전 조건](https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/prerequisites.html)과
[Logs Endpoint 조건](https://docs.aws.amazon.com/AmazonCloudWatch/latest/logs/cloudwatch-logs-and-interface-VPC.html)을 따른다.
EC2의 수집 IAM 정책은 `CreateLogStream`, `PutLogEvents`, `DescribeLogStreams`를 포함한다.

`tests/external_bootstrap.tftest.hcl`은 정책 HCL 로딩 후 같은 출력을 실제 baseline SG mock에
전달한다. 기존 39개와 신규 3개로 SG 42개, VPC 14개를 pytest 연계에서 확인한다.
로컬 결과·대기 조건·미수행한 AWS 배포/실측은
[P3-1B 검증 기록](../../../../docs/roles/network/2026-10-12-p3-1b-baseline-egress-policy.md)에 기록한다.

입력 VPC에 `baseline`(명시한 테스트 트래픽)과 `quarantine`(허용 규칙 없음)을 만든다.
SG 부착·교체·복구는 수행하지 않는다. AWS 생성 기본 allow-all egress는 provider가 제거하며,
격리 SG는 `ingress = []`, `egress = []`를 명시해 빈 집합을 관리한다.

| 입력 | 의미 | 기본값 |
| --- | --- | --- |
| `vpc_id` | 대상 EC2와 같아야 하는 VPC ID | 필수 |
| `traffic.ingress` | 이름 → `{cidr, protocol, from_port, to_port, description}` | 필수 |
| `traffic.egress` | 같은 구조의 목적지 규칙 map | 필수 |
| `names.baseline` | 기본 SG 이름 | `CloudShield-Target-SG` |
| `names.quarantine` | 격리 SG 이름 | `CloudShield-Quarantine-SG` |
| `environment`, `tags` | 환경 및 추가 태그 | `dev`, `{}` |

`traffic = { ingress = {}, egress = {} }`는 기본 SG도 빈 규칙으로 관리한다.
기본 개방 포트나 CIDR은 없다. IPv4 정규 CIDR(ingress `/0` 금지, baseline egress `0.0.0.0/0` 허용), `tcp`/`udp`, 정수 포트
1~65535, 오름차순 포트 범위, ASCII 설명, 중복 거부 및 방향별 최대 60개를 검증한다.
CIDR은 네트워크 주소와 prefix 모두 정규 표기여야 하며 `/00`, `/032` 같은 선행 0은 거부한다.
IPv6·ICMP·전체 프로토콜·SG 참조는 지원하지 않는다. 넓은 CIDR 여러 개로 전체 인터넷을
덮는 집합까지 계산하지 않으므로 승인된 최소 범위인지 리뷰가 필요하다.

P3-1A는 baseline `traffic.egress`의 입력 허용 범위만 변경한다. `/0`을 입력해도
격리 SG의 `ingress = []`, `egress = []`는 유지한다. 외부 egress 기본 규칙을 추가하지
않으며 자동 개방이나 실제 배포를 의미하지 않는다. 서비스별 목적지·프로토콜·포트 정책은
P3-1B에서 정의하고, 루트 egress 결합·프로비저닝은 P3-2의 클라우드 A 범위다.
이번 로컬 검증 결과와 미수행한 AWS 배포·실측은
[P3-1A 검증 기록](../../../../docs/roles/network/2026-10-12-p3-1a-egress-cidr-validation.md)에 기록한다.

출력은 `baseline_sg_id`, `quarantine_sg_id`, `quarantine_sg_arn`,
`quarantine_sg_name`, `vpc_id`이다. ARN은 Lambda IAM 입력용이고 SG ID와 다르다.
기본 격리 이름은 엔진의 VPC별 자동 탐색 계약과 일치한다. 이름을 바꾸면 소비자도 협의해야 한다.

규칙 전체를 inline 속성 목록으로 소유하여 빈 입력 전환과 드리프트 정정을 관리한다.
같은 SG에 독립 rule 리소스나 다른 Terraform 모듈을 혼용하지 않는다.
SG/이름/VPC 교체는 연결된 리소스가 있으면 삭제 실패할 수 있으므로 실제 배포 때 변경 계획 검토가 필요하다.

검증 환경은 Terraform `1.16.5`, AWS provider `5.100.0`이다. 기존 provider `~> 5.0`과
운영 HCL의 Terraform `>= 1.6.0`을 유지한다. 동봉한 plan 시점 mock 테스트는 검증한 CLI를 사용한다.

```powershell
terraform fmt -check -recursive
terraform init -backend=false -input=false
terraform validate
terraform test
```

`TF_DATA_DIR`은 임시 경로로 지정한다. 테스트는 mock plan만 실행한다.
생성된 module lock 파일은 로컬에 보관하고 공통 루트 lock을 대신하지 않는다.
빈 SG는 기존 tracked TCP 연결의 즉시 종료나 완전 격리 보장이 아니다.
관리·복구와 Private 외부 통신 조건, 사용 예시는
[네트워크 설계 명세](../../../../docs/roles/network/vpc-quarantine-sg-spec.md)를 참고한다.
