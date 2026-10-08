# CloudShield 기본 / 격리 SG 모듈

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
기본 개방 포트나 CIDR은 없다. IPv4 정규 CIDR(`/0` 금지), `tcp`/`udp`, 정수 포트
1~65535, 오름차순 포트 범위, ASCII 설명, 중복 거부 및 방향별 최대 60개를 검증한다.
IPv6·ICMP·전체 프로토콜·SG 참조는 지원하지 않는다. 넓은 CIDR 여러 개로 전체 인터넷을
덮는 집합까지 계산하지 않으므로 승인된 최소 범위인지 리뷰가 필요하다.

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
