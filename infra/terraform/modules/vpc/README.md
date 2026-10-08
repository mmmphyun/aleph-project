# CloudShield VPC 모듈

IPv4 VPC, Public/Private 서브넷, IGW, 계층별 라우팅 테이블과 명시적 연결을 생성한다.
VPC가 자동 생성하는 default SG는 빈 규칙으로 관리한다. 대상 EC2나 서비스 SG는 생성하지 않는다.
Public은 IGW 기본 경로, Private은 VPC local 경로만 사용한다. 두 계층 모두 공인 IP 자동 할당은 꺼져 있다.
NAT, Endpoint, VPN, Peering, Flow Logs 저장 대상은 포함하지 않는다.

| 입력 | 의미 | 기본값 |
| --- | --- | --- |
| `topology.vpc_cidr` | 정규 IPv4 /16~/28 | 필수 |
| `topology.availability_zones` | 허용 AZ 이름 집합 | 필수 |
| `topology.public_subnets` | 이름 → `{cidr, availability_zone}` | 필수, 1개 이상 |
| `topology.private_subnets` | 이름 → `{cidr, availability_zone}` | 필수, 1개 이상 |
| `name` | Name 태그 접두어 | `CloudShield` |
| `environment` | Environment 태그 | `dev` |
| `tags` | 추가 태그 | `{}` |

출력: `vpc_id`, `vpc_cidr`, `public_subnet_ids`, `private_subnet_ids`,
`internet_gateway_id`, `route_table_ids`, `route_table_association_ids`.
서브넷/연결 출력은 입력 이름을 키로 유지한다. 단일 대상 서브넷을 임의 선택하지 않는다.

CIDR 형식·정규화·크기, VPC 포함 관계, 전체 서브넷 중복/겹침, AZ 집합 소속,
Public/Private 최소 개수·합계 200개 상한을 검증한다.
계정의 AZ 가용성/리전, 기존 네트워크 충돌, 예약 주소·quota는 실제 배포 담당자의 수동 확인이 필요하다.

루트 provider는 기존 `hashicorp/aws ~> 5.0`을 상속한다. 운영 HCL은 기존
Terraform `>= 1.6.0` 제약을 유지한다. 동봉한 mock 테스트는 plan 단계 computed 값
주입을 사용하므로 검증한 CLI `1.16.5`를 사용한다. 테스트 기능을 위해 루트 제약은 바꾸지 않는다.

이 디렉터리에서 로컬 검증:

```powershell
terraform fmt -check -recursive
terraform init -backend=false -input=false
terraform validate
terraform test
```

`terraform test`는 mock provider + `command = plan`만 실행한다. 실제 AWS plan/apply가 아니다.
`init`은 provider를 다운로드하지만 AWS 인프라를 검증하지 않는다. `TF_DATA_DIR`은 임시
경로로 지정하고 생성된 `.terraform.lock.hcl`은 로컬 검증용으로만 보관한다. 결합 루트의
공통 lock 파일은 클라우드 A가 관리한다. state/plan/자격증명은 커밋하지 않는다.

전체 제안 토폴로지, 결합 예시, 검증 결과 및 Flow Logs 미설정 조건:
[네트워크 설계 명세](../../../../docs/roles/network/vpc-quarantine-sg-spec.md).
