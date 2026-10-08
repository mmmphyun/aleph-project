# 타깃 EC2 및 CloudWatch Agent 자동 배포

클라우드 B 소유 모듈. Ubuntu amd64 EC2, 암호화 gp3, IMDSv2, EC2 로그 쓰기 역할,
두 로그 그룹(기본 7일 보존), SSH/Nginx 구독 및 기존 Lambda 호출 권한을 생성한다.
네트워크와 Lambda 자체는 입력받는다. 루트 오케스트레이션은 클라우드 A가 결합한다.

## 사용

`examples/standalone/`에서 `terraform init` 후 AMI ID, 서브넷 ID, 보안 그룹 목록,
동일 계정/리전 Lambda ARN을 tfvars 또는 `-var`로 전달하고 `terraform plan`을 확인한다.
실제 배포는 승인된 테스트 계정/VPC에서만 실행한다. AWS 키를 파일에 넣지 않는다.

AMI는 Ubuntu 22.04/24.04 LTS amd64여야 하며 지원 타입은 t3.micro/small/medium이다.
기본적으로 공인 IP를 부여하지 않는다. 서브넷은 APT 저장소, Agent 배포 S3,
CloudWatch Logs에 접근할 수 있어야 한다(NAT 또는 적절한 엔드포인트/경로).
네트워크 담당 SG가 허용된 테스트 공격자에 대해서만 TCP 22/80을 열어야 한다.

고정 로그 그룹명은 기존 수집 계약을 재사용하므로 계정/리전당 한 번만 배포한다.
기존 그룹이 있으면 해당 Terraform 주소로 import한 뒤 plan으로 보존 기간을 확인한다.
기존 구독은 그룹당 구독 한도와 이름 충돌을 배포 전에 확인한다.

## 동작과 영향

기존 초기화 스크립트와 Nginx/CW 설정을 gzip으로 압축하여 user-data에 포함한다.
외부 Git 저장소에서 실행 코드를 내려받지 않는다. user-data ASCII 길이를 16KiB 이하로 검증한다.
로그 그룹/구독/호출 권한/IAM 정책 생성 후 EC2를 생성하여 첫 로그 전달 경합을 줄인다.
Agent 설치는 AWS 공식 Ubuntu amd64 패키지의 latest 채널을 사용하며 외부 다운로드가 필요하다.
패키지 버전 고정과 서명 검증은 운영 배포 전에 별도 공급망 정책으로 확정해야 한다.

설정 변경 시 EC2가 교체되어 로컬 디스크가 유실된다. Terraform apply 성공은
cloud-init 완료나 실제 로그 전달 성공을 뜻하지 않는다. 배포 후 `cloud-init status --wait`,
`systemctl is-active amazon-cloudwatch-agent`, `/health`, 두 CloudWatch 로그 스트림과
Lambda 실행을 확인해야 한다. bootstrap 실패는 cloud-init-output.log에 남고 비정상 종료한다.

Nginx /admin은 인증 실패 트래픽을 위한 테스트 경로다. 새 인증 해시는 무작위 비밀번호로
생성하고 평문을 저장하지 않는다. 기존 정상 해시는 재실행 시 유지한다.
2초 flush 설정은 전체 수집/대응 시간의 상한을 보장하지 않는다.

## 검증

Terraform 1.7 이상 및 AWS provider 5.x 필요:

```powershell
terraform init -backend=false
terraform fmt -check -recursive
terraform validate
terraform test
```

mock provider 테스트는 기본 보안 옵션/로그 구독/최소 IAM, 다른 계정·리전,
빈 SG, 무한 보존 및 ARM 타입을 검증하며 AWS 리소스를 생성하지 않는다.
저장소 루트에서는 `powershell .\scripts\check.ps1`로 Python 전체 게이트를 실행한다.
공통 게이트는 Terraform 검사를 포함하지 않으므로 위 명령도 별도로 실행한다.

참고: [AWS Agent 설정 적용](https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/create-cloudwatch-agent-configuration-file.html),
[Terraform mock provider](https://developer.hashicorp.com/terraform/language/tests/mocking).
