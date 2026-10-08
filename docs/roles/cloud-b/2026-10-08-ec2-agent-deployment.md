# 타깃 EC2 및 CW Agent 자동 배포 검증

- 작업 이슈: #160
- 직무: 클라우드 B
- 작업 카드: https://app.notion.com/p/A-d5f04d37c22582ad9e7f81acd36191d0?p=3ea04d37c225814482ccc682fb579e84&pm=c
- 관련 카드: https://app.notion.com/p/A-d5f04d37c22582ad9e7f81acd36191d0?p=3e904d37c225815b95d4def93741b2a0&pm=c
- Notion 커넥터 조회는 404로 실패하여 사용자 제공 제목과 범위를 기준으로 구현했다. 카드 속성/상태는 직접 변경하지 않았다.

## 수정 사항

`infra/terraform/modules/ec2/`에 Ubuntu amd64 타깃, 암호화 EBS, IMDSv2,
수집 전용 IAM 역할/프로파일, 기존 설정에서 읽은 로그 그룹과 유한 보존 기간을 구현했다.
SSH 및 Nginx 필터는 기존 수집기 명세와 계약 테스트로 비교한다. 동일 계정/리전 Lambda에
로그 그룹 ARN과 source_account로 제한한 호출 권한을 부여하고 구독 생성 이후 EC2를 시작한다.

user-data는 기존 초기화 스크립트와 Nginx/Agent 설정을 gzip으로 포함한다.
16KiB 제한을 검사하고 AWS 공식 Agent 패키지를 설치·시작한다. 설정 변경 시 EC2를 교체한다.
SSH 백업은 서비스 재시작 성공 후 제거하고 중간 장애도 복원한다. Nginx 실패 시 설정/기존
index/인증 파일을 복원한다. 무작위 비밀번호의 SHA-512 해시만 저장하며 난수/해시 생성 실패와
잘못된 해시를 거부한다. UFW·권한·헬스체크 실패를 성공으로 처리하지 않는다.

## 검증 결과

- Windows / Python 3.12.14 / Terraform 1.9.8 / AWS provider 5.100.0
- `powershell .\scripts\check.ps1`: 종료 코드 0, **896 passed, 2 skipped**, 기존 socket 차단 테스트 warning 1건
- `ruff check .`, `ruff format --check .`: 통과
- 실제 초기화/배포 템플릿 기반 타깃 테스트: **19 passed**
- Terraform 모듈 및 standalone 예제 `validate`: 통과
- Terraform `fmt -check -recursive`: 통과
- `terraform test`: **6 passed**, mock provider로 실행, 실제 AWS 호출/생성 없음
- `bash -n init_target_server.sh`, `git diff --check`: 통과

단위 테스트는 복제한 셸 구현 대신 실제 파일의 구간을 읽어 실행한다.
rsyslog/SSH 문법/SSH 재시작, Nginx 문법/재시작, UFW, 난수/해시 생성/잘못된 해시,
Agent 다운로드/설치/시작과 헬스체크 장애 및 재실행 멱등성을 검증했다.
외부 시스템 명령은 mock 처리하므로 실제 Ubuntu 서비스 동작이나 AWS 로그 전달 성공을
증명하는 테스트는 아니다. 실제 배포 후 검증 명령은 모듈 README에 기록했다.

## 계약·연계 및 배포 영향

`src/contracts/`, 공통 루트 Terraform, 네트워크 SG, Lambda 런타임, CI는 변경하지 않았다.
루트 연결은 클라우드 A 소유이므로 입력을 받는 standalone 예제를 제공했다.
AMI/서브넷/SG/Lambda ARN은 배포자가 확정해야 한다. 계정/리전당 고정 로그 그룹은 1세트만
관리하며 기존 그룹은 import가 필요하다. 외부 패키지/로그 API 접근 경로와 SG 22/80 정책은
네트워크 담당과 확인한다. 실제 apply 시 EC2/EBS/IAM/로그 그룹/구독 및 Lambda 정책이 변경된다.
이번 작업에서 실제 apply는 실행하지 않았다. AWS 키/토큰은 코드나 user-data에 넣지 않았다.
