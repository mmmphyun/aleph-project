# P3-1A baseline egress CIDR 검증 완화

- 기준일: 2026-10-12 KST
- Notion Task: https://notion.so/3f704d37c225804b90c5db0a14eea47b
- Issue: https://github.com/mmmphyun/aleph-project/issues/165
- 기준 main: `cda6697`; 브랜치: `fix/network-quarantine-sg-egress-cidr`
- `.agent-role=network` 확인 및 사전 RFC 브리핑 후 사용자 “진행해” 승인
- 수정 범위: `infra/terraform/modules/quarantine_sg/**`, `tests/unit/test_network.py`, `docs/roles/network/**`

## 방향별 입력 정책과 계약

baseline SG는 정상 운영 트래픽 입력을 소비하고 격리 SG는 허용 규칙 없이 유지한다.
공통 CIDR/프로토콜/포트/설명 검증에서 `/0` 금지 조건을 분리해 ingress에만 적용했다.
baseline `traffic.egress`는 정규 IPv4 `0.0.0.0/0`을 허용한다. ingress `/0`은 계속 거부한다.
`cidrnetmask`와 `cidrhost(..., 0)` 비교로 CIDR 문법·IPv4·네트워크 주소 정규화를 유지한다.
TCP/UDP, 정수 포트 1~65535, 포트 순서, ASCII 설명 1~255자, 중복 거부와 방향별 60개 상한도 유지한다.

`main.tf` 및 `outputs.tf`는 변경하지 않았다. baseline 규칙은 입력된 map만 사용하며,
격리 SG의 `ingress = []`, `egress = []`는 고정이다. 대응 엔진의
`validate_quarantine_security_group`이 `IpPermissions`와 `IpPermissionsEgress` 모두 빈 목록을
요구하는 계약을 읽기 전용 확인했다. 빈 baseline egress는 계속 빈 규칙이다.
외부 egress 기본 규칙을 추가하지 않으며 입력 허용이 자동 개방이나 실제 배포를 의미하지 않는다.
서비스별 목적지·프로토콜·포트 정책은 P3-1B, 루트 egress 결합·프로비저닝은
P3-2의 클라우드 A 범위다. IPv6·ICMP·전체 프로토콜·SG 참조 지원은 추가하지 않았다.

## 기존 자산과 회귀 테스트

PR 154의 설계·inline SG 규칙 소유권·출력 계약과 PR 163의 루트 연결 및 CI 검증 환경을 재사용한다.
운영 HCL의 Terraform `>= 1.6.0`, AWS provider `~> 5.0`과 기존 lock 버전 `5.100.0`을 유지한다.
검증 CLI는 기존 Terraform `1.16.5`, Trivy `0.75.0`을 재사용한다.
노션 티켓의 `modules/network/quarantine_sg` 경로는 오기로 확인했고 실제 `modules/quarantine_sg`를 사용했다.

기존 `reject_world_egress`를 허용 및 리소스 결과 검증으로 교체했다. ingress `/0` 거부 검증은 유지한다.
SG mock plan은 기존 17개에 egress 전용 18개를 더해 35개다. pytest 연계 기대 개수도 35로 갱신한다.
잘못된 CIDR·prefix·IPv6·host bits·비정규 `/0`, 프로토콜·포트·설명·중복·규칙 상한을 실제 HCL로 검증한다.
60개 UDP `/0` 허용과 61개 거부, 빈 egress 및 격리 SG의 빈 양방향 규칙을 확인한다.
테스트 실패를 문자열 존재 검사나 skip으로 대체하지 않는다.

## 사전 RFC 적용 범위

정적 변수 검증 변경이므로 신규 런타임 상태·DB 항목·일관성·지연/역순 이벤트 처리는 없다.
스토리지는 기존 SG 규칙 상한으로 제한하며 잘못된 입력은 Terraform validation 실패로 전파한다.
런타임 `raise`/재시도/DLQ 코드는 변경하지 않는다.

## 검증 기록

실제 AWS 조회·생성·변경·삭제 및 실제 AWS
`plan/apply/destroy/import`, SG 교체·복구·통신 실측·10초 E2E는 수행하지 않는다.
provider 설치·문법 검증·mock 성공은 AWS 배포 성공이 아니다.

| 검사 | 실제 결과 |
| --- | --- |
| 원본 `powershell .\scripts\check.ps1` | exit 1; R&R 통과 후 기존 `.pytest_cache` 열거 권한 오류 |
| 동일 SHA-256 임시 체크아웃의 동일 게이트 | exit 1; R&R·테스트 경로·Ruff lint·format 통과, pytest 실패 |
| 게이트 내 pytest | **916 passed, 4 failed, 0 skipped, 1 warning**, 256.35초 |
| 실패 4건 | 네트워크 VPC/SG 2건, WAF 정책/차단 주소 보존 2건; Windows Application Control provider 실행 차단 |
| 원본 SG 모듈 `fmt -check -recursive` | exit 0 |
| SG `init -backend=false -input=false -lockfile=readonly` | exit 0, 공식 registry 서명 검증된 AWS provider 5.100.0; AWS 배포 검증 아님 |
| SG `validate` | exit 1, provider 스키마 로드 전 실행 정책 차단; 문법 검증 성공으로 기록하지 않음 |
| SG AWS mock `terraform test` | exit 1, 35개 run 발견 후 provider 실행 차단; 실제 HCL 평가 완료·통과 0개 |
| VPC / WAF init | 각 exit 0; VPC fmt exit 0, VPC validate exit 1(같은 실행 차단) |
| Trivy 0.75.0, 전체 심각도 `--exit-code 1` | 변수 미지정 및 합성 baseline egress `/0` 명시 모두 exit 0, 각 71 successes / 0 failures |

실패를 skip으로 바꾸거나 검사 기준을 낮추지 않았다. Trivy 미지정 입력 실행에는 변수 경고가 있었고,
합성 `.tfvars`로 ingress `/32`·egress `/0`·TCP 443을 지정한 재검사에는 변수 경고가 없었다.
ignore·제외·심각도 필터는 추가하지 않았다. 1 warning은 기존 소켓 차단 확인이다.

임시 체크아웃: `C:/Users/User/AppData/Local/Temp/cloudshield-p3-1a-20261012`.
검증 전 추적 파일·신규 HCL·신규 문서·역할 파일 **213개 전체의 SHA-256 일치**를 확인했다.
결과 기록과 기존 설계 문서의 이력 안내만 검사 후 갱신했으며 런타임·변수·HCL 테스트·pytest·검사기는
검증 도중 변경하지 않았다. 원본 캐시 자료·ACL 및 사용자 비추적 문서 3개를 보존했다.
임시 provider/state/plan/lock은 커밋하지 않는다.

환경: Windows / Python 3.12.14 / pytest 8.4.2 / Ruff 0.16.4 / moto 5.2.3 /
boto3 1.43.88 / Terraform 1.16.5 / AWS provider 5.100.0 / Trivy 0.75.0.
공통 lock을 변경하지 않고 `uv sync --all-extras --frozen --python <기존 3.12.14 실행 파일>`로 준비했다.
기존 provider 및 공식 registry 재설치본 모두 실행 차단되었으며 보안 정책·파일 속성을 변경하지 않았다.
기존·복사·공식 provider 실행 파일 SHA-256을 확인했고 기존·복사본은
`12b413fada9bad9125f344749181020bb373f45726c7879790a95999eff19e7d`로 동일하다.

증빙은 같은 Temp 상위 경로에 보존한다.

- manifest: `cloudshield-p3-1a-sha256.json`, SHA-256 `23d7a7bdcc2a5b250ecf3ebaa2d51a272cd7fe79773d4bfb37718a003029eb60`
- 원본 실패 로그: `cloudshield-p3-1a-original-check.log`; 전체 게이트: `cloudshield-p3-1a-full-check.log`
- SG init/validate/mock: `cloudshield-p3-1a-verified-init.log`, `cloudshield-p3-1a-verified-validate.log`, `cloudshield-p3-1a-sg-mock.log`
- Trivy: `cloudshield-p3-1a-trivy.json`, `cloudshield-p3-1a-trivy-egress.json` 및 같은 이름 `.log`
- 실행한 `check.ps1` SHA-256: `8b89383ac3366d4c4c95842e9ef24e9438ccfc21ea7a6c6d1efd51acad8c88fa`

PR 163의 [CI run](https://github.com/mmmphyun/aleph-project/actions/runs/37751953177)은
Terraform 설치·3개 모듈 init 및 필수 환경 주입 후 **920 passed, 0 failed, 0 skipped, 1 warning**이었다.
최신 P3-1A 커밋의 CI 결과는 PR 본문에 별도 확정한다. 선행 CI 성공을 이번 HCL 변경 검증으로 대신하지 않는다.

Draft 대기 조건: Windows provider 실행 차단을 정상 검증 환경에서 해소한 뒤 SG validate/mock 및
동일 `powershell .\scripts\check.ps1` 전수 통과를 확인해야 한다. GitHub Linux CI 성공과 로컬 게이트 실패를
별도로 기록하며 미완료 로컬 DoD를 완료로 표시하지 않는다. 필수 리뷰어는 `gkacksdnjs22-stack`이다.

## 자동화와 완료 범위

현재 `notion_sync.yml`은 Issue opened/reopened 시 진행 중, PR opened/reopened 시 검토 중,
PR merged 시 완료로 노션을 전이한다. Draft 예외는 없고, merged PR 본문의 모든 `#숫자`를 찾아
열린 Issue를 종료하므로 `Refs`로 종료를 막을 수 없다. 본문에는 P3-1A Issue만 번호로 연결한다.
P3-1B/P3-2는 본문에 후속 협업 범위로 적고 P3-1A 완료와 구분한다.
노션 상태·속성은 직접 변경하지 않는다. 이번 요청에서 PR을 머지하지 않고 보안 리뷰를 기다린다.
