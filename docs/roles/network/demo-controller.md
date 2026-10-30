# 로컬 단일 데모 컨트롤러

> 최신 재실측: SSH 공격·차단·복구·TCP 회복·3차 Slack 완료. Web은 ALB TCP 80 기준선 timeout으로 스캔 전 중단. [최신 실측 결과와 ALB 허용 요청](2026-10-30-p5-4-live-retry.md). 아래 준비 내용은 실행 전 이력이다.

`network/demo_controller.py`는 로컬 PC에서 기존 공격 도구, A의 복구 함수, B의 Slack 함수와 대시보드를 연결한다. 기본 명령은 plan이다. AWS 자격증명과 웹훅은 로컬에만 남기며, 공격 노드에는 승인 대상과 실행 자료만 보낸다.

## 1. 현재 준비와 실행 방법

프로젝트 루트 PowerShell에서 준비된 비공개 구성을 사용한다. 이 파일에는 키 값이 아닌 로컬 프로필명·비공개 파일 경로·승인 대상·기존 원격 자산 해시가 들어 있다. Git에 추가하지 않는다.

```powershell
$env:PYTHONPATH = 'src'
$controllerConfig = Join-Path $env:USERPROFILE 'CloudShieldEvidence/p5-4-controller/controller-tcp.private.json'
uv run python network/demo_controller.py plan --config $controllerConfig
uv run python network/demo_controller.py preflight --config $controllerConfig
```

실제 preflight 결과는 blockers 0개, EC2 DryRunOperation, Grafana 쿼리 1A/1B/2A/3A/4A 모두 Complete다. 웹훅 확인은 파일/형식 검사다. preflight는 대상 트래픽·복구 변경·Slack 전송을 실행하지 않는다. 현재 설정의 `require_key_auth=false`는 TCP 연결 회복만 확인하며 키 인증은 null로 남긴다.

실제 실행은 기존 러너 규격의 유효한 승인 파일을 구성의 approval_file 경로에 보존한 뒤 수행한다. 아직 이 파일을 만들거나 아래 명령을 실행하지 않았다.

```powershell
uv run python network/demo_controller.py run --execute --scenario all --config $controllerConfig
```

승인은 승인 ID·승인자·UTC 승인/만료 시각·출발 IP·타깃 인스턴스/IP·승인 ALB origin을 기존 parse_approval로 검증한다. 유효기간 최대 24시간·파일 16KiB이며 Linux에서는 실행 사용자 소유 0600을 요구한다. 같은 승인 ID는 한 번 소비하며 자동 재실행하지 않는다. Windows 비공개 폴더는 사용자에게만 허용된 ACL로 보존한다. 비공개 파일과 원본 증거는 Git 밖 절대 경로만 받는다.

종료 코드: 0은 plan/preflight 성공 또는 컨트롤러 절차 성공, 2는 구성/승인/preflight 오류, 3은 실행 중 부분 실패다. 0이어도 전체 P5 DoD나 첫 공격 기준 10초 SLA를 뜻하지 않는다.

## 2. 연결하는 기존 코드와 실패 처리

1. 원격 자산 8개 해시·공격 노드 신원·타깃 Baseline SG·잔류 WAF 차단을 확인한다. 기존 tcpdump_capture.sh로 SSH 또는 승인 ALB IPv4 최대 2개를 120초/2,000패킷 상한으로 캡처한다.
2. 기존 demo_attack_runner.sh를 SSH/Web 각 한 번 호출한다. SSH는 기존 합성 오답 5개/동시성 1, Web은 기존 후보 GET 15개 상한을 그대로 사용한다. 실제 서버 로그에서 같은 출발지·실행 구간의 새로운 incident_id가 유일하고 타깃 스트림이 일치해야 기존 보안 매퍼로 리포트를 구성한다.
3. 공격 프로세스를 정리한 뒤 A의 restore_baseline_security_group와 unblock_ip_wafv2를 로컬에서 호출한다. 명시한 IPSet ID에서 단일 공격 IP만 해제하며, 한 계층 실패 시에도 다른 계층을 시도하고 각각 구성을 재조회한다.
4. 공격 노드에서 신규 TCP 연결 또는 같은 origin 루트 HEAD 200을 최대 20회/30초, 시나리오 시작 기준 112초 관측 한도 안에서 확인한다. RPC 시간이 있으므로 실제 탐침 간격을 정확한 1초로 선언하지 않는다. require_key_auth=true이면 승인된 별도 계정으로 true를 1회 실행한다.
5. 유일한 실제 사건이 연결된 경우 B의 send_recovery_slack_alert에 기존 ID와 평면 복구 payload를 전달한다. 실패한 계층/통신 결과도 그대로 전달한다. 테스트용 사건 ID나 중첩 components 객체를 만들지 않는다.
6. 소유 PID/시작 tick/명령 경로가 맞는 프로세스만 정리하고 증거를 해시 대조해 회수한다. 기존 roundtrip_timeline으로 오프라인 요약하고 같은 구간의 Grafana 5개 쿼리 응답을 보존한다.

공격 요청 후 SSH 응답이 유실돼도 승인된 단일 대상 복구를 시도한다. 부분 복구·실제 사건 미확인·통신 미회복·Slack 실패·캡처 조기 종료·파일/해시 오류는 complete=false이고 다음 공격은 시작하지 않는다. 파일은 원자 생성·덮어쓰기 금지이며 일반 메타데이터 1MiB, 원격 파일 최대 32개, PCAP 개별 1GiB 상한이다. 증거 회수 오류 시 부분 파일을 진단용으로 보존한다.

## 3. 인증과 증거 범위

로컬 boto3 프로필은 승인된 단일 타깃 복구 권한을 가진다. Grafana는 사용자가 전달한 A의 직접 SDK 인증 방식으로 같은 로컬 자격증명을 컨테이너 환경에서 사용하며 IAM 강제 조회 전용 계정은 아니다. GetFederationToken/AssumeRole은 이 경로의 필수 요건이 아니다. 기존 A/B provisioning/dashboard 파일은 수정하지 않았다.

SSH 실행은 로컬 client config를 사용하지 않고 키·known_hosts를 명시하며 AWS_*·SLACK_WEBHOOK_URL을 자식 환경에서 제거한다. 원격 어댑터는 AWS SDK·웹훅을 받지 않는다. WAF ListIPSets 없이 명시 ID를 사용한다. WAF Update의 실제 권한 성공은 아직 실증하지 않았다.

실제 실행 시 로컬 runs 아래에 controller-result, 시나리오 결과, 서버 사건 원문, A 복구 결과, 독립 탐침, Slack 함수 응답, 원격 manifest/PCAP/러너 로그, 타임라인 입력/요약, Grafana 쿼리 원문을 보존한다. Incoming Webhook은 Slack 원본 ts를 반환하지 않아 null이다. WAF 원문과 Slack 전체 3단계 원문/화면은 B의 추가 보존이 필요하다.

컨트롤러 호출 시각을 첫 실제 공격 패킷 시각으로 대체하지 않는다. 현재 타임라인의 첫 실제 공격과 장비 간 최대 시계 오차는 null이며 e2e_sla_verified=false다. PCAP 프레임 분석·키 인증 회복·연결 재사용·같은 사건 관제 대조가 남아 있다. [실측 보고서](2026-10-30-p5-4-roundtrip-packet-grafana-correlation.md)와 [팀원 전달 내용](p5-4-team-handoff.md)을 함께 확인한다.

## 4. 검증

실제 AWS 변경이나 Slack 전송 없이 네트워크 회귀 테스트와 필수 powershell .\scripts\check.ps1 게이트를 실행했다. 로컬 결과는 **1590 passed, 4 skipped, 1 warning, 201.19초**, 종료 코드 0이다. 기존 소켓 차단 검증 경고 1개이며 검증 게이트·의존성·타 직무 테스트를 변경하지 않았다. 테스트는 단일 대상 복구와 다른 IP 보존(moto), 전송 유실·부분 장애·승인 재사용·저장 실패·실제 사건 매핑·키 인증 선택·캡처 수명·Grafana 익명 차단/Complete 조건을 다룬다. 최신 CI 결과는 기존 Draft PR #243에 기록한다.
