# 시나리오 1·2 통합 데모 러너

- Notion Task: https://notion.so/3fe04d37c22580cca171c526fe747de7
- GitHub Issue: https://github.com/mmmphyun/aleph-project/issues/193
- 브랜치: `feat/network-p4-demo-attack-runner`
- 이번 산출물은 구현·외부 통신 없는 모의 검증이다. 실제 AWS 공격·인프라 변경·복구는 실행하지 않았다.

## 1. 준비 조건과 소유권

`demo_attack_runner.sh`는 `set -euo pipefail`과 `exec python3`로 Python 러너에 인자를 전달한다.
기본 동작은 계획 출력이다. 외부 통신, DNS 조회, 공격 도구 조회·실행, 승인 파일 읽기,
증거 파일 생성을 하지 않는다. Python 3.12 이상과 Bash가 있으면 dry-run할 수 있다.

실제 실행은 별도 승인을 받은 Linux 환경에서만 가능하다. SSH에는 기존과 동일하게
Hydra(SSH 모듈 및 `-K`), tcpdump, TShark, 단일 캡처 인터페이스와 캡처 권한이 필요하다.
Web에는 Bash·curl과 기존 스캐너가 허용한 ALB HTTP 80이 필요하다. 자동 sudo는 없다.

클라우드 A는 현재 EC2 인스턴스 ID·공개 IPv4, 승인 ALB, 출발 IPv4 허용,
SG/WAF 복구 준비를 확인한다. 클라우드 B는 테스트 계정·로그 수집·관측 준비를 확인한다.
AWS 계정/인스턴스 소유권·실제 출발 IP는 러너가 조회하지 않는다. 승인 파일은 운영자가
확인한 사실의 기록이며, 서명이나 AWS 자산 검증을 대신하지 않는다.

수정 범위는 `network/`, `tests/unit/test_network.py`, `docs/roles/network/`다.
계약·탐지·차단 엔진·수집·Slack·IAM·Terraform·GitHub Actions는 호출하거나 수정하지 않는다.

## 2. dry-run과 옵션

저장소 루트에서 실행한다. 아래 명령은 실제 통신을 하지 않는다.

```bash
bash network/demo_attack_runner.sh
bash network/demo_attack_runner.sh --scenario ssh
bash network/demo_attack_runner.sh --scenario web --web-observe-seconds 45
bash network/demo_attack_runner.sh --scenario all --dry-run
```

| 옵션 | 의미 |
| --- | --- |
| `--scenario ssh\|web\|all` | SSH, Web 또는 SSH → 복구 확인 → Web; 기본 all |
| `--execute` | 승인·준비 조건을 통과했을 때만 실제 통신 허용 |
| `--dry-run` | 명시적 계획 모드; `--execute`와 동시 지정 불가 |
| `--approval-file PATH` | 현재 승인 JSON; 실제 실행 시 필수 |
| `--evidence-root PATH` | Git 밖의 기존 비공개 증거 루트; 실제 실행 시 필수 |
| `--interface eth0` | SSH 캡처 인터페이스; `any`·셸 문자·잘못된 이름 거부 |
| `--web-observe-seconds 1..60` | Web 공격 시작 후 관측 상한; 기본 60초 |

SSH의 기존 공격·계측 상한은 CLI에서 늘릴 수 없다. 짧은 Web 관측 시간을 선택하면
스캐너가 후보 실행을 끝내기 전에 중단될 수 있으며, 이는 시간 초과로 처리한다.

## 3. 승인 정보와 향후 실제 실행 연결

현재 유효한 승인 정보가 없으면 실행을 거부한다. 과거 보고서의 주소를 기본 타깃으로
가져오지 않는다. 특히 과거 일회용 공격 노드 출발 주소 `3.26.171.60`은 SSH 타깃으로 거부한다.
공개 IPv4라는 사실만으로 타깃을 승인하지 않으며, 현재 승인 파일의 인스턴스 ID와
타깃 주소, 환경의 타깃 주소가 모두 있어야 한다. 출발지와 타깃이 같아도 거부한다.

운영자는 Git 밖에 자신이 소유한 0700 디렉터리를 준비하고, 승인 파일을 0600 일반 파일로 둔다.
승인 파일은 최대 16KiB, 유효기간은 최대 24시간이다. 시작 전과 단계 전환 후 유효기간을 재검사한다.
개인키·AWS 키·토큰·비밀번호를 넣지 않는다. 다음은 **형식 예시**이며 주소·시각은 실제 승인 값으로
교체해야 한다. 예약 문서 주소는 검증에서 거부된다. 예시 자체로 실제 실행할 수 없다.

```json
{
  "approval_id": "approved-change-reference",
  "approved_by": "cloud-a-operator",
  "approved_at": "2026-10-19T00:00:00Z",
  "expires_at": "2026-10-19T01:00:00Z",
  "source_ipv4": "192.0.2.10",
  "ec2": {
    "instance_id": "i-0123456789abcdef0",
    "public_ip": "192.0.2.20"
  },
  "alb_origin": "http://cloudshield-alb-dev-308142572.ap-southeast-2.elb.amazonaws.com"
}
```

SSH 전용 실행은 `alb_origin`이 필요 없고, Web 전용 실행은 `ec2`가 필요 없다.
ALB는 기존 `web_dir_scan.sh`의 `APPROVED_ALB_HOST` 계약을 읽어 검증한다.
다른 호스트·HTTPS·다른 포트·userinfo·경로·쿼리·fragment를 허용하지 않는다.
ALB 변경이 필요하면 기존 승인 범위를 담당자와 먼저 재검토한다.

실제 실행 전에 운영자가 준비한 환경 변수가 필요하다. 이 변수는 준비 확인 기록이며,
러너가 서버 설정·로그 수집·AWS 상태를 대신 검증했다는 뜻은 아니다.

```bash
export CLOUDSHIELD_PIPELINE_READY=yes
export CLOUDSHIELD_SOURCE_ALLOWED=yes
export CLOUDSHIELD_RECOVERY_READY=yes
export CLOUDSHIELD_TARGET_IP='<현재 승인된 EC2 공개 IPv4>'
export CLOUDSHIELD_TEST_ACCOUNT=cloudshield_test
```

향후 별도의 실제 실행 승인을 받은 경우에만 다음 형식을 사용한다. 이번 작업에서는 실행하지 않는다.

```bash
bash network/demo_attack_runner.sh --scenario all --execute \
  --approval-file /var/lib/cloudshield-private/current-approval.json \
  --evidence-root /var/lib/cloudshield-evidence/demo \
  --interface eth0 --web-observe-seconds 60
```

## 4. 기존 도구 연결과 실행 상한

| 단계 | 재사용과 상한 |
| --- | --- |
| SSH | `ec2_hydra_measurement.py`의 설정·도구 확인·실행 함수 재사용; TCP 22, 전용 계정, 합성 오답 5개, 동시성 1, 응답 대기 10초, 공격 최대 60초 |
| SSH 캡처 | 기존 `tcpdump_capture.sh`; 75초·2,000패킷, 캡처 준비와 생존 확인, 최대 60회 탐침·1초 간격·0.8초 connect 제한 |
| Web 공격 | `web_dir_scan.sh` 1회 호출; 후보 15개, curl 동시성 1, 응답 후 간격 1초, 개별 요청 3초, 전체 60초 |
| Web 관측 | 별도 루트 HEAD; 공격 전 1회, 공격 중 최대 60회, 연결·요청 제한 각 1초; 본문 저장·프록시·리다이렉트 없음 |
| 순차 복구 | 운영자 확인 1회와 복구 후 TCP 탐침 1회; Web 시작 전 정상 HEAD 200 재확인 |

공격과 HEAD 관측은 서로 다른 요청이다. Web 후보 GET의 401/404는 스캔에서 정상적으로
관측될 수 있으며, 루트 HEAD baseline은 200이어야 한다. 차단 후보를 발견해도 기존 공격 도구의
실패 코드를 성공으로 바꾸지 않는다. 완료 전 실패하거나 시간 상한을 넘으면 정리 후 비정상 종료한다.

`sg_connection_timeline.py`와 `waf_packet_timeline.py`는 오프라인 CSV 분석기다.
실시간 TCP timeout·HTTP 코드만으로 이 분석기들의 PCAP 검증 결과를 만들어내지 않는다.
Web 러너 자체는 PCAP을 캡처하지 않는다. 패킷 증명이 필요하면 별도 승인된 캡처와 원본 대조가 필요하다.

## 5. 순차 모드의 복구 절차와 중단

1. SSH 단계가 끝나면 러너가 멈추고 현재 실행 ID를 표시한다.
2. 클라우드 A 담당자가 기존 복구 절차로 Baseline SG 및 필요한 WAF IP 차단 해제를 수행한다.
   기존 `scripts/restore_baseline_sg.py`, `scripts/unblock_waf_ip.py`는 담당자가 별도 실행한다.
   러너는 해당 스크립트나 Boto3 복구 API를 호출하지 않는다.
3. 운영자가 담당자의 복구 완료를 확인한 뒤 터미널에 `RESTORED <현재 실행 ID>`를 입력한다.
   비대화형 stdin, EOF, 다른 입력은 다음 공격을 차단한다. 사전 지정 플래그는 없다.
4. 러너가 승인 유효기간·TCP 정상 연결·HTTP 200을 재확인한 뒤 Web 공격을 한 번 시작한다.
5. Web 종료 후 SG/WAF 원복 확인은 담당자에게 연결한다. 최종 복구를 러너가 자동 수행했다고 표시하지 않는다.

Ctrl+C는 130, SIGTERM은 143으로 중단한다. 새 세션으로 생성한 소유 프로세스만 정리한다.
다른 실행의 프로세스를 이름으로 찾아 종료하지 않는다. 재공격·무제한 재시도·예약 실행은 없다.
재실행은 새 승인과 새 실행 증거로 별도 수행하며, 러너가 자동 재개하지 않는다.

## 6. 출력·증거와 판정 한계

stdout은 UTC 밀리초, 시나리오, 단계, 관측 결과, 남은 관측 시간의 표다.
경과 시간은 단조 시계로 계산한다. 카운트다운은 관측 한도이며 차단 완료 보장이 아니다.
프로세스 호출 시각은 첫 패킷·첫 서버 인증 실패 시각과 구분한다.

| 표시 | 확인한 사실 / 추가 증거 |
| --- | --- |
| `TCP connect timeout` | 클라이언트 연결 제한 시간 내 완료 안 됨; PCAP SYN 무응답·SG 원인은 별도 대조 |
| `HTTP 200 → 403` | 루트 HEAD 응답 전환; WAF BLOCK·규칙·clientIp는 WAF 원본 로그 필요 |
| `attack_request_recorded` | 기존 Web 스캐너의 실제 요청 메타데이터를 종료 후 대조; 실시간 출력 순서와 원래 관측 시각을 구분 |
| `not_observed` | 유한 관측 구간 내 차단 후보 미관측; 성공 아님 |
| `late_probe` | 단조 시계 기준 관측 상한 이후 도착한 응답; 403이어도 차단 후보로 집계하지 않음 |
| `end` | 로컬 실행 종료와 종료 코드; AWS·WAF·Slack은 항상 별도 미평가 |

실행별 새 디렉터리를 독점 생성한다. 기존 실행 폴더와 파일은 덮어쓰지 않는다.
`events.jsonl`은 이벤트 순번, 기록 시각, 원래 관측 시각, 단조 경과 시간, 결과를 저장한다.
최종 `end` 행의 `details.exit_code`가 로컬 종료 상태다. 이벤트는 최대 512개,
한 행 4KiB·총 1MiB로 제한한다. 용량 초과·쓰기/flush/close 실패는 비정상 종료한다.
이 파일과 SSH의 하위 실행 폴더(PCAP·비공개 로그·manifest), `web-scan.txt`는 Git 밖에 보존한다.
원본 경로와 주소가 포함될 수 있으므로 공개 PR에는 마스킹한 결과와 필요한 해시만 공유한다.

| 종료 코드 | 의미 |
| --- | --- |
| 0 | 로컬 공격 도구 완료 및 차단 후보 관측; 전체 파이프라인 성공 판정 아님 |
| 2 | 인자·승인·준비 조건 미충족 |
| 3 | 차단 후보 미관측 |
| 20 | baseline 또는 단계 사이 복구 확인 미충족 |
| 70 | 도구 실행/관측 규격/정리 실패 |
| 74 | 증거·승인 파일 I/O 또는 용량 상한 실패 |
| 124 | 시간 초과 |
| 130 / 143 | 사용자 중단 / 종료 신호 |
| 그 외 | 기존 도구의 비정상 종료 코드 전달; SSH 계측기의 10/21/22 등 유지 |

[L4 재실측](2026-10-14-p3-3c-hydra-l4-remeasurement.md)의 약 5.478초는
실패 5회 누적부터 최초 무응답 탐침까지이며, 공격 첫 SYN 기준은 약 23.936초였다.
[WAF 재실측](2026-10-16-p3-6-waf-403-retest.md)의 약 18.197초는 Lambda 시작부터
최초 403 관측까지이며, 첫 공격 GET 기준은 약 26.324초였다. 서로 다른 시작점을
같은 성능 지표로 비교하지 않는다. 드문 탐침 사이의 정확한 정책 적용 순간도 미확정이다.
제어 API 완료·실제 데이터 경로 반영·Slack 게시/사용자 수신은 각각 별도 증거가 필요하다.
이 러너의 모의 성공으로 전체 10초 SLA를 입증하지 않는다.

## 7. 로컬 검증과 남은 확인

`tests/unit/test_network.py`에서 공격·소켓·HTTP·자식 프로세스·시계를 모의 처리한다.
선택/순차 실행, dry-run, 승인·입력 거부, 정상→차단 후보, 미관측, 시간 초과,
도구 실패, 사용자 중단, 소유 자식 정리, 복구 게이트, 증거 덮어쓰기·용량·쓰기 실패를 검증한다.
실제 실행 도구로 폴백하면 테스트가 실패한다. 기존 네트워크·계약 테스트도 보존한다.

필수 게이트는 저장소 루트의 `powershell .\scripts\check.ps1`이다.
검증 완료 결과와 환경상 미실행 항목은 PR에 별도 기록한다.

실인프라 잔여 확인: 최신 타깃/출발 IP 승인, 도구·캡처 권한, 전용 계정 상태,
SG 복구 후 ALB 정상성, WAF 전파 구간, Lambda/WAF/Slack 로그 상관관계,
장비 간 시계 오차, 실제 신호 종료와 원본 PCAP 보존이다. 별도의 실측 승인 후 확인한다.
