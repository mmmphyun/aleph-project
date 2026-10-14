# P3-4 시나리오 1 수집 지연 실측 — INC-1791953271-2171

- 관련 Issue: https://github.com/mmmphyun/aleph-project/issues/176
- Notion Task: https://app.notion.com/p/A-d5f04d37c22582ad9e7f81acd36191d0?p=3f704d37c22580548913cde15c3bb05e&pm=c
- 담당: 클라우드 B / 작성일: 2026-10-14 KST
- 상태: CW 수집 지연, Slack 원본 게시 시각 및 네트워크 담당 전달 결과 반영 완료. 제공된 시각 기준 최초 SYN부터 Slack 게시까지 23.639945초. 클라이언트 수신 시각과 시스템 간 시계 동기화는 미확인.

## 대상 및 증거

AWS 계정 `885755545044`, 리전 `ap-southeast-2`, 타깃 스트림 `i-027b9d94be16b0d77`.
출발지 `1.245.252.171`, 요청 계정 `cloudshield_test`.
기존 수집 프로필은 `cloudshield-cloud-b`, 역할 권한은 `CloudWatchReadOnlyAccess`다. 이번 PR 준비에서는 로컬 증거만 검증했으며 AWS API·공격·서버 변경을 실행하지 않았다.

CloudWatch 읽기 권한으로 `/cloudshield/target/auth-log`의 해당 스트림과 `/aws/lambda/CloudShield-Threat-Orchestrator`를 조회했다.
조회 구간은 2026-10-14 13:42:51~13:52:51 KST이며 CLI 자동 페이지 처리를 유지했다.
auth 이벤트 95건, Lambda 이벤트 16건을 원본으로 저장했다. 해당 출발지·계정의 `Failed password` 이벤트는 5건이다.
EC2의 `/var/log/auth.log` 파일을 직접 읽은 것은 아니며, CW에 전달된 원문 메시지와 이벤트 메타데이터를 증거로 사용한다.

로컬 원본은 Git 제외 경로 `output/p3-4/INC-1791953271-2171/`에 보존했다.
`auth-raw.json`, `lambda-raw.json`, `auth-failures.json`, `auth-timeline.csv`, `collection-summary.json`, `slack-evidence.json`, `network-provided.json`, `tcp22-local-check.json`을 포함한다.
2026-10-13 17:46~17:51 조회 건과 날짜가 다른 별도 사건으로 취급한다.

| 증거 구분 | 확보 범위 |
|---|---|
| 클라우드 B 원본 확인값 | CW auth 원문·timestamp·ingestionTime, Lambda START/END/REPORT, 기존 Slack 원본 확인값 |
| 타 담당 전달값 | 클라우드 A의 T_block·T_sg_verified·T_restored, 네트워크의 T_attack·T_cut·탐침·Kali 재연결 |
| 계산·해석 | 기록된 시각의 차이와 nearest-rank 통계, 미인식 계정에서도 탐지·대응이 이어진 단일 실행의 증빙 |
| 추정 | Lambda 요청과 사건은 시간상 부합하나 incident_id 직접 연결은 미확보 |
| 미측정·미확보 | 클라이언트 수신·표시, EC2 계정 활성화·정확한 조회 실패 원인, 시계 동기화, PCAP 원본 |

노션 카드 조회는 연결 계정에서 `404 object_not_found`로 실패했다. 제공된 카드 URL·사용자 요구사항·기존 Issue #176과 로컬 증거를 기준으로 진행했고 노션 속성·상태는 변경하지 않았다.

## 인증 실패 및 CW 수집 시각

아래 시각은 모두 2026-10-14 KST이다. T_auth는 CW 이벤트 timestamp의 밀리초 표현이다.
원문 auth 메시지의 더 세밀한 소수초와 UTC 오프셋도 JSON·CSV에 보존했다.
T_cw는 ingestionTime이며 API 조회 시각을 사용하지 않았다.

| 순번 | T_auth | T_cw | 기록된 시각 기준 수집 지연 |
|---|---|---|---|
| 1 | 13:47:35.592 | 13:47:36.801 | 1.209초 |
| 2 | 13:47:38.357 | 13:47:40.825 | 2.468초 |
| 3 | 13:47:41.986 | 13:47:43.822 | 1.836초 |
| 4 | 13:47:45.283 | 13:47:45.833 | 0.550초 |
| 5 | 13:47:48.911 | 13:47:50.853 | 1.942초 |

기존 `collector.collection_latency` 도구에 동일 로그 그룹의 선택된 5개 원본 이벤트를 입력했다.
expected-count=5, budget-ms=3000 기준 관측 5건, 누락 0건, 중복 0건, p50=1836ms, p95=2468ms, 최대=2468ms, 3000ms 초과 0건이다.
p50/p95는 nearest-rank 방식이며 5건의 단일 실행 표본이다. 이 결과를 다른 실행의 SLA 보장으로 일반화하지 않는다.
EC2 시계 동기화 증적은 확보하지 않았으므로 값은 기록된 timestamp와 ingestionTime의 차이로 제한한다.

## 미인식 계정 입력에서의 탐지 증빙과 확인 한계

5건 모두 다음 형식이다:

```text
Failed password for invalid user cloudshield_test from 1.245.252.171 ...
```

보안 소유 파일 `src/detection/rules.py`를 읽기 전용으로 확인했다. `AUTH_FAILURE_IDENTITY_PATTERN`은 `(?:invalid user )?`를 지원하며, `evaluate_rules`는 동일 IP·계정의 5분 내 실패 5회 이상을 `SSH_BRUTE_FORCE`로 판정한다. 정규식과 탐지 구현은 수정하지 않았다.
이번 실행은 미인식 계정 입력에서도 실패 5건의 수집·누적 탐지·대응 카드 게시가 이어졌다는 탐지 강건성의 증빙이다. 단일 실행을 “100% 정상 작동”이나 다른 실행의 성능 보장으로 일반화하지 않으며, 의도된 Dictionary Attack이었다고 확정하지 않는다.
탐지 성공과 `cloudshield_test` 계정 활성화 확인은 별개다. `invalid user` 자체를 세팅 결함으로 단정하지 않으며, 서버 내부 점검을 수행하지 않아 정확한 계정 조회 실패 원인은 미확정이다.
추가로 같은 sshd 프로세스(10056)에서 13:47:33.595984 KST의 `Invalid user cloudshield_test`와 13:47:33.816174 KST의 `pam_unix(sshd:auth): check pass; user unknown`을 확인했다.
이 로그는 공격 당시 사용자 미인식 상태를 뒷받침하지만 원인을 확정하지 않는다.
기존 관측 기록상 SSM 경로 확인은 `ssm:DescribeInstanceInformation` 권한 부족으로 거부됐다. 현재 EC2 관리자 SSH/SSM 접속은 확보되지 않았다. 계정 상태 확인이나 서버 변경이 필요하면 대상·명령·영향을 먼저 제시하고 별도 실행 승인을 받아야 한다.
로그를 통해 확인한 공격 당시 상태와 현재 EC2의 계정 상태는 구분한다.
이번 작업에서는 초기화 스크립트 재실행이나 서버·SG·Lambda 설정 변경을 수행하지 않았다.

## 클라우드 A 전달값과 독립 확인 범위

| 항목 | 전달값 (KST) | 클라우드 B 확인 범위 |
|---|---|---|
| 5회차 T_auth | 13:47:48.911 | CW 원본과 일치 |
| 5회차 T_cw | 13:47:50.853 | CW ingestionTime과 일치 |
| T_block | 13:47:50.994 | 같은 시각의 Lambda START 확인. 로그에는 차단 API 호출 시각이 별도로 나타나지 않아 START와 차단 실행을 동일시하지 않음 |
| T_sg_verified | 13:47:52.500 | 클라우드 A 전달값. 클라우드 B는 당시 SG를 독립 조회하지 않음 |
| T_restored | 13:52:28.594 | 클라우드 A 전달값. 당시 Baseline SG 상태를 독립 조회하지 않음 |

마지막 Lambda 요청 ID는 `4557b25c-3a8f-4463-b908-078578d9f282`이며 START 13:47:50.994, END/REPORT 13:47:54.216, Duration 3221.18ms가 기록됐다.
이 요청과 사건의 연계는 시각상 부합하지만 조회된 로그에 incident_id가 없어 직접적인 식별 연결은 미확보이다.

전달된 3.589초는 `T_sg_verified - 5회차 T_auth`로 계산된다.
이는 임계치 도달 이벤트부터 SG 확인까지이며 `T_attack`부터의 전체 공격 대응 시간이나 Slack 포함 전파 시간이 아니다.

## Slack 원본 및 네트워크 결과

기존 관측에서 Slack 원본 메시지의 사건 ID·출발지·대상 계정·타깃을 대조한 결과를 이어받았다. 이번 검증에서는 로컬 `slack-evidence.json`의 원본 ts와 사용자 제공 원본 확인값을 대조했다. 카드의 L4 격리 및 L7 차단 성공 표시는 서비스 상태를 독립 조회한 증거와 구분한다.

- 채널: `#webhook` (`C0BU9AE6970`)
- [원본 Slack 메시지](https://skt-aleph.slack.com/archives/C0BU9AE6970/p1791953274092879)
- 원본 `ts`: `1791953274.092879`
- Slack 게시 시각: **2026-10-14 13:47:54.092879 KST** (UTC 04:47:54.092879)

이 값은 Slack 서비스에 기록된 게시 시각이며 사용자 클라이언트의 실제 수신·표시 시각은 미확인이다. 본 보고서는 `T_slack_posted`로 명시한다.
사건 ID에 포함된 epoch나 Webhook 성공 시각을 Slack 게시·수신 시각으로 대체하지 않았다.
현재 사건에서의 Slack 연결 여부·수신 시각을 전날 웹훅 미연결 상태로 추정하지 않는다.

기존 관측 기록상 2026-10-14 14:23:15.184~14:23:15.421 KST, Windows PC에서 운영자가 제공한 타깃 TCP 22에 단일 연결이 성공했다. 이번 PR 준비에서는 연결 탐침을 재실행하지 않았다.
SSH 인증은 시도하지 않았다. 이 결과는 현재 PC의 TCP 연결 확인이며 Kali에서 `nc -zv`로 수행한 복구 증적은 아니다.
네트워크 담당의 다음 실측 결과를 사용자를 통해 전달받았다. 모두 2026-10-14 KST이며 사건 ID가 일치한다.

| 항목 | 네트워크 담당 전달값 |
|---|---|
| T_attack | 13:47:30.452934 — Hydra 첫 SYN |
| T_cut | 13:47:54.388985 — 최초 무응답 SYN |
| 연결 탐침 | 24회 성공 후 36회 연속 타임아웃 |
| 복구 후 Kali 재연결 | 14:35:23.944 — 정상 연결 확인 |

PCAP 분석 결과는 전달받았지만 PCAP 원본 파일은 확보하지 않았으며 클라우드 B가 독립 재분석한 결과로 표시하지 않는다.
Kali 재연결 성공은 클라우드 A의 복구 전달값과 함께 복구 후 접근 가능 상태를 뒷받침한다. 재연결 시각 자체를 SG 복구 완료 시각으로 대체하지 않는다.

| 계산 구간 | 전달값·원본 시각 기준 소요 시간 |
|---|---|
| T_attack → T_cut | 23.936051초 |
| T_attack → T_slack_posted | 23.639945초 |
| T_attack → T_sg_verified | 22.047066초 |
| 5회차 T_auth → T_sg_verified | 3.589초 |
| 5회차 T_auth → T_cut | 5.477985초 |
| 5회차 T_auth(CW timestamp) → T_slack_posted | 5.181879초 |
| 5회차 T_cw → T_slack_posted | 3.239879초 |

따라서 제공된 시각 기준 공격 개시부터 Slack 게시 및 네트워크 단절까지는 각각 10초를 초과한다.
임계치 도달인 5회차 인증 실패부터 Slack 게시까지는 약 5.182초다. auth 원문 소수초(.911690)를 사용하면 5.181189초이며 위 표는 CW timestamp(.911)의 밀리초 기준과 일관되게 계산했다.
임계치 도달 후 SG 확인까지의 3.589초와 공격 개시부터의 시간을 구분한다.
T_cut은 최초 무응답 SYN의 시각이며 실제 차단 변경 시각과 동일하지 않다. 탐침 간격과 타임아웃 판정 방식은 PCAP 원본·탐침 원본 확보 후 확인한다.
서로 다른 시스템 간 시간 동기화 증적은 미확보이므로 미세한 시각 차이의 해석은 제한한다.

따라서 이번 기록에서 직접 확보한 클라우드 B 실측값은 5건의 T_auth/T_cw, 수집 지연 및 원본 Slack ts에 따른 T_slack_posted다.
T_attack/T_cut과 Kali 재연결은 네트워크 담당 전달 실측값으로 반영했다. 최초 SYN부터의 10초 목표와 5회차 실패 이후의 대응 구간은 구분한다. 실제 클라이언트 수신 시각은 미확인으로 남긴다.

## 원본 재검증 및 재현 범위

2026-10-14 PR 준비 시 auth 원본 95건에서 대상 출발지·계정의 실패 5건을 다시 선택하고 `auth-failures.json`과 전체 이벤트 객체가 동일함을 검증했다. eventId·지연을 CSV와 대조했고 이벤트 날짜가 모두 2026-10-14 KST임을 확인했다.
기존 `summarize_collection_latency`에 선택한 원본을 입력해 저장된 `collection-summary.json`과 모든 필드가 일치함을 확인했다. Slack 원본 ts와 KST 게시 시각을 대조하고 Decimal 기반 계산으로 23.639945초·23.936051초·5.181879초·3.589초를 재검증했다. 원본을 재수집하거나 수정한 결과가 아니다.

계측 CLI 재현 명령은 저장소 루트에서 다음과 같다. 예상 5건·3초 예산은 CW 수집 구간의 검증 조건이며 최초 공격 기준 10초 목표와 다르다.

```powershell
$env:PYTHONPATH = 'src'
.\.venv\Scripts\python.exe -m collector.collection_latency output/p3-4/INC-1791953271-2171/auth-failures.json --expected-count 5 --budget-ms 3000
```

Git 제외 원본의 SHA-256은 다음과 같다. PCAP 원본 해시는 클라우드 B가 확보하지 않았다.

| 파일 | SHA-256 |
|---|---|
| auth-raw.json | `e157319df1d2e8f9ecd46a9230a0e691a4a43e3162a6e5f68e260db4884187f0` |
| auth-failures.json | `24cb75da5d4eb7ca77c67996879e7db74300be5485ef8b7a79897d1c7cf337a2` |
| auth-timeline.csv | `51316a45882e7d12ace04b90bfa214e4deff8b7a0c2b7802ea0aeb9dc8728a04` |
| collection-summary.json | `3468756f6d4c704e0f25e06661ef925f47473ed9e04da86191870d3dde97210d` |
| lambda-raw.json | `2409064237fff57f51c25543bd9290242be1d1f1b4595d4eeb71a35e2b3d7cc0` |
| slack-evidence.json | `2f00a0a431a876595e374f46266d3a2395599d5b5d59469efad8582d180b1303` |
| network-provided.json | `2e96534db8a50ce6e4908247e58beae6984451e0a91a524d13db78f17220f37f` |
| tcp22-local-check.json | `8d7c735813ec6ae307d594dbde77b0345c288f4a14c3b986c7f365de7fcdcae4` |

선행 클라우드 B PR #174는 머지됐고 기존 Issue #176·브랜치를 재사용한다. 클라우드 A #178의 임계치 이후 3.589초를 최초 공격 기준 10초 달성으로 해석하지 않는다. 후속 머지 순서는 P3-3B(#178) → P3-3C(#179) → P3-4이며 이 PR 준비에서는 머지하지 않는다.

## 로컬 품질 검증 결과

2026-10-14, `AGENT_ROLE=cloud-b`로 공식 `scripts/check.ps1`을 실행했다. 최초 샌드박스 실행은 pytest 임시 디렉터리 생성 권한 오류로 중단했으며 통과로 취급하지 않았다. 검사 코드·옵션을 변경하지 않고 정상 로컬 권한으로 재실행했다. PowerShell의 프로세스 실행 정책만 Bypass로 지정했고 품질 검사 우회 옵션은 사용하지 않았다.

- R&R·테스트 표준 경로·Ruff lint 통과, 128개 파일 format 검사 통과.
- pytest: **984 passed, 4 skipped, 1 warning**, 152.21초, 공식 스크립트 종료 코드 0. skipped 4건은 검증 성공 건수에 포함하지 않는다.
- 경고: 기존 `test_network_socket_is_blocked_by_default`에서 DNS 호출을 소켓 차단 플러그인이 막으며 발생한 UserWarning.
- 실행 로그: Git 제외 경로 `output/p3-4/check-pr-unsandboxed.log`. 문서 외 구현·공통 계약·타 직무 파일 변경 없음. 신규 분산 상태 구현이 없어 역순 인입·부분 장애·용량 제한 신규 테스트 추가 대상은 없으며 기존 전체 테스트를 실행했다.
