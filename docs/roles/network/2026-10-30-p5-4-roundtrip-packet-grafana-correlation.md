# P5-4 SSH·Web 왕복 패킷과 Grafana 서버 로그 대조

- 담당: 네트워크 `@RockCandy444`
- [Notion Task](https://notion.so/40504d37c225810e9698ded0d11acc77) · [Issue #242](https://github.com/mmmphyun/aleph-project/issues/242)
- 브랜치: `docs/network-p5-4-roundtrip-packet-grafana-correlation`
- 기준 main: `822fdc1c8ea0be75d921a989302dc5e6b240e9f9`
- 문서 기준일: 2026-10-30 KST. 실제 측정일은 아직 없음.
- **상태: 로컬 단일 컨트롤러·Grafana AWS 연결 준비 완료, TCP/HTTP 모드 preflight blockers 0개. SSH·Web 공격·차단·복구 실측은 미실행이며 DoD 미충족.**

## 1. 범위와 착수 근거

이번 작업은 실제 SSH·Web 트래픽의 정상→차단 후보→복구 후 정상 통신을 패킷과 요청으로 관측하고, 같은 사건의 CloudWatch·Grafana·Slack 자료를 대조한다. 최초 문서 범위에서 사용자가 단일 데모 컨트롤러 준비까지 승인하여 `network/`, `tests/unit/test_network.py`, `docs/roles/network/`를 수정한다. A/B의 기존 함수·공통 계약·인프라·CI·다른 직무 코드는 변경하지 않는다. [컨트롤러 실행 안내](demo-controller.md)를 함께 본다.

사용자는 읽기 전용 정찰 후 제시한 계획을 승인하고 신규 공격 노드와 타깃의 식별 정보를 제공했다. 공개 문서에서는 각각 `attacker-p5-4`, `target-p5-4`로 표시한다. 실제 주소·키·승인 파일·PCAP·민감 로그는 Git에 추가하지 않는다. SSH/IMDS 식별에 이어 로컬 프로필로 STS 신원, 타깃 주소·Baseline SG, WAF IPSet을 독립 조회했다. EC2 변경 권한은 DryRunOperation으로 확인했고 실제 변경은 없었다.

공식 `uv run python scripts/get_my_tasks.py` 재확인 결과 P5-4는 `시작 전`, `착수 가능`이었다. 열린 PR은 0건이었고 동일 Notion 링크의 기존 이슈 및 지정 브랜치는 발견되지 않았다. P5-1·P5-1.5·P5-2·P5-2.1·P5-3의 최신 카드 상태와 본문을 읽었다. 이 완료 상태를 현재 배포·대상 정상성의 증거로 사용하지 않는다.

승인 후 main을 fast-forward하여 기준 커밋으로 최신화하고 이슈 선발행→지정 브랜치 생성 순서로 착수했다. 기존 미추적 회의 문서 3개와 비공개 과거 증거는 보존한다. 이전 검증 worktree의 detached `c1d1490`은 최신 main으로 사용하지 않는다.

## 2. 재사용 자산과 확인된 차이

| 기존 자산 | 재사용 범위와 한계 |
| --- | --- |
| [통합 러너](demo-attack-runner.md), `network/demo_attack_runner.sh`, `network/demo_attack_runner.py` | 실행 승인·유한 공격·baseline·차단 후보·run_id·events.jsonl. 종료 코드 0은 전체 왕복 성공이 아님 |
| `network/ec2_hydra_measurement.py` | SSH 전용 계정·합성 오답 5개·동시성 1·내부 캡처·탐침·비공개 manifest. TCP 연결 성공과 SSH 인증 성공은 다름 |
| `network/web_dir_scan.sh` | 실제 curl 요청 메타데이터. 호출 직전 시각은 첫 패킷/HTTP 송신 시각이 아님 |
| `network/tcpdump_capture.sh` | 기존 파일 보호·단일 IPv4/포트/인터페이스·시간/패킷 상한. Web 캡처는 별도 실행 필요 |
| [왕복 계측기](roundtrip-timeline-telemetry.md), `network/roundtrip_timeline.py` | 해시한 보존 파일의 오프라인 연결·Decimal 계산. 공격·조회·복구·업로드를 실행하지 않음 |
| `network/waf_packet_timeline.py` | 기존 TCP CSV 플래그·방향·stream 분석. HTTP/WAF 집행 원인은 추정하지 않음 |
| `network/sg_connection_timeline.py` | 기존 보존된 동일 소켓 관측의 분석에만 사용. 합성 SG 교체를 실제 사건으로 전환하지 않음 |
| `scripts/measure_pipeline.py` | A 소유 SG 부착·성공 로그 관측. 물리적 차단·WAF·복구 지연 측정기가 아님. 기본 대상 ID를 현재 대상으로 사용하지 않음 |

위 네트워크 도구 8개, AGENTS.md, 공식 착수 스크립트, PR 템플릿은 정찰 당시 작업 HEAD `70e4986`과 원격 기준 main의 Git blob이 같았다. [PR #220](https://github.com/mmmphyun/aleph-project/pull/220)은 squash `6694ac364911217323aca15afb16b27f27075288`으로 머지됐다.

카드의 기술과 현재 구현 사이에는 다음 차이가 있다. 담당자 영역을 수정하거나 존재하지 않는 측정값을 만들어 해소하지 않는다.

| 카드의 요구 | 실제 구현과 이번 처리 |
| --- | --- |
| 복구 후 통신까지 연속 PCAP | 내부 SSH 캡처는 75초이고 Web 러너는 PCAP을 만들지 않음. 별도 유한 연속 캡처가 필요 |
| L4/L7·LLM·복구 지연 패널 | B의 실제 4개 패널은 후보 인입·탐지→API 반환·LLM 최종 상태·사건 타임라인. 없는 지연 패널은 미구현으로 기록 |
| measure_pipeline과 양 시나리오 지표 일치 | SG 관측은 SSH에서 비교 가능. WAF만 차단하는 Web 및 복구 지연에는 대응 지표가 없어 해당 비교는 비적용/미확인 |
| 3차 복구 카드와 독립 통신 회복 | 기존 모의 위협 스크립트의 복구 카드 `traffic_verified`는 구성 결과로 설정됨. 독립 네트워크 탐침으로 재검증 필요 |
| 실제 트래픽 사건의 3차 알림 | 확인한 자동 연결은 모의 위협 주입 스크립트에 있음. 새 모의 사건을 생성하지 않고 실제 incident_id를 유지하는 A 절차 확인 필요 |

## 3. 선행 증거의 출처 경계

- [A P5-1](../cloud-a/2026-10-28-p5-1-pipeline-deploy-and-grafana-provisioning.md): 시드니 리전 배포·Grafana 프로비저닝 문서. 이후 #227·#228·#231·#233·#235·#237·#241 머지 이력을 확인했으나 현재 AWS 코드 버전은 미조회다.
- [B P5-2](../cloud-b/2026-10-29-p5-2-grafana-slack.md) 및 [후속 검증](../cloud-b/2026-10-30-p5-2-panel-verification.md): 사건 `INC-1793322987-0090`의 고정 로그 기반 실환경 통합 실증. 실제 공격 트래픽 실측이 아니다. 검증용 임시 Grafana는 문서상 정리됐다.
- B 공개 증거의 Logs Insights 5개 쿼리는 모두 Complete, Grafana 데이터소스 응답 5개는 status 200이었다. 대응 2.7042초·enhanced 1건·타임라인 8행은 그 과거 구간의 값이며 이번 실측 결과에 합치지 않는다.
- [보안 P5-3](../security/2026-10-30-p5-3-llm-executive-report-evaluation.md): 제공된 SSH·Web 보고서 각 1건의 전문·근거·화면 검수. 배포·추론·Slack은 사용자 제공 실측이고 네트워크 왕복 캡처 증거는 아니다.
- [P4 보고서](2026-10-25-p4-3-final-showcase-verification.md), [L4/L7 비교](2026-10-21-l4-vs-l7-propagation-latency-analysis.md), 기존 SSH·WAF 재실측은 별도 과거 실행이다. 이전 첫 공격 기준 지연을 현재 SLA로 재사용하지 않는다.

## 4. 최초 점검 이력과 승인 범위

아래 표는 자격증명과 호출 규격을 전달받기 전의 점검 이력이다. 현재 준비 상태는 4.2절로 갱신한다.

| 항목 | 현재 확인 범위 | 실행 전 필요한 확인 |
| --- | --- | --- |
| 공격 노드·타깃 | 사용자로부터 인스턴스 ID·공인 IP·Baseline SG 수신. 공격 노드 IMDS의 인스턴스 ID·리전 일치 및 계정/VPC 값 확보 | 타깃의 계정·VPC·현재 주소/리소스 대응의 관리 API 확인 |
| 리전·배포 | 사용자가 ap-southeast-2 지정, 저장소는 #241 머지 기준 | 실제 함수 버전·코드 해시·배포 상태·기준 코드 대응 |
| SSH 경로 | 지정된 키 파일은 없음. 사용자가 기존 PEM의 해당 인스턴스 사용을 확인했고, 인코딩 사본으로 ubuntu 접속 성공 | 최초 관측 host key의 독립 지문 확인 범위는 미확인. 이후 접속은 같은 지문을 강제 |
| 공격 도구·권한 | Hydra·tcpdump·TShark·curl 존재, `sudo -n true` 성공 | 기존 러너의 실제 도구 호환성·캡처 준비·baseline 가드는 실행 전 별도 확인 |
| Python 런타임 | 최초 3.10.12 제약을 확인한 후 사용자 전용 경로에 Python 3.12.16 준비·체크섬/실행 확인. 시스템 Python 보존 | 실제 실행 시 준비한 런타임의 절대 경로/PATH 사용 |
| AWS 조회 | Windows·Kali·공격 노드에서 안내 프로필/세션을 찾지 못함. 공격 노드 IAM info는 IMDSv2 HTTP 404, AWS CLI·boto3 없음 | 실제 조회 프로필 호스트/경로 또는 A/B 담당자의 원본 제공 경로 |
| A 복구 | 사용자가 준비 완료 선택 응답 | 담당자·시간대·실제 사건 ID 유지·L4/L7 복구·3차 알림 절차와 기록 |
| B 수집 | 기존 로그 그룹·대시보드 JSON 확인 | 현재 CW Agent·구독·계정 상태, WAF 원문 및 동일 사건 Slack 조회 경로 |
| Grafana | 후속 준비로 127.0.0.1:3000에 인증 활성화. 익명 대시보드 401·인증 API 200·기존 4개 패널 확인 | AWS 읽기 전용 인증 연결·실제 데이터 조회·화면 대조 |
| Web 대상 | 사용자가 기존 허용 ALB와 HTTP 80을 지정 | 현재 DNS·WAF 연결·정상 HEAD·허용 origin 검증. 아직 요청하지 않음 |
| SSH 키 인증 | 카드 DoD에 포함됨 | 공격용 오답 계정과 별도로 인증 확인용 계정·키·허용 명령·host key 확인 |
| 승인 파일·증거 경로 | 기존 16KiB·최대 24시간 유효기간·소유권 가드 유지 | 현재 대상/출발지·승인자·유효시간·0700 원격 증거 루트 |

개인키·비밀번호·토큰 값은 문서나 이슈에 기록하지 않는다. 최초 로컬 지정 키·AWS 설정 누락은 Get-Item으로 `not_found`를 확인했으며 접근 거부로 추정하지 않았다. 기존 Kali의 기본 및 /home 사용자 경로에서도 안내 파일을 찾지 못했다. 이후 사용자가 지정한 키 사본과 로컬 AWS 프로필을 사용한다.

최초 SSH 점검은 OpenSSH의 `invalid format`·`Permission denied (publickey)`와 종료 코드 255로 실패했다. 원인은 기존 PEM의 UTF-16 인코딩이었다. 원본 바이트를 보존하고 Git 밖 새 파일에서 UTF-16→ASCII/LF 변환 후 암호화 라이브러리로 파싱 가능함을 확인했다. 같은 키의 사본으로 접속은 성공했다. 키 원문·사본·키 해시는 공개 자료에서 제외한다. 호스트 키는 최초 관측값을 별도 비공개 known_hosts에 기록했고 후속 접속은 StrictHostKeyChecking=yes를 사용했다.

읽기 전용 명령으로 도구 존재·버전, 로컬 라우팅 조회, 비대화형 sudo, IMDSv2 자기 인스턴스 식별/VPC/IAM 정보 상태만 확인했다. IAM 자격증명 엔드포인트는 조회하지 않았다. 최초 점검에서는 타깃 SSH/HTTP 요청·Hydra 공격·캡처·설치·복구·AWS 관리 API를 실행하지 않았다. Python 3.10은 기존 모듈의 `from datetime import UTC`도 지원하지 않아 후속 준비에서 별도 Python 3.12를 설치했다. 이는 관측된 환경 제약이며 별도 코드 수정 사유로 범위를 넓히지 않는다.

## 4.1 사용자 후속 요청에 따른 실행 환경 준비

사용자가 “준비할 수 있는 것은 준비”하도록 요청한 뒤 다음 작업을 수행했다. 실제 공격·타깃 탐침·패킷 캡처·AWS 관리 API·복구는 실행하지 않았다.

- [공식 Python 배포본](https://github.com/astral-sh/python-build-standalone/releases/tag/20261026)의 CPython 3.12.16 Linux x86_64 아카이브 34,505,639바이트를 새 사용자 경로에 설치했다. GitHub 공개 digest와 SHA-256 `ce4f6d0a6cfdb3bed6e44c2f9affd85943c76a42e25ad3a259002f31d6fb8a20` 일치를 확인했다. 다운로드 40MiB/120초·해제 512MiB/20,000항목 상한과 경로 이탈 방어를 적용했고 시스템 Python은 변경하지 않았다.
- 기준 커밋 822fdc1의 네트워크 자산 8개를 Git blob 바이트 그대로 배치했다. 로컬 패키지와 원격의 SHA-256 `22d2ed0c0257469cc47b8711b8b10520886f8016426059dc2555f5c86a304750` 및 개별 파일 해시를 대조했다. 기존 코드·상수·승인 가드는 수정하지 않았다.
- 셸 3개 문법 검사, 기존 check_hydra의 SSH 모듈/-K 확인, 통합 러너 all dry-run 및 roundtrip_timeline.py --help가 모두 종료 코드 0이었다. 실행 증거 디렉터리는 비어 있으며 승인 파일을 만들어 넣지 않았다.
- 실제 캡처 시 sudo가 필요하므로 별도 root 소유 0700 증거/승인 디렉터리를 준비했다. root 실행 환경에서 기존 private_root·validate_evidence_root 검사를 통과했고 ens5 인터페이스를 목록으로 확인했다. 캡처를 시작한 결과는 아니다.
- NTP=yes·NTPSynchronized=yes를 확인했다. 장비 간 최대 시계 오차는 미측정이므로 null을 유지한다. 원격 여유 공간 약 5.44GB와 3GiB 캡처 여유 기준을 확인했다.
- 기존 지정 이미지 Grafana 11.2.0을 127.0.0.1:3000에 기동했다. A 프로비저닝·B 대시보드를 읽기 전용 마운트하고 익명 접근을 껐다. 임의 생성 관리자 비밀번호는 Git 밖 사용자 전용 파일에만 보존했다. AWS 자격증명은 마운트하지 않았고 EC2 metadata credential discovery도 비활성화했다.
- Grafana health/database=ok, 익명 대시보드 401, 인증 후 기존 cloudshield-p5-2 대시보드·cloudshield-cloudwatch 데이터소스 API 200을 확인했다. 기존 패널 4개/쿼리 5개가 로드됐다. AWS 연결·실제 쿼리·브라우저 화면 렌더링은 미검증이다.

[후속 공개 준비 증거](evidence/p5-4/preparation-2026-10-30/environment-preparation.public.json)에 원본 파일별 해시·선별/마스킹·준비 결과를 기록했다. 원격 원본 7개를 새 비공개 로컬 폴더로 회수해 전송 전후 바이트 수·SHA-256 일치를 확인했고, 별도 보존 manifest와 Grafana 검증 원본도 보존했다. 공개 JSON의 UTF-8/LF Git blob SHA-256은 `5310f572e8adb8fddc39f3104f56e2d3a36cfbd9f3d616ce276185b1fe5282db`다.

후속 승인과 현재 남은 원본 요청은 [전달 요청문](p5-4-team-handoff.md)으로 갱신했다. 팀원에게 메시지를 발송하지 않았다. 준비한 Grafana/런타임을 현재 왕복 성공·10초 SLA로 집계하지 않는다.

## 4.2 단일 컨트롤러와 AWS/Grafana 연결 준비

사용자는 A가 제공한 기존 SG 복구·단일 IP WAF 해제·B의 3차 Slack 호출 규격을 로컬 컨트롤러에서 연결하도록 승인했다. 공격 노드에는 AWS 키·Slack 웹훅을 전달하지 않는다. 새 복구 엔진은 만들지 않고 A의 `restore_baseline_security_group`, `unblock_ip_wafv2` 및 B의 `send_recovery_slack_alert`를 그대로 호출한다. IPSet ID를 명시해 ListIPSets 추가 권한을 요구하지 않는다. 전체 차단 목록 해제와 IAM 변경은 사용하지 않는다.

Grafana에는 사용자가 전달한 A의 Direct SDK Credentials 방식으로 로컬 프로필 자격증명을 컨테이너 환경에 주입했다. 기존 provision/dashboard 파일은 읽기 전용으로 유지한다. 동일 IAM 사용자는 복구 쓰기 권한도 있으므로 IAM 차원에서 조회 전용인 계정이라고 표현하지 않는다. Grafana 준비 검증에서는 조회만 실행했다. GetFederationToken의 AccessDenied는 직접 인증 경로의 필수 권한 문제가 아니다.

최종 실제 preflight에서 STS 신원·현재 타깃·공격 IP 차단 부재·원격 노드·필수 로그 그룹·Grafana 조회를 확인했다. 기존 5개 쿼리(1A/1B/2A/3A/4A)는 모두 Complete이며 익명 대시보드는 401이다. Slack 웹훅은 비공개 파일의 형식만 확인했다. WAF Update는 소유자 승인 범위지만 실제 호출 전이므로 권한 성공을 실증하지 않았다. [공개 선별 증거](evidence/p5-4/controller-2026-10-30/controller-preparation.public.json)에 실제 preflight 원본 해시를 연결한다.

타깃 키 등록은 TCP·HTTP 복구 데모의 필수 조건으로 요구하지 않는다. 현재 비공개 구성은 `require_key_auth=false`, preflight blockers는 0개다. 이 모드의 SSH 키 인증 결과는 null이며 P5 카드의 키 인증 DoD는 미충족으로 남는다. 전체 카드 검증이 필요하면 별도 승인 계정·공개키 등록·검증된 host key가 필요하다.

기본 plan은 네트워크를 사용하지 않는다. preflight는 조회/DryRun만 한다. 유효한 기존 승인 파일과 run --execute를 함께 지정해야 실제 실행된다. 유효 승인 파일은 아직 만들지 않았고 실제 공격·타깃 탐침·캡처·복구·Slack 전송은 모두 미실행이다. 컨트롤러는 실제 서버 사건 ID가 유일하게 연결될 때만 3차 카드를 보내며, 부분 복구·전송/저장 실패·캡처 조기 종료를 전체 성공으로 처리하지 않는다.

## 5. 유한 실행 계획

반복 횟수는 SSH 1회·Web 1회를 제안한 상태다. 자동 재공격은 없으며 실패 회차를 보존한다. Web은 SSH의 복구·정상성·잔존 윈도우 영향 확인 후 별도 실행 ID로 시작한다.

| 단계 | 상한과 관측 |
| --- | --- |
| SSH 공격 | 기존 합성 오답 5개·동시성 1·Hydra 응답 대기 10초·공격 60초 |
| SSH 기본 계측 | 기존 내부 캡처 75초·2,000패킷·탐침 최대 60회·간격 1초·connect 0.8초 |
| SSH 연속 캡처 | 별도 파일로 baseline 전부터 최대 120초·2,000패킷. 내부 캡처와 독립 해시 |
| SSH 키 인증 | 현재 선택 해제. require_key_auth=true인 별도 승인 구성에서 회복 후 1회·최대 5초. baseline 인증은 자동 검증하지 않음 |
| Web 공격 | 후보 GET 15개·동시성 1·응답 후 1초 간격·개별 3초·전체 60초 |
| Web 정상 탐침 | 동일 origin 루트 HEAD baseline 1회·공격 중 최대 60회·connect/요청 각 1초 |
| Web 연속 캡처 | 승인 시점 ALB IPv4 최대 2개에 기존 캡처기를 각각 실행·각 120초/2,000패킷. 실제 요청 목적지가 범위 밖이면 완전성 미확인 |
| 복구 관측 | 로컬에서 A의 기존 승인 함수를 호출하고 구성을 재조회. 탐침 최대 20회 또는 30초이며 시나리오 시작 기준 112초까지 관측. SSH RPC를 포함하므로 탐침 간격은 정확한 1초로 간주하지 않음 |
| 시간 한도 | 연속 캡처 T0 기준 A 복구 시작 +85초·구성 확인 +105초 이내 준비를 제안. +120초에 미관측이면 미완료로 종료 |
| 관제 조회 | 해당 실행 전후 1분과 분 경계를 포함한 고정 범위. 패널 5개 쿼리·사건 메트릭·WAF 원문·같은 사건 Slack 3단계 대조 |

복구 시간 한도는 관측 준비 조건이며 플랫폼 SLA가 아니다. A의 대응 가능 시간 합의가 필요하다. 기존 Web HEAD는 매번 별도 curl 프로세스이므로 keepalive를 보장하지 않는다. 동일 연결의 응답 전이를 필수로 증명하려면 기존 curl 지원·요청 수·시간 상한을 확인한 구체적인 유한 실행안을 추가 확정한다. 관측하지 않은 재사용 연결을 문서로 만들어 넣지 않는다.

실제 출발지·대상·승인 불일치, 예상 밖 인증 성공, baseline 실패, 캡처 조기 종료·디스크/저장 오류, 시각·해시 모순, 상한 초과, 담당자 중단 요청이면 멈춘다. 소유 프로세스만 정리한다. 공격 요청 후 실패하면 승인된 단일 대상의 기존 A 복구 함수를 시도하고 후속 공격을 시작하지 않는다. IAM·Terraform·배포 변경은 수행하지 않는다. 다른 직무·채널에 메시지를 보내지 않았다.

## 6. 현재 왕복 판정과 계산 기준

아래 null은 실제 실행의 실패값이 아니라 **실행 자체가 없어서 확보하지 않은 값**이다. 현재 실행 run_id·incident_id·PCAP·원본 관측은 생성되지 않았다.

| 시나리오 | baseline / 첫 공격 / 차단 후보 / A 복구 / 첫 정상 회복 | 차단 관측 지연 | 차단 유지 관측 구간 | 복구 처리 관측 지연 | 판정 |
| --- | --- | --- | --- | --- | --- |
| SSH | 모두 null | null | null | null | 미실행 |
| Web | 모두 null | null | null | null | 미실행 |

계산에는 기존 roundtrip 입력 manifest와 실제 원본을 참조하는 sidecar를 사용한다. 상위 run_id·SSH 하위 run_id·incident_id·시나리오·대상·시간·해시·원본 좌표를 대조한다. 선언한 사건 ID만 있고 서버 근거가 없으면 직접 연결 완료로 쓰지 않는다.

| 지표 | 정확한 시작 → 끝 | 현재 한계 |
| --- | --- | --- |
| 차단 관측 지연 | 첫 실제 공격 패킷/HTTP 요청 → 첫 timeout/403 후보 확인 | 호출 시각·정책 API 반환·정확한 정책 적용 순간과 구분 |
| 차단 유지 관측 구간 | 첫 차단 후보 → 복구 후 첫 정상 통신 | Notion T2−T1. 복구 실행기 처리 시간으로 이름 붙이지 않음 |
| 복구 처리 관측 지연 | A의 실제 복구 실행 시작 → 첫 정상 통신 | 시작 원본 없으면 null. 요청 시각으로 대체하지 않음 |
| 서버 대응 구간 | detected_epoch → remediated_epoch | ThreatRemediatedMetric·duration_seconds와 비교하되 첫 공격→물리 차단 SLA와 구분 |

UTC·원문·원본 해상도를 보존하고 Decimal로 계산한다. 초 단위 원본에 밀리초를 추가하지 않는다. 장비 간 최대 시계 오차는 미측정 상태이므로 null이다. 탐침 간격·timeout·양자화·로그 수집 공백을 표시하며 단조 경과 시간을 다른 장비 wall time과 빼지 않는다. 음수 구간·동일 시각의 상반된 관측·서로 다른 대상/회차는 임의 보정하지 않는다.

10초 SLA는 현재 **미평가**다. 첫 실제 공격 기준과 탐지 조건 누적 이후 기준을 나눠 기록한다. API 성공·Grafana p95·Slack 게시·엔진 복구 보고만으로 물리 차단·독립 통신 회복·멱등성을 선언하지 않는다.

## 7. 패킷·서버·관제 대조에 필요한 원본

| 구간 | 네트워크 원본 | A/B 원본과 대조할 항목 |
| --- | --- | --- |
| 정상·공격 | baseline SYN/SYN-ACK/ACK, 실제 공격 stream/HTTP 요청, 호출 기록 | 타깃·출발지·전용 계정·수집 원문·실제 탐지 조건 |
| 마지막 정상·첫 후보 | 마지막 정상 handshake/HTTP 200, 신규 무응답 SYN·재전송·timeout 또는 루트 403 | 실제 incident_id·ThreatRemediatedMetric·API 요청/응답·WAF BLOCK/규칙/요청 ID |
| 복구·회복 | 캡처가 유지된 상태의 정상 handshake·키 인증 또는 동일 루트 HTTP 200 | A 요청/실행 시작/완료·구성 재조회·3차 카드 원문과 원본 ts |

실측 후 SYN/ACK/RST/FIN·3-Way Handshake·재전송·무응답을 frame/stream·UTC·방향 표로 구조화한다. 지금은 실제 프레임이 없어 패킷 행을 작성하지 않는다. 정상 종료 RST/FIN을 SG 차단으로, timeout/5xx를 WAF BLOCK으로, TCP 성공을 SSH 인증 성공으로 바꾸지 않는다.

Grafana는 B JSON의 UID `cloudshield-p5-2`, 데이터소스 `cloudshield-cloudwatch` 및 실제 로그 그룹·쿼리와 대조한다. `bin(1m)`의 집계점이 표시 범위에 들어오도록 분 경계를 포함한다. 쿼리 상태·필터·행 수·페이지·중복·누락을 남기고 No data/실패/미수집을 0건으로 처리하지 않는다. 표본 1건의 p95·100%를 운영 성능으로 확대하지 않는다.

Slack은 동일 사건의 원문·ts·실제 게시 순서를 확인한다. 2차 전송과 enhanced/Fallback은 별개이며, 3차 엔진 보고와 독립 통신 회복도 별개다. 수동 재전송으로 순서를 맞추지 않고 게시 시각을 사용자 단말 수신 시각으로 쓰지 않는다.

## 8. 증거 보존과 공개 경계

실제 공격 실행의 원본·공개 파생 증거는 아직 없다. 향후 원본은 Git 밖 실행별 새 경로에 보존하고 회수 전후 SHA-256을 비교한다. 공개 선별본에는 실제 IP·계정 ID·전체 ARN·서명 URL·토큰·개인키를 넣지 않는다. 원본/공개 선별본 해시·변환 방식·행/frame/로그 좌표를 각각 남긴다. 요약 JSON도 공개 전 검수한다.

이번 준비 점검의 [공개 선별 JSON](evidence/p5-4/preflight-2026-10-30/attacker-preflight.public.json)은 공격 증거와 분리한다. 원본 3개는 Git 밖 `CloudShieldEvidence/p5-4-preflight-20261030T062725Z/`에 보존했다. 원격 Python의 JSON stdout을 로컬 SSH 클라이언트에서 수신하여 UTF-8/LF 파일로 저장한 바이트의 해시다. 원격 파일을 회수한 PCAP이나 AWS API 전체 응답이 아니다. 시각·사건·SLA를 만들어 넣지 않았다.

| 준비 점검 증거 | SHA-256 | 선별 좌표/범위 |
| --- | --- | --- |
| 비공개 `attacker-preflight.private.json` | `a502c06cb88ed517c7fcdb09197938952d9e5f3138f28a987f0270f1afe7db6c` | metadata.instanceId/region, tools, aws_files, profiles, sudo_noninteractive |
| 비공개 `attacker-metadata.private.json` | `d37065e69b4dbeb4eb9c875578053264cc108bf8c04ae7f997b7962b83c67062` | vpc_ids 개수, tool_versions, aws_session_env_present. IAM 오류 종류는 다음 원본의 상태로 보완 |
| 비공개 `attacker-runtime.private.json` | `2d91ff42e8c665475da64c637ef25fd11ce48994e50f1fd28ff91c7b5912d9e1` | alternate_runtimes, iam_info_http_status=404, curl_rate_supported=false |
| 공개 `attacker-preflight.public.json` | `05117c8fbfc0c199769b967b0683fe622f3b2b92c2c45977a8d5255b760b5b04` | 위 자료의 버전·준비 여부·해시·한계. IP/계정/인스턴스/VPC/원본 경로·키 제외 |

최초 SSH 실패 코드는 도구 출력의 관측 내용을 전사한 것이며 별도 SSH stderr 원본 파일이 보존됐다고 주장하지 않는다. 공개 JSON은 그 출처를 표시한다. 공개 JSON 해시는 생성한 UTF-8/LF 바이트 및 저장소 Git blob 기준이며, Windows 체크아웃의 CRLF 변환 후 작업 파일 해시와 다를 수 있다. 준비 점검에는 실제 사건 ID·공격 run_id·차단·회복·SLA가 모두 없으며 null/미실행으로 남긴다.

정찰에서 기존 비공개 P4 PCAP 5개를 다시 해시하여 [P4 보고서](2026-10-25-p4-3-final-showcase-verification.md)의 기록과 일치를 확인했다. 다음은 **과거 파일 보존 확인**이며 P5-4 왕복 증거가 아니다.

| 과거 파일 식별 | SHA-256 |
| --- | --- |
| N1 공격 PCAP | `a619f5d16bf7c073e08c0e59f92a12ac2e7fa5b14b16e22575032de17b6e1a8c` |
| N2 공격 PCAP | `898d02efd03f0ecf9a039ce5d03acb4bb1cec5ae3c04714227a11454fb03290e` |
| N3 공격 PCAP | `f248368781f68749a80094d66059ee5eea2aa8ce238185938396482d08b8266f` |
| N1 이후 복구 확인 PCAP | `58f121d6f4e4df7fa8b6b1e83a64f33590f124003c9037f84500d8c83865bb7b` |
| N2 이후 복구 확인 PCAP | `d239be72302c8ce5adfa81caf1cd8a2b3141a6a585f961a534a730828801faaa` |

해시 일치는 바이트 보존·파일 식별의 근거다. AWS 출처의 독립 인증·전체 추출·패킷 무손실을 증명하지 않는다.

## 9. 품질 검증과 잔여 DoD

필수 명령은 `powershell .\scripts\check.ps1`이다. 최초 실행은 R&R 통과 후 테스트 경로 재귀 조회에서 기존 `C:\Aleph\.pytest_cache` 접근 권한 오류로 종료 코드 1이었다. Ruff·pytest까지 실행되지 않았으므로 이 실행을 통과로 집계하지 않는다. 전체 출력은 Git 밖 임시 경로의 `cloudshield-p5-4-check-20261030T151742.log`에 보존했다.

기존 캐시·검증 스크립트·테스트를 변경하지 않고 관리 worktree `network-p5-4-validation/Aleph`를 기준 커밋 `822fdc1c8ea0be75d921a989302dc5e6b240e9f9`에서 새로 만들었다. 문서 초안 1개만 적용하고 `uv sync --all-extras --locked` 후 **동일 명령**을 우회 플래그 없이 실행했다. 역할은 AGENT_ROLE=network, Windows·Python 3.14.7·pytest 8.4.2이며 프로젝트의 허용 Python 범위 안이다.

- R&R·표준 테스트 경로·Ruff lint 통과, Ruff format 172개 파일 통과.
- pytest: **1555 passed, 4 skipped, 1 warning, 189.71초**, 종료 코드 0.
- skip 4개는 기존 네트워크/WAF Terraform mock 준비 조건이며, warning 1개는 기본 소켓 DNS 차단을 확인하는 smoke 테스트다. 미실행 IaC 검증을 통과로 확대하지 않는다.
- 전체 출력: Git 밖 임시 경로 `cloudshield-p5-4-validation-20261030T152215.log`.
- 잠금 파일 SHA-256: `c2fbbe69b15e457557dbcfe6a0354d7cdf34f87dac822e4d16d658ba0b51a7ca`.
- 이후 준비 관측·게이트 결과·공개 선별 JSON만 문서에 반영했다. 최종 파일의 JSON 파싱·출처/해시·상대 링크·마스킹·R&R·diff를 별도 확인한다. 제품 코드·테스트·의존성은 그대로다.

후속 환경 준비·전달문·공개 증거 4개를 같은 기준 커밋의 기존 검증 worktree에 적용하고 필수 명령을 재실행했다. 결과는 R&R·표준 경로·Ruff lint·format 173개 통과, **1555 passed, 4 skipped, 1 warning, 184.62초**, 종료 코드 0이다. 전체 출력은 Git 밖 `cloudshield-p5-4-prepared-check.log`에 보존했다. 기존 제품 코드·테스트·공통 의존성을 수정하지 않았다. 이후 이 검증 결과만 문서에 추가했다.

기존 PR 커밋 d5900df의 [CI run 41015277970](https://github.com/mmmphyun/aleph-project/actions/runs/41015277970)은 Terraform mock 초기화를 포함해 **1559 passed, 1 warning**, 성공했다. 후속 준비 커밋의 최신 CI는 PR checks와 최종 안내에 별도로 기록한다.

후속 승인 범위의 네트워크 컨트롤러와 회귀 테스트를 추가했다. 실제 AWS 대신 모의 전송과 moto로 단일 대상 복구·다른 IP 보존·부분 장애·사건 연결·저장 실패·승인 재사용·캡처 수명·Grafana 인증/완료 상태를 검증했다. 필수 동일 게이트는 **1590 passed, 4 skipped, 1 warning, 201.19초**, 종료 코드 0이다. Git 밖 cloudshield-p5-4-controller-check.log에 출력을 보존했다. 검증 게이트·의존성·타 직무 테스트는 변경하지 않았다. 최신 CI는 PR checks 참조.

- [ ] 승인된 현재 대상·배포·수집·인증 환경과 A 복구 절차 확정
- [ ] SSH 전체 왕복 PCAP·키 인증 회복·프레임 분석·양측 사건 연결
- [ ] Web 전체 왕복 PCAP·루트 정상 회복·WAF BLOCK 원문·연결 재사용 검증 범위
- [ ] 동일 사건 Grafana·CloudWatch·Slack 3단계 대조 및 실제 원본 해상도 평가
- [ ] 각 지연·첫 공격 기준 10초 SLA·시계 오차·복구 구성/통신/멱등성의 확인 범위 고정
- [ ] 현재 실행 원본/공개 증거 목록·별도 해시·선별/마스킹 이력
- [x] 동일 기준 커밋의 분리 환경에서 필수 품질 게이트 실행·결과 기록
- [x] 기존 PR 커밋의 CI 결과 기록; 후속 준비 커밋의 최신 상태는 PR checks 참조

미확보 조건을 과거·합성 자료로 채우지 않는다. DoD 미충족 상태로 PR을 제출하면 Draft로 명시하고 리뷰어 `gkacksdnjs22-stack`을 지정한다. Notion 상태는 GitHub Actions가 전담하며 별도 요청 전 머지하지 않는다.
