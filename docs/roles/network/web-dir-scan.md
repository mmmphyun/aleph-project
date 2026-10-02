# Web 디렉터리 모의 스캔 실행 가이드

이 실험은 합성 경로를 짧은 시간에 요청해 HTTP 경로, 상태 코드, 요청 빈도에 남는 L7 흔적을 확인하기 위한 것이다. TCP 플래그 기반 SG 분석이나 실제 WAF 차단 실험은 포함하지 않는다.

## 현재 연계 범위와 후속 티켓

이 스크립트는 로컬 테스트 HTTP 대상의 요청 계획과 HTTP 상태 코드·요청 수 증거를 다룬다. 2026-10-02 main `7fbe19e` 기준 Web 룰과 Nginx 파서는 구현되어 있어 이번 보완에서는 모의 요청·응답을 기존 파서 및 룰에 연결한다. 운영 CloudWatch 전달, `IncidentReport` 생성, 자동 차단 또는 10초 E2E 성공을 검증한 것은 아니다. main 오케스트레이터의 진입점은 아직 SSH 로그 중심이다.

- HTTP 로그 수집 경로 명세: 클라우드 B [Nginx access.log CloudWatch Agent 수집 Issue #82](https://github.com/mmmphyun/aleph-project/issues/82)
- HTTP 로그 라우팅·디코딩: 클라우드 B [CloudWatch 멀티 스트림 및 Nginx 페이로드 디코더 Issue #95](https://github.com/mmmphyun/aleph-project/issues/95)
- Web 탐지 룰 연계: 보안 [Web L7 시그니처 설계 Issue #98](https://github.com/mmmphyun/aleph-project/issues/98) 및 [후속 탐지 구현 Notion 티켓](https://notion.so/3e904d37c2258110b345fd5d1999a244)

## 준비와 dry-run

Git Bash에서 저장소 루트 기준으로 실행한다. 기본값은 `curl`, 후보 10개, 동시성 1, 요청당 제한 시간 3초이며 요청을 보내지 않는다.

```bash
bash network/web_dir_scan.sh --url http://127.0.0.1:8080
bash network/web_dir_scan.sh --url http://127.0.0.1:8080 --tool gobuster --candidates 10 --concurrency 2 --timeout 3
```

## 명시적 실행

로컬에서 직접 관리하는 테스트 HTTP 서버를 준비하고, 대상 포트가 의도한 서비스인지 확인한다. 실제 요청은 `--execute`가 있어야 시작된다. 숫자형 `127.0.0.1` 또는 `[::1]`만 허용하며 DNS 이름, 외부 주소, URL 사용자 정보, 쿼리, fragment, 추가 경로는 거부한다. 프록시는 비활성화한다. Docker 대상이나 별도 승인 테스트 대상은 현재 스크립트가 직접 소유·검증할 수 없으므로 지원하지 않는다.

```bash
bash network/web_dir_scan.sh --url http://127.0.0.1:8080 --candidates 5 --timeout 2 --evidence ./web-dir-evidence.txt --execute
bash network/web_dir_scan.sh --url http://127.0.0.1:8080 --tool gobuster --candidates 5 --concurrency 2 --timeout 2 --evidence ./gobuster-evidence.txt --execute
```

후보는 스크립트 내 합성 경로 20개로 고정한다. 후보 수는 1~20, gobuster 동시성은 1~4, curl 동시성은 1, 요청 제한 시간은 1~10초다. 리다이렉트를 따라가지 않으며 인증 정보나 응답 본문을 저장하지 않는다. curl은 아래의 `--paths`로 기존 후보의 순서·반복을 선택할 수 있다.

## 중단·증거·정리

터미널에서 `Ctrl+C`로 중단한다. 스크립트가 생성한 curl/gobuster 또는 간격 대기 프로세스와 임시 출력·wordlist를 정리하며 다른 프로세스나 파일은 건드리지 않는다. 중단, 요청 timeout, 도구 부재, 연결 실패는 증거 파일의 `state`와 `exit_code`로 구분한다. 종료 시 TERM 후 최대 약 1초의 정리 유예를 두고 남은 소유 PID를 KILL한다.

증거는 `--evidence`로 지정한 경로에 새로 생성된다. 생략하면 현재 디렉터리에 `web-dir-scan-<UTC 시각>-<PID>.txt`가 생성된다. 기존 파일은 덮어쓰지 않는다. 시작·종료 UTC 시각, 계획·시도 요청 수, 관측 상태 수, HTTP 200/301/302/403/404/기타 분포를 기록한다. curl은 각 요청의 실제 시도 수와 상태 코드를 집계한다. gobuster는 내부 사전 검사 요청과 필터링 때문에 실제 시도 수를 확정할 수 없어 `attempted_requests=unknown`으로 표시하며, 404는 wildcard 사전 검사와 충돌하므로 결과에서 제외한다. 404 분포가 필요하면 curl 모드를 사용한다. 필요한 증거만 검토·보관하고, 실험 종료 후 본인이 만든 증거 파일을 직접 삭제한다.

SG conntrack 동작 분석과 WAF 403 이후 FIN/RST 패킷 분석 및 PCAP 보고서는 각 전용 후속 티켓에서 다룬다. 이 가이드로 실제 SG 교체나 WAF 차단을 수행하지 않는다.

gobuster가 일부 응답 후 실패하거나 사용자 중단·전체 실행 제한 시간에 도달해도, 소유 프로세스를 종료한 뒤 이미 출력한 합성 후보의 200/301/302/403 결과를 한 번 집계한다. 진단 문구와 필터 밖 404/기타 코드는 관측 수에 포함하지 않는다. 도구 종료 코드 130/143은 `interrupted`, 28/124는 `timeout` 및 증거 종료 코드 124로 기록한다. 1/6/7은 `connection_failure`, 그 밖의 비정상 종료는 `tool_error`로 기록하며 원래 종료 코드를 보존한다. 실제 gobuster의 종료 코드 1만으로 세부 실패 원인을 확정할 수는 없다.

## Web 임계조건 재현 보완 (#124)

[노션 티켓](https://notion.so/3eb04d37c22580b1aac4d0e2eb17c6a0)을 읽기 전용으로 확인했다. 본문은 빈 작업 템플릿이므로 별도 상세 정책은 없었다. 기존 구현에서 확인한 사실은 아래 표이며, 구현 범위는 기존 후보 재조합·간격·실행 한도와 부족한 모의 테스트 보완이다. 보안 임계값과 수집 설정을 변경하지 않는다.

### 현재 코드에서 확인한 조건

| 항목 | main 기준 동작 |
| --- | --- |
| 의심 경로 | 첫 세그먼트가 admin/login/dashboard/api/backup/config/private/internal/debug/status/metrics/old/test인 경로. 하위 경로도 해당한다 |
| 기본 후보 중 제외 | health, robots.txt, sitemap.xml, uploads, images, static, assets. 기본 앞 5개는 health를 포함하므로 의심 고유 경로는 4개다 |
| 별도 우선 룰 | 경로 탈출은 PATH_TRAVERSAL, 민감 파일은 SENSITIVE_FILE_PROBING으로 디렉터리 열거보다 먼저 반환된다. 이번 CLI는 기존 후보만 허용한다 |
| 정규화 | 계약 파서가 percent decode 1회, 룰이 추가 1회 수행 후 `?` 이후를 제외한다. `+`, 중복 슬래시, `..`, 경로 대소문자를 고유 키에서 통일하지 않는다. 의심 첫 세그먼트 비교만 casefold한다 |
| 고유 경로 | 동일 출발지 IP·현재 슬라이딩 창에서 정규화된 전체 경로의 서로 다른 개수. `/admin/a`와 `/admin/b`는 별개이며 같은 경로의 반복은 1개다 |
| 실패 경로 | 그 창에서 401/403/404를 한 번 이상 받은 의심 고유 경로 수. 같은 경로의 성공 응답이 실패 이력을 취소하지 않는다. 실패 이벤트가 창 밖으로 나가면 실패 집계에서 빠진다 |
| 시간 | Nginx `timestamp_str`을 초 단위로 파싱해 IP별로 정렬. 차이가 10초를 **초과**할 때만 제거하므로 양 끝 포함. 고유 5개 이상과 실패 고유 3개 이상이 동시에 필요하다 |
| 호출 간 상태 | `evaluate_web_rules`는 상태를 보존하지 않는다. 배치 분할 누적·영속 중복 제거는 플랫폼 책임이다 |

HTTP 의미와 룰의 실패 분류를 혼동하지 않는다. 200은 성공, 301/302는 리다이렉션, 401은 인증 필요, 403은 접근 거부, 404는 자원 없음이다. 429는 요청 제한, 5xx는 서버 오류지만 **현재 열거 룰의 실패 집합에는 없다**. 따라서 룰 관점에서는 401/403/404 외의 코드가 모두 실패 집계에 미포함이며, 그것을 모두 HTTP 성공이라고 부르지 않는다. 000·연결 실패·timeout은 유효한 관측 HTTP 응답으로 세지 않는다. 기존 증거 포맷에서 401/429/5xx는 `http_other`에 들어가므로 이 요약만으로 실패 고유 경로 수를 복원할 수 없다.

### 요청 계획 사용법

기존 `--candidates`와 기본 후보 순서는 그대로 유지한다. curl 전용 `--paths`는 슬래시 없는 기존 후보명을 쉼표로 연결하며 1~20개, 최대 512자다. 중복과 순서를 보존한다. `--candidates`와 함께 지정하거나 임의 경로·쿼리·인코딩·인증 정보 등을 넣으면 실행 전에 거부한다. 원시 입력은 오류 메시지에 출력하지 않는다.

`--interval 0..11`은 이전 요청 완료 후 다음 요청까지의 대기 초이며 기본 0이다. `--max-runtime 1..300`은 전체 요청 실행 단계의 한도로 기본 205초다. 최소 대기 합계 `(요청 수-1) × interval`만으로 한도를 소진하면 거부하며, 실제 응답 지연으로 한도를 넘으면 중단한다. 준비·종료 증거 기록 및 프로세스 정리 시간은 추가될 수 있다. 시계는 호스트 epoch 초를 사용하므로 시스템 시각 변경이 없는 실험 환경을 전제로 한다.

아래 명령은 모두 **dry-run**이다. 이번 검증에서는 실제 대상 접속을 하지 않았다.

```bash
# 의심 고유 경로 4/5/6개를 요청하는 계획: 실제 실패 응답 조건 충족은 별개다.
bash network/web_dir_scan.sh --url http://127.0.0.1:8080 --paths admin,login,dashboard,api
bash network/web_dir_scan.sh --url http://127.0.0.1:8080 --paths admin,login,dashboard,api,backup
bash network/web_dir_scan.sh --url http://127.0.0.1:8080 --paths admin,login,dashboard,api,backup,config
# 정상 후보 및 중복 요청: 요청 수와 고유 경로 수의 차이
bash network/web_dir_scan.sh --url http://127.0.0.1:8080 --paths admin,admin,login,dashboard,health
# 응답 시간이 0인 가정에서도 5개 경로의 첫/마지막 요청이 12초 간격
bash network/web_dir_scan.sh --url http://127.0.0.1:8080 --paths admin,login,dashboard,api,backup --interval 3 --max-runtime 30
```

실제 실행은 기존과 같이 승인된 본인 로컬 서버에서 `--execute --evidence <새 파일>`을 명시해야 한다. curl 동시성은 1로 유지한다. gobuster는 기존 동시성·후보 방식만 제공하며 사용자 경로 순서와 간격 지정을 거부한다. 내부 사전 요청·필터가 있어 정확한 열거 임계조건 비교에는 curl 계획을 사용한다.

| 모의 시나리오 | 기대 결과와 전제 |
| --- | --- |
| 의심 경로 4 / 5 / 6개, 모두 404, 같은 시각 | 미탐지 / 탐지 / 탐지 |
| 의심 경로 5개, 실패 고유 경로 2 / 3 / 4개 | 미탐지 / 탐지 / 탐지 |
| 의심 경로 5개, 401·403·404·200·302 | 룰 직접 호출은 탐지. 현재 수집 필터 이후는 경로 3개만 남아 미탐지 |
| 동일 경로의 실패를 3회 반복 | 실패 고유 경로는 1개이며 요청 수 3과 다르다 |
| health·정적 경로만 반복 | HTTP 실패 응답이어도 열거 대상 경로가 아니므로 미탐지 |
| 첫/마지막 이벤트 간격 9 / 10 / 11초, 의심 5개 모두 실패 | 탐지 / 탐지 / 미탐지 (중간 이벤트는 최초 시각) |

요청 시작 간격은 `interval + 이전 응답 소요 시간 + 실행 오버헤드`의 영향을 받는다. Nginx에는 서버 처리 시각으로 기록되므로 계획 간격만으로 시간창 충족을 보장하지 않는다. 동일 경로의 응답도 서버 상태에 따라 바뀔 수 있다. 모의 테스트는 격리 PATH의 가짜 curl/gobuster만 호출하고, 간격은 가상 시계를 전진시키며, 실제 파서·룰 함수를 호출한다. 도구 실패 시 실제 실행 파일로 폴백하지 않는다. 기존 HTTP 분포·부분 실패 테스트와 중복 구현하지 않고 이를 재사용했다.

### 담당자 간 연결 조건과 남은 한계

1. 클라우드 B: `nginx.conf`의 cloudshield_combined → `/var/log/nginx/access.log` → CW Agent의 `/cloudshield/target/nginx-access-log` 연결 설정이 있다. `/health`는 access_log가 꺼져 있다. 수집 필터는 401/403/404만 선택하므로 성공·리다이렉션까지 포함하는 룰의 고유 경로 집계와 차이가 있다. 전달 범위 정렬은 클라우드 B·보안 협업 사항이다.
2. 보안: `NginxAccessLogEvent.parse_line`과 `evaluate_web_rules`는 구현되어 있다. main의 `map_threat_to_incident`는 SSH 룰만 지원하며 Web 매퍼는 작업 시작 시 열린 PR #123에 있었다. 해당 변경을 가져오거나 정책을 대신 정하지 않았다.
3. 클라우드 A: main `threat_orchestrator_handler`는 `SyslogAuthEvent`와 `AuthFailureWindow`를 사용한다. Nginx 라우팅, Web 시간창의 배치 간 누적, Web 매퍼 호출 연결이 필요하다. `IncidentReport`의 BLOCK_WAF 액션과 WAF 차단 엔진은 존재하지만 Web 입력에서의 관통 실행 증거는 아니다.
4. 클라우드 B: `send_slack_alert`는 BLOCK_WAF 보고서에 WAF 카드를 선택할 수 있다. 보고서·실제 대응 결과가 연결된 후 필드 및 카드 조건 검증이 필요하다. 이번 작업에서 Slack 메시지는 보내지 않았다.

증거 파일은 기존 요약 형식을 유지한다. 요청별 경로·시각·상태나 고유 경로 판정을 저장하는 탐지 엔진을 네트워크 코드에 복제하지 않았다. 실제 관측을 판단하려면 별도로 승인된 서버 로그가 필요하며, 이번 결과는 운영 탐지·차단 또는 10초 E2E 성공을 의미하지 않는다. 협업 사항은 이 문서에만 정리하고 별도 이슈를 생성하지 않는다.
