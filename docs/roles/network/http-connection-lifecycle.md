# HTTP 연결 재사용·TCP 종료 방식 비교 로컬 실험

- 담당: 네트워크 `@RockCandy444`
- [Notion 카드](https://notion.so/40c04d37c225811389ecc1f752d8bc14) · [Issue #248](https://github.com/mmmphyun/aleph-project/issues/248)
- 브랜치: `feat/network-http-connection-lifecycle`
- 기준 main: `06d9dc10827c56d4639fa88ef38a496b5dbbf60a`, 선행 [PR #247](https://github.com/mmmphyun/aleph-project/pull/247)

## 목적과 범위

HTTP 응답 상태가 바뀌는 것, TCP 한쪽 방향이 닫히는 것, 연결 전체가 정상 종료되거나 reset되는
것을 전용 합성 서버에서 구분한다. AWS·팀 EC2·SG/WAF·운영 Slack·호스트 방화벽·공유 Docker
네트워크·팀 nginx 설정을 사용하거나 변경하지 않는다. 수정은 `network/`,
`tests/unit/test_network.py`, `docs/roles/network/`뿐이다.

읽기 전용 점검과 RFC 제안 후 사용자가 2026-11-02 새 Notion 카드를 먼저 만들고 시작하도록
승인했다. 카드 기본 상태는 시작 전이며 담당자는 RockCandy다. WIP 0개와 선행 완료를 확인하고,
원본 main을 fast-forward한 뒤 카드 착수 가능 확인·Issue 발행·작업 브랜치 순서로 착수했다.
커넥터 Issue 생성 403은 gh CLI로 처리했다. 최초 브랜치 전환이 Issue 실패 뒤 실행된 것을
확인해 구현 전 main으로 복귀했고 Issue 발행 후 작업 브랜치로 돌아왔다.
노션 상태·PR·Commit의 후속 갱신은 GitHub Actions에 맡긴다.

기존 사용자 미추적 회의 문서 3개는 main 최신화 전후 SHA-256이 같았다. 기존 검증 worktree
3개의 수정/미추적 파일·실험 증거·캐시 ACL을 그대로 보존했다.

## 재사용 자산과 변경 이유

| 자산 | 재사용과 경계 |
| --- | --- |
| `lab/packet_lab.py` | 상한 명령 실행·고유 ID/label·격리 검사·바이너리 회수·manifest·실패 회차 보존·정리를 재사용한다. 서버 명령/회수 worker/허용 파일 및 suite factory를 주입하는 훅만 추가했다 |
| `lab/run.py:Lab` | 로컬 npipe/unix Linux 엔진 검사, 환경 및 독점 출력 디렉터리를 계승한다 |
| `tcpdump_capture.sh`, `lab/tcpdump.sh`, `packet_worker.py` | 준비 신호·유한 캡처·최소 권한 강하·소유 자식 종료·정밀 시각·기록 함수를 재사용한다 |
| `waf_packet_timeline.py` | TCP 주소/포트·플래그·관측 구간·stream 무결성을 재사용한다 |
| `sg_connection_timeline.py`, `roundtrip_timeline.py` | 시각 파서·소켓/메시지 대조 항목·중복 JSON 거부·청크 해시를 재사용한다. SG 시나리오 및 사건 타임라인을 다시 만들지 않는다 |
| `src/contracts/`, 탐지·대응·리포터 | 인터페이스를 읽어 확인했다. 합성 트래픽을 위협 사건으로 변환하거나 AWS/Slack 경로를 호출할 필요가 없다 |

새 실행/worker/판독기·전용 Dockerfile/dockerignore·본 보고서와 기존 네트워크 테스트,
공통 훅 파일까지 총 8개 파일만 변경한다. 기존 `packet_scenario_compare.compare`의 요청 1회·
연결 1개·8초 캡처 계약과 기존 4개 시나리오 기대 조건은 유지한다.

PCAP과 TCP 재조립은 TShark가 수행한다. 새 판독기는 `-2 -T pdml -J "frame ip tcp http"`의
원본 프레임·반복 HTTP 노드·재조립 정보를 보존한다. `occurrence=f`나 HTTP 상태의 첫 등장만
사용하지 않는다. 이미 디코딩된 TCP 페이로드를 앱 송수신 바이트의 seq 범위와 대조하는 것은
추가 PCAP 디코더를 구현하는 작업이 아니다.

## 재현 명령과 실행 상한

Windows PowerShell에서 실제 작업 루트 `C:/Aleph`를 사용한다. 기본 명령은 plan만 출력한다.
build는 명시적으로 Debian/apt를 내려받고 run은 로컬의 전용 이미지 ID만 사용한다.
이미지의 worker·캡처 파일 SHA-256을 실제 작업 소스와 비교한 뒤 서버를 시작한다.
자동 pull/build/재연결/재시도/리다이렉트는 없다.

```powershell
Set-Location C:\Aleph
$env:PYTHONUTF8 = '1'
$env:PYTHONIOENCODING = 'utf-8'
uv run python network/lab/connection_lab.py plan
uv run python network/lab/connection_lab.py build
uv run python network/lab/connection_lab.py run
powershell .\scripts\check.ps1
```

| 항목 | 고정 상한 |
| --- | --- |
| 실행 | 동시성 1, A~D 각 3회·총 12회 |
| A | 신규 연결 1개·순차 GET 3회 |
| B | 신규 연결 2개·GET 총 3회; 두 번째 연결은 명시적 대조군 |
| C | 연결 1개·방향별 합성 메시지 1개·각 256B 이하 |
| D | 연결 1개·합성 메시지 1개·256B 이하 |
| 클라이언트 | connect 3초, 개별 I/O 2초, 전체 10초 |
| 캡처 | 준비 3초, 최대 15초 또는 512패킷, PCAP 1MiB |
| 저장 | 로그별 64KiB, 메타데이터·분석별 1MiB, 회차 4MiB, 묶음 64MiB |
| 수명 | 작업 45초·정리 15초, 소유 자식 TERM 2초 후 KILL/회수 1초 |
| 전체 | 실험·최종 기록 13분, 명시적 이미지 빌드 별도 10분 |

로그별 물리적 파일 상한을 위해 캡처 자식의 `RLIMIT_FSIZE`는 **64KiB**로 더 작게 적용했다.
따라서 PCAP도 실제로는 64KiB를 넘을 수 없으며 1MiB 상한을 충족한다. 이 실험의 합성 트래픽은
수 KiB이고 포화 시 정상 무응답으로 처리하지 않는다. 실제 config에도 해당 설정을 기록한다.
회차 12개에 최대 60초씩 배정하고 최종 기록에 60초를 남기는 예산이다.

두 컨테이너는 cap-drop ALL·no-new-privileges·읽기 전용 rootfs·tmpfs 4MiB·메모리 256MiB·
CPU 1개·PID 64개로 제한한다. 서버에는 추가 capability가 없고 클라이언트에는 캡처용
NET_RAW·SETUID·SETGID·KILL만 허용한다. NET_ADMIN·privileged·포트 공개·호스트/소켓 bind는 없다.
각 회차에서 정확한 자원 ID·label·네트워크 구성원을 검사하고 이번 실행 소유 자원만 정리한다.

## 시나리오와 판독 원칙

| 시나리오 | 앱 동작 | TCP 대조 |
| --- | --- | --- |
| A: `http_reuse` | 한 소켓에서 200→403→200, 모두 keep-alive. 마지막 응답 뒤 클라이언트 정상 종료 | 한 handshake/stream, 같은 양쪽 소켓·주소/포트, 메시지 순번·Content-Length·원문 바이트, 마지막 응답 뒤 FIN |
| B: `http_close` | 첫 소켓 200→403+close·EOF, 명시적 새 소켓에서 200+close | 두 handshake/stream과 별도 소켓/포트. 각 서버 FIN·ACK·반대 FIN·ACK |
| C: `half_close` | C→S 19B 메시지 뒤 C가 SHUT_WR. 서버가 데이터·EOF를 읽고 S→C 20B 응답 | C FIN 뒤 반대 방향 데이터. 서버 앱 수신과 클라이언트 앱 수신을 별도 기록하고 양방향 FIN을 마지막에 확인 |
| D: `established_rst` | C→S 26B 메시지를 서버가 읽은 뒤 SO_LINGER=(1,0)·close, 클라이언트 ECONNRESET | 완료된 handshake·요청 데이터 뒤 S→C RST/ACK, 송신 방향·raw seq/ack와 linger 실제 적용값 |

HTTP 메시지는 요청 URI·X-Run-ID·X-Sequence·Content-Length 및 같은 stream의 요청 frame 참조로
대응시킨다. 수신 버퍼의 일부 헤더/본문과 여러 메시지를 처리하며 recv 1회=메시지 1개로
가정하지 않는다. 앱 소켓 ID는 실행/역할/연결 번호와 PID·FD·주소/포트를 함께 기록하므로
두 프로세스의 같은 FD 번호를 같은 소켓이라고 해석하지 않는다.

단일 handshake·raw seq/ack와 전체 송수신 바이트를 대조해 신규 연결·후속 요청·재전송을
구분한다. 각 FIN의 seq 끝점과 반대 방향의 ACK를 확인하고 반대 FIN/RST의 순서를 보존한다.
half-close는 한 방향의 송신 종료이며 half-open과 다르다. SHUT_WR을 수행한 쪽은 같은 방향으로
다시 송신하지 않는다. HTTP 403 자체가 TCP 종료를 일으킨다고 일반화하지 않는다.

SO_LINGER reset은 Linux 컨테이너의 native int 2개·8바이트 구조체에 한정한다. 실제 getsockopt
바이트와 커널 버전을 남기며 RST가 관측되지 않거나 EOF/timeout이 발생하면 실패다. 최초
SYN에 REJECT RST를 반환했던 선행 과제와 다르다.

## 증거·오류·재분석

원본은 ignored `network/lab/runs/connection/`의 고유 실행 디렉터리에 보존한다. 각 회차에는
실제 설정·소스/이미지 ID·버전·양쪽 소켓/송수신 로그·서버/클라이언트 완료 결과·PCAP·PDML·
decoder 진단·분석/종료/정리 결과·파일 SHA-256·manifest가 있다. worker PID/시작 시각으로
실제 종료를 확인한 뒤 원본 해시→바이너리 전송→저장 바이트 해시→원본 재해시를 대조한다.
확보 실패 시 원본 컨테이너와 해당 네트워크를 보존하고 실패·잔여 ID를 전달한다.

캡처 누락·절단·패킷/파일 상한·도구/저장 오류·사용자 중단·정리 실패를 정상 종료나 정상
무응답으로 분류하지 않는다. 커널 drop 0·캡처 수·전체 프레임 길이·worker/server 완료를
검사한다. 실패 회차와 불리한 패킷도 보존한다.

실제 첫 실행의 원본 PDML에 있는 TShark XML 주석을 선언으로 오인하는 판독기 결함을 발견했다.
계획된 12회는 그대로 수행하고 추가 연결 실험을 반복하지 않았다. 원래 실패 summary와 manifest를
덮어쓰지 않고, 판독 수정 후 같은 원본의 해시를 확인하는 별도 오프라인 분석으로 검증한다.

## 단위 테스트와 필수 품질 게이트

기본 pytest는 Docker·외부 통신을 실행하지 않는다. 합성 소켓/PDML로 4가지 수명주기·분할/
다중 메시지·자동 재연결 오인·seq/ack·FIN/RST 방향·앱 수신·입력/실행 혼합·시간/용량 상한,
캡처/서버/클라이언트/저장/중단/정리 실패와 해시 불일치·권한을 검증한다. 기존 테스트의 기대
조건이나 로직은 삭제/완화하지 않는다. 실제 Linux 소켓/캡처 결과와 단위 테스트를 구분한다.

원본 `.pytest_cache` ACL 접근 오류는 관리자 범위 조회에서도 확인했다. 이를 변경하지 않고
관리형 분리 검증 사본 `C:/Users/User/.codex/worktrees/network-connection-validation/Aleph`에서
바이트 일치를 확인한 소스로 필수 `powershell .\scripts\check.ps1`을 수행한다. 최종 결과·원본
로그·해시는 아래에 기록한다.

## 분산 인프라 5대 제약

1. 수명주기: Lambda·호출 간 공유 상태가 없어 외부 DB는 불필요하며 부분 상태를 회차 파일로 보존한다.
2. 스토리지: DynamoDB 400KB/TTL은 비적용이며 파일·회차·묶음 상한과 독점 생성을 적용한다.
3. 일관성: 분산 DB 읽기는 없으며 worker 종료·flush·기록 완료·전송 전후 해시 뒤 분석한다.
4. 순서 역전: 슬라이딩 윈도우는 없으며 원본 프레임 순서·시각·stream·seq/ack를 보존한다.
5. 장애 전파: DLQ는 비적용이며 수집·저장·도구·정리 실패를 부분 증거·비정상 종료로 전달한다.

## P5-4와 선행 로컬 실험의 비교 한계

[P5-4 최종 기록](2026-10-30-p5-4-live-results.md)의 Web 200→403→200은 별도 curl 프로세스의
관측이어서 같은 연결 재사용을 증명하지 않는다. 이번 A는 해당 구분을 로컬에서 설명한다.
[선행 로컬 실험](local-packet-comparison.md)은 요청마다 신규 연결 1개와 Connection: close를
사용했다. 기존 DROP 및 SYN→RST 연결 거부는 이번 수립 후 RST와 구분한다.

로컬 결과는 실제 AWS SG/WAF 동작·AWS 전파 시간·10초 SLA·과거 P5-4 연결 재사용의 증거가
아니다. 과거 21.291308초·SLA 미충족과 미확보 항목을 그대로 유지한다. 재전송이 없으면 0으로
기록하되 15초 관측 밖의 재전송, bridge/오프로딩/시계 오차를 배제한 것으로 표현하지 않는다.


## 실제 12회 결과와 원본/파생 결과의 구분

실제 수집 묶음은 `20261102T055302Z-822d40df568e`이다. 캡처 구간은 **2026-11-02 14:53:06 KST~2026-11-02 14:58:16 KST**이며 생성·실행·증거 회수·정리를 포함한 묶음은 **321.39초**로 13분 이내다. PCAP 12개·총 **156프레임/19269바이트**, 원본 증거 **3,667,999바이트/207파일**을 보존했다. 모든 회차의 worker/server 완료와 커널 drop 0, 소유 자원 정리 완료를 확인했다. 최종 cs-connection- 컨테이너·네트워크 잔여는 0개다.

최초 `run`은 XML 주석 거부 결함으로 **12회 모두 분석 실패·exit 1**이며 원본 summary의 complete=false를 그대로 보존한다. 주석을 허용하고 DTD/ENTITY만 거부하도록 수정한 뒤, 최종 파생 묶음 `20261102T060227Z-dd8bb7e7fd03`에서 **같은 12회 증거 모두 판독 통과·exit 0**를 확인했다. 최종 오프라인 분석은 0.25초다. 새 연결이나 요청은 추가하지 않았다. 중간 오프라인 분석 묶음 `20261102T055932Z-36b586880efc`도 보존했다.

| 회차 | 프레임 | 클라이언트 포트 | handshake 프레임 | 종료 프레임 | 재전송 | 최종 판독 |
| --- | ---: | --- | --- | --- | ---: | --- |
| http_reuse-1 | 14 | 41870 | 1/2/3 | C FIN 12, S FIN 13 | 0 | 통과 |
| http_reuse-2 | 14 | 37418 | 1/2/3 | C FIN 12, S FIN 13 | 0 | 통과 |
| http_reuse-3 | 14 | 42662 | 1/2/3 | C FIN 12, S FIN 13 | 0 | 통과 |
| http_close-1 | 22 | 58370 / 58384 | 1/2/3 / 13/14/15 | S FIN 10, C FIN 11; S FIN 20, C FIN 21 | 0 | 통과 |
| http_close-2 | 22 | 34006 / 34014 | 1/2/3 / 13/14/15 | S FIN 10, C FIN 11; S FIN 20, C FIN 21 | 0 | 통과 |
| http_close-3 | 22 | 46184 / 46194 | 1/2/3 / 13/14/15 | S FIN 10, C FIN 11; S FIN 20, C FIN 21 | 0 | 통과 |
| half_close-1 | 10 | 35962 | 1/2/3 | C FIN 6, S FIN 9 | 0 | 통과 |
| half_close-2 | 10 | 32944 | 1/2/3 | C FIN 6, S FIN 9 | 0 | 통과 |
| half_close-3 | 10 | 40994 | 1/2/3 | C FIN 6, S FIN 9 | 0 | 통과 |
| established_rst-1 | 6 | 58414 | 1/2/3 | S RST 6 | 0 | 통과 |
| established_rst-2 | 6 | 47252 | 1/2/3 | S RST 6 | 0 | 통과 |
| established_rst-3 | 6 | 57284 | 1/2/3 | S RST 6 | 0 | 통과 |

모든 재전송은 **0회**이며 관측 구간에 한정한 값이다. A는 각 회차 stream 0 하나,
B는 각 회차 stream 0/1 두 개, C/D는 각 회차 stream 0 하나다. 각 PCAP의 stream 번호는
해당 파일 안에서만 유효하다. 모든 PCAP magic은 d4c3b2a1로 **마이크로초 해상도**이며,
TShark의 소수 9자리 표시를 나노초 정확도로 해석하지 않는다.

### A와 B의 상세 대조

A 1회차 run_id는 `cs-connection-ea24fec687cd48e5828b6668f6c50aa3`이다.
클라이언트 `172.31.0.3:41870` ↔ 서버 `172.31.0.2:8080`, stream 0,
handshake 1/2/3으로 고정된다. 앱 소켓 ID도 각각 같은 run_id의 `:client:1`, `:server:1`이다.
GET /1(frame 4)→200(6), GET /2(8)→403(9), GET /3(10)→200(11)이고 응답 모두
Connection: keep-alive·Content-Length: 12다. 403 이후 새 handshake 없이 같은 소켓/stream에서
세 번째 요청·응답이 전달됐다. 클라이언트 FIN은 세 번째 200 이후인 frame 12다.

B 1회차에서는 첫 연결 포트 58370·stream 0·handshake 1/2/3에서 200(6)→403(9)를 받은 뒤
서버 FIN(10)·클라이언트 EOF·반대 FIN/ACK(11)·최종 ACK(12)를 확인했다. 두 번째 연결은
포트 **58384**·stream **1**·새 소켓 `:client:2`/`:server:2`·handshake **13/14/15**이며,
GET /3(16)→200(18)과 서버 FIN(20)·반대 FIN/ACK(21)·최종 ACK(22)를 확인했다.
이 200을 첫 연결이 유지되거나 회복된 결과로 표현하지 않는다.

### handshake·FIN·half-close·RST 흐름

| 첫 회차 | 방향·프레임과 raw seq/ack | 의미 |
| --- | --- | --- |
| A | C FIN 12: seq 826434083, ack 2083896344 → S FIN/ACK 13: ack 826434084 → C ACK 14 | 마지막 200 뒤 클라이언트가 정상 종료; FIN의 +1을 반대 방향 ACK와 대조 |
| B 첫 연결 | S FIN 10: seq 237999644, ack 1245289214 → C FIN/ACK 11: ack 237999645 → S ACK 12 | close 응답 뒤 서버 주도 종료와 앱 EOF |
| C | handshake 1/2/3 → C 19B 데이터 4 → C FIN 6: seq 446694168 → S 20B 데이터/ACK 7: ack 446694169 → S FIN 9 → C ACK 10 | C 쓰기 종료 후 S→C 데이터가 가능함. ACK와 별도로 서버 19B·클라이언트 20B 앱 수신 로그를 확인 |
| D | handshake 1/2/3 → C 26B 데이터 4 → S ACK 5 → S RST/ACK 6: seq 2288190962, ack 590231351 | 서버 실제 26B 수신·linger 설정 뒤 reset, 클라이언트 ECONNRESET(104), FIN 없음 |

D의 실제 linger 바이트는 `0100000000000000`이다. C에서는 서버의 데이터 수신→EOF→응답 송신,
클라이언트의 송신→SHUT_WR→반대 방향 데이터·EOF 수신을 각각 기록했다. C의 ACK 7은 반대 방향
응답 데이터에 실린 ACK이며 ACK만으로 서버 앱 수신을 추정한 것이 아니다.

### 실측 환경과 소스 식별

| 항목 | 값 |
| --- | --- |
| Docker Desktop / client·server | 4.97.0 (244584) / 29.9.2 |
| context / 엔진 | desktop-linux, 로컬 npipe, Linux amd64 |
| 커널 | 6.18.33.2-microsoft-standard-WSL2 |
| 컨테이너 Python / tcpdump | 3.11.2 / 4.99.3, libpcap 1.10.3 |
| 호스트 Python / TShark | 3.12.14 / 4.6.8 |
| 전용 이미지 | `sha256:8112b91113831574ec7c2ce4712477ef2b2bd440314c6d150df3dbf78da87d0a` |
| 실제 worker SHA-256 | `12da85f69014748020224094829ebb9d648c975ccc88b6e1551973e09c65c9f4` |

실험 당시 HEAD는 기준 main이며 미커밋 작업 소스 16개의 실제 바이트 해시를 plan/image에
기록했다. 이미지 worker/캡처의 원격 해시와 로컬 소스가 일치했다. 판독 수정 후 소스는
파생 references.json에 별도로 기록한다. 이미지의 worker는 수정 전후 같은 바이트다.
베이스 태그와 apt는 digest 잠금이 아니므로 다른 날 재빌드의 바이트 동일성을 주장하지 않는다.

### 증거 SHA-256과 오프라인 재현

원본 파일 180개와 회차 manifest 12개, suite summary/plan 해시 연결을 재검증했다.
아래 manifest는 **원래 분석 실패 상태**를 포함한다. 파생 manifest는 이 원본 manifest들을
참조하고 새 분석 파일만 포함하므로 원본 결과를 덮어쓰지 않는다.

- 원본 summary.json: `cf6c4327421637de1d0a17f6159f2b86b0d986b885ef22b9d2fd740cb785608f`
- 원본 plan.json: `2d675423fa06217f4d62de2224a2f8341babd635b0f4d2f4578321697e5c9fe8`
- 최종 파생 summary.json: `003135b660d54840a9080f57f06a72e973db861172dddc235ed41afdba38db00`
- 최종 파생 manifest.json: `d3d5982486fc2415482187e11fd132af54b0edc43239d9baa40cf2130d74e6e8`

| 회차 | PCAP SHA-256 | 원본 manifest SHA-256 |
| --- | --- | --- |
| http_reuse-1 | `052183efae5883c4cc9271f1a2664233216d6337f4cc468846883b3849b97538` | `6807e90cc11aab8b23f737a72382afe3939754d1f89308212e2441a3f30b38d1` |
| http_reuse-2 | `2d08e6b9bab7d6736c10899520b42a10310cfd1809b9c1e67568d1b478bf3c1e` | `05050d82b5a04aa3a941e315585f3b46580687332d44cff5b583b4bfefc24bb7` |
| http_reuse-3 | `d5c77dd1a146173ec830c50ecbdfd148ae4342dcfbac9b8c9c83e3248994519b` | `a724178edeac7d70c48932796b59598aaf24a77bc93b065fd95ed08ef176f5b4` |
| http_close-1 | `24122f7ef0a3827db876a0ac5ad46d90caaaf321338de9387b3118c1cd6a9d94` | `b6b3952a86f4862e85a70713dcfa0d95ffca9f4e80d8fe12b9f0c7a1b0dae0b1` |
| http_close-2 | `ab2c53f283ff1fa79505068577f0f20d78187a8529adcec78d134227f553250a` | `2ecfe2d83bf25268d4851d3f25eb1f9d2e63323d0f3f9f7f278035cc7cddb74f` |
| http_close-3 | `4e0787ea7f5ce805ab08f36a5c274f53238667f00366b03c726b82ee2ed3c728` | `ba81d77e6d0ff48ef6a335dca53a33c88bb9d370db33e2159f68da858e414195` |
| half_close-1 | `3b77bc9e9ce2fb0646df05920913270c311ca941866993bf7cc3703598ff8781` | `0e9e65d3442366acf619023f053332a5e4c7e0eea1db14d706c6e3912c39274d` |
| half_close-2 | `5ad5f779033f7c77fe7d6bfe0a5ded3921d0bb37960f998b2cb90f79a16d45b3` | `2399fee0b2096e9b153803969cfb372078756712f695870a2ca43c00663bc2dd` |
| half_close-3 | `b40ec84804d45a9a293d7748c47a12431fcb2d45647717458962328e35a6f1b9` | `a1e05767caa4f2543bc2af25411f4f3f96396dc248ac0c7b4fd2ab77f1c13533` |
| established_rst-1 | `744d802f9359f241b6f415956557aee373fd811195352db8a3ef9c95781746e5` | `a635a62a436f8c2ee650d1d1375eada7279dbe1f1290f13e2cf5f3d7ece5131e` |
| established_rst-2 | `d491dd9ea793bdc4f55c753114257273df96abeb1f93f47e5697369772cf18c8` | `e5273fe5014f6d9d72e4f0a1bb071f83e7c19133009a65be1b7a8d0f8d3880c7` |
| established_rst-3 | `b654f51524f42597daf50751b343674f6bb19ab4585e88daa72abdff56d7e480` | `a4b822e5824eea6da5e2c18625512e57e203a3b31d90c6303847c215a9ff4331` |

```powershell
uv run python network/lab/connection_lab.py analyze --suite C:\Aleph\network\lab\runs\connection\20261102T055302Z-822d40df568e
```

analyze는 원본 summary/plan/manifest와 모든 파일의 크기·SHA-256을 먼저 확인하고 새 고유
디렉터리에만 쓴다. Docker·외부 도구·소켓 호출은 없다. 경로 이탈·실행 혼합·해시 불일치·
미완성 수집·정리 실패·중단은 성공으로 판정하지 않는다. HTTP 실제 12회에서는 전체 메시지별
독립 송신이 관측됐으며, 분할/동일 세그먼트 복수 메시지는 합성 단위 테스트로 별도 검증했다.


## 최종 품질 검증과 보존 상태

신규 `test_connection_*`는 **81건**이며 기존 `test_packet_*` 80건을 포함한 집중 검증은
**161 passed**다. 기본 소켓 차단을 유지했고 기본 pytest에서 Docker/실제 네트워크는 실행하지
않았다. 기준 main의 기존 테스트·fixture **252개 top-level AST**가 모두 동일함을 확인했다.

필수 `powershell .\scripts\check.ps1`은 관리형 분리 검증 사본에서 **exit 0**,
**1746 passed / 기존 4 skipped / 기존 1 warning, 194.35초**로 통과했다. R&R 경계·표준 테스트
경로·Ruff lint/format도 통과했다. warning은 기존 smoke의 DNS 소켓 차단 검증이다.
검증 전 변경 파일 8개의 SHA-256이 원본과 같았고, 검증 후 변경은 본 Markdown의 결과 기록뿐이다.
원본 `.pytest_cache` 및 기존 pytest 임시 경로의 접근 오류는 ACL 변경 없이 보존했으며,
집중 검증은 해당 환경에서 관리자 실행 범위로 확인하고 필수 전체 게이트는 깨끗한 분리 사본에서
실행했다. 우회 플래그나 기존 검증 삭제는 사용하지 않았다.

- 검증 위치: `C:/Users/User/.codex/worktrees/network-connection-validation/Aleph`
- 환경 준비: 원본과 같은 Python 3.12.14, `uv sync --locked --extra dev`
- 게이트 원본 로그: `network/lab/runs/connection-quality/e988488d56504b118c10a3fcedab15c4/check.log`
- 게이트 로그 SHA-256: `01ecf4d729e6b4024c7e05ee63cecd9bd621893bd204ab676ddfd96c749757c2`

기존 사용자 미추적 문서 3개의 해시는 작업 전후 동일하고, 기존 검증 worktree 3개도 그대로다.
소유 실험 컨테이너·네트워크 잔여는 0개이며 재현용 전용 이미지는 보존한다. PCAP·원본 및 파생
분석·실패 summary·manifest는 ignored 로컬 증거로 남긴다. 공개 보고서의 해시는 바이트 식별이며
발급 주체 인증이나 원본의 외부 공개를 뜻하지 않는다.

기술적 판독 기준은 [RFC 9112 연결 유지](https://www.rfc-editor.org/rfc/rfc9112.html#section-9.3),
[Python shutdown](https://docs.python.org/3.11/library/socket.html#socket.socket.shutdown),
[TShark 출력 옵션](https://www.wireshark.org/docs/man-pages/tshark),
[Wireshark TCP 재조립](https://www.wireshark.org/docs/wsug_html_chunked/ChAdvReassemblySection)을
참고했다. 정상 403 응답과 TCP 종료의 관계는 이번 서버가 선택한 동작으로 해석한다.
