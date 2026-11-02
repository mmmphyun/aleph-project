# 로컬 DROP·TCP RST·HTTP 403 패킷 비교 테스트베드

- 담당: 네트워크 `@RockCandy444`
- [Notion 카드](https://notion.so/40c04d37c22581a6b43cf74402426eae) · [Issue #246](https://github.com/mmmphyun/aleph-project/issues/246)
- 브랜치: `feat/network-local-packet-comparison`, 기준 main `3bcc083cb3c0e13abd6196e97fd7acd4c67d4b26`
- 작성일: 2026-11-02 KST. 최종 실험·품질 게이트 결과는 아래 검증 절에 기록한다.

## 목적과 소유권

P5-4의 보존 자료를 읽을 때 timeout·TCP 연결 거부·HTTP 거부를 구분할 수 있도록 원인을 통제한
로컬 TCP 8080 실험을 제공한다. 사건 시각 요약이나 새 탐지·대응 파이프라인을 만들지 않는다.
실제 AWS·팀 EC2·SG/WAF·운영 Slack을 사용하지 않고, 호스트 방화벽·공유 Docker 네트워크·
팀 nginx 설정도 변경하지 않는다. 수정은 `network/`, `tests/unit/test_network.py`,
`docs/roles/network/`에 한정한다. 공통 계약·의존성·CI·타 직무 코드는 그대로다.

2026-11-02 읽기 전용 RFC 후 사용자가 명시적으로 진행을 승인했다. 네트워크 열린 PR 없음,
P5-4 PR #243 머지와 Notion 선행 완료, 본 카드 시작 전/착수 가능을 확인한 뒤 main을
fast-forward하고 Issue→브랜치 순서로 착수했다. Notion 상태·속성은 직접 변경하지 않는다.
기존 미추적 회의 문서 3개도 보존한다.

## 기존 자산 재사용과 변경 이유

| 자산 | 재사용과 차이 |
| --- | --- |
| `network/lab/run.py:Lab` | 생성 디렉터리·환경 정리·로컬 npipe/unix Linux 엔진 preflight를 상속한다. 새 러너는 출력/시간 상한과 소유권 정리를 보강한다 |
| `network/lab/hydra_lab.py` | internal bridge, 정확한 생성 ID/label·실제 주소/경로·LISTEN 준비 검증 패턴을 계승한다. SSH 인증·공격 계정은 필요 없다 |
| `network/tcpdump_capture.sh`, `network/lab/tcpdump.sh` | 원본을 그대로 이미지에 복사한다. 준비 신호·유한 캡처·전용 UID 권한 강하·자식 종료·기존 파일 보호를 재사용한다 |
| `network/waf_packet_timeline.py:analyze_csv` | TCP CSV 구조·주소/포트·플래그·시각·stream 검증과 방향별 패킷 보존을 재사용한다 |
| `network/sg_connection_timeline.py:epoch,integer` | 기존 정밀 시각·정수 검증을 재사용한다. SG 제어 이벤트나 A/B/R 소켓 시나리오는 만들지 않는다 |
| `network/roundtrip_timeline.py:strict_json,fingerprint` | 중복 JSON 키·비유한 값 거부, 청크 SHA-256·읽기 중 변경 검증을 재사용한다. 사건 요약은 호출하지 않는다 |
| `network/demo_attack_runner.py:create_run_directory` | UTC+무작위 ID의 독점 디렉터리 생성만 사용한다. AWS 승인·공격·복구 경로는 호출하지 않는다 |
| `src/contracts/`, 탐지·대응·리포터 인터페이스 | 읽기 확인했다. 로컬 실험을 AWS IncidentReport나 위협 사건으로 변환할 필요가 없어 호출·변경하지 않는다 |

새 파일은 `Packet.Dockerfile`·전용 dockerignore, `packet_lab.py`, `packet_worker.py`,
`network/packet_scenario_compare.py`, 본 문서다. 기존 네트워크 테스트 파일에만 회귀를 추가한다.
패킷 디코딩은 TShark에 맡기고 기존 TCP 검증 결과에 raw seq/ack·HTTP·재전송 필드만 대조한다.
TShark의 `True/False`와 `0/1` 표기는 전달 사본에서 정규화하며 원본 CSV는 보존한다.

## 재현 환경과 명령

Windows PowerShell, 저장소 루트에서 실행한다. Docker Desktop Linux 엔진과 로컬 Docker
CLI, Python 프로젝트 환경, TShark가 필요하다. Windows TShark는 PATH 또는
`C:/Program Files/Wireshark/tshark.exe`를 사용한다. Linux에서는 PATH로 찾는다.

```powershell
$env:PYTHONUTF8 = '1'
$env:PYTHONIOENCODING = 'utf-8'
uv run python network/lab/packet_lab.py plan
uv run python network/lab/packet_lab.py build
uv run python network/lab/packet_lab.py run
powershell .\scripts\check.ps1
```

인자 없이 실행하면 plan만 출력하며 파일·Docker·외부 통신을 만들지 않는다. build는 명시적으로
Debian 이미지·apt 패키지를 내려받는다. run은 로컬에 준비한 전용 이미지만 사용하며 자동 pull,
build, 재시도, 외부 주소 지정은 없다. 증거 루트도 `network/lab/runs/`로 고정한다.
베이스 태그·apt 저장소는 digest 잠금이 아니므로 다른 날 재빌드 바이트의 동일성을 주장하지 않는다.
실행 당시 이미지 ID·레이어·도구 버전과 실제 소스 SHA-256을 보존한다.

| 실측 환경 | 값 |
| --- | --- |
| Docker Desktop / client·server | 4.91.0 (239619) / 29.8.0 |
| context / 엔진 | `desktop-linux`, Linux amd64, 로컬 npipe |
| 커널 | `6.18.33.2-microsoft-standard-WSL2` |
| 컨테이너 | Debian bookworm, Python 3.11.2, curl 7.88.1-10+deb12u15 |
| 캡처 | tcpdump 4.99.3, libpcap 1.10.3, `eth0` 비 promiscuous 캡처 |
| 방화벽 | iptables 1.8.9, nf_tables |
| 디코딩 | TShark 4.6.8 |
| 전용 이미지 ID | `sha256:b128fe0ba12967e522337d9b970654a28d0f410a0b9bf0c56bcc9be7349682e9` |

각 회차는 새로운 internal bridge와 서버·클라이언트 각 1개를 만든다. Docker inspect로 실제
두 주소·정확한 네트워크 구성원을 확인한다. 호스트 포트 공개, host 모드, bind mount, Docker
소켓 마운트, privileged는 없다. 두 컨테이너 모두 cap-drop ALL·no-new-privileges·읽기 전용
rootfs·메모리 256MiB·CPU 1개·PID 64개 상한을 적용한다. 증거 tmpfs는 4MiB다.

정상/403 서버에는 추가 capability가 없다. DROP/RST 서버만 NET_ADMIN을 받고 INPUT의
현재 클라이언트 /32·TCP 8080 규칙만 설정한다. 클라이언트는 기존 캡처의 NET_RAW·SETUID·
SETGID·KILL만 받는다. Docker의 CAP_ 접두사 표기만 정규화하고 실제 허용 집합은 정확히 검사한다.
HTTP 서버는 별도 Python 서버이며 응답 본문 25바이트·Content-Length·Connection: close를 사용한다.

## 고정 실행 상한과 증거

| 항목 | 상한/처리 |
| --- | --- |
| 반복 | 정상·DROP·RST·403 각각 3회, 전체 동시성 1, 회차당 신규 TCP 연결 시도 1회·GET 최대 1회 |
| 클라이언트 | 연결 4초, 전체 요청 5초, 프로세스 감시 6초; 프록시·curl 설정·리다이렉트·재시도 없음 |
| 준비 | TCP 요청 없이 서버 LISTEN 확인, 캡처 준비 신호 최대 3초 |
| 캡처 | 8초 또는 256패킷, OS RLIMIT_FSIZE로 PCAP 1MiB; 패킷 상한 도달도 성공으로 간주하지 않음 |
| 출력 | 로그별 64KiB, 메타데이터·분석 파일별 1MiB, 회차 총 4MiB, 묶음 64MiB |
| 시간 | 회차 작업 45초+정리 15초, 12회·최종 기록 최대 13분, 명시적 build는 별도 10분 |
| 종료 | 소유 자식 TERM 2초 후 KILL·회수 1초; 클라이언트 전체 worker도 13초/강제 종료 유예 3초로 감시 |

회차마다 서버는 계속 LISTEN하며 정상/403만 응답 코드를 바꾼다. DROP은 INPUT DROP,
RST는 INPUT REJECT `--reject-with tcp-reset`을 사용한다. 규칙 존재를 `iptables -C`로 검사하고
`iptables-save -c`의 실제 규칙·패킷 카운터를 요청 전후 보존한다. 방화벽은 해당 컨테이너의
네트워크 namespace 안에서만 바뀐다. Docker는 전용 bridge 생성·삭제에 필요한 자체 처리를 수행한다.

`network/lab/runs/<UTC-고유ID>/<시나리오>-<회차>/`에 다음을 저장한다.

| 파일 | 근거 |
| --- | --- |
| config.json, scenario.json | 실제 주소·포트·시나리오·상한·worker ID와 실제 규칙 검증/카운터 |
| image.json, versions.json, tshark-version.json | 이미지·OS·도구 버전 |
| worker-result.json, curl.stdout/stderr, headers.txt, body.txt | 실제 curl 종료 코드·시각·소켓·HTTP 상태·본문 및 종료 사유 |
| capture.pcap, capture.stdout/stderr | 전체 대상 TCP 캡처·준비·종료·커널 누락 통계 |
| packets.csv, decoder.json, analysis.json | 원본 TShark 필드, 디코더 상태, 설정/클라이언트/패킷 대응 결과 |
| commands.json | 실제 명령·종료·시간/출력 초과 구별, 바이너리 전송은 원문 대신 바이트 수·해시 |
| manifest.json, manifest.sha256 | 회차 결과·정리 실패와 파일별 바이트 수·SHA-256, manifest 자체 해시 |
| 상위 plan.json, summary.json/sha256 | 소스 커밋·실제 작업 트리 해시·고정 계획, 12회 결과와 회차 manifest 해시 연결 |

worker 종료를 PID·시작 시각으로 확인한 뒤 바이너리 exec 스트림을 읽고 원본 SHA-256과 저장 후
해시를 비교한다. 기존 파일은 독점 생성으로 보호한다. 로그/시간 상한 위반은 부분 출력 표시와
비정상 종료로 전파하며 출력 일부를 정상 결과로 제시하지 않는다. 캡처가 시작 전에 종료되면
요청을 실행하지 않는다. 캡처 종료 코드·커널 드롭·실제 디코딩 개수가 맞아야 판독한다.

증거 회수 실패 시 원본을 가진 소유 컨테이너·네트워크를 남기고 후속 회차를 중단한다.
다른 자원은 ID와 label을 확인한 뒤 정리하고 실패 ID를 기록한다. create의 응답 유실은
이번 이름+label이 일치하는 자원만 회수한다. 전체 이름 검색·prune·공유 자원 삭제는 없다.
실험 이미지는 후속 재현용으로 남긴다. 증거를 자동 삭제하지 않으며 새 실행은 새 디렉터리를 쓴다.

## 패킷 판독과 기대 관측

| 상황 | 3-Way Handshake | 클라이언트 | 패킷/종료 기대와 실제 대조 기준 |
| --- | --- | --- | --- |
| 정상 | C SYN → S SYN-ACK → C ACK | curl 0, HTTP 200 | 같은 stream의 GET·서버 200, 실제 FIN/RST 송신 방향 기록 |
| DROP | C SYN, 서버 응답 미관측 | curl 28, connect timeout | 규칙 카운터 증가·SYN 관측·서버 방향 응답 없음이 함께 필요 |
| RST 거부 | C SYN → S RST/ACK, 연결 미수립 | curl 7, 연결 오류 | 서버 방향 RST의 ack=SYN seq+1, handshake·HTTP 응답 없음 |
| HTTP 403 | C SYN → S SYN-ACK → C ACK | curl 0, HTTP 403 | TCP 성공 뒤 GET·서버 403, 실제 FIN/RST 방향 별도 기록 |

SYN의 raw seq와 SYN-ACK의 ack, SYN-ACK의 raw seq와 세 번째 ACK의 ack를 32비트 공간에서
대조한다. ACK가 GET을 포함하는 경우도 허용하지만 순서는 프레임 번호로 확인한다.
FIN은 반쪽 종료일 수 있고, RST가 있더라도 송신 방향과 시점을 보고한다. HTTP 오류를 TCP
연결 실패로 바꾸지 않는다. curl 7만으로 RST라고 확정하지 않고 실제 응답 패킷이 필요하다.

신규 연결은 stream·주소/포트로 나눈다. 같은 stream·클라이언트 포트·초기 seq의 반복 SYN은
재전송으로 세고 TShark의 retransmission/fast/spurious 표시를 중복 없이 함께 기록한다.
재전송 0은 관측 구간에서의 값이며 이후 재전송 부재를 뜻하지 않는다. 클라이언트가 4초 후
연결을 포기하고 캡처가 8초로 끝나므로 커널의 더 긴 재전송 흐름은 관측할 수 없다.
PCAP 원본 해상도와 TShark의 출력 소수 자릿수를 구별하며 장비 간 절대 시계 정확도를 주장하지 않는다.

## 개발 중 실패 회차 보존

| 실행 묶음(UTC ID) | 결과와 보존 |
| --- | --- |
| `20261102T005957Z-3cc558948671` | 12회 모두 컨테이너 시작 실패. local 로그 드라이버의 기본 압축+max-file=1 조합을 거부. 요청/PCAP 없음, 전부 정리 |
| `20261102T010035Z-97807bd1b806` | 12회 모두 격리 검증 실패. 엔진의 CAP_ 접두사를 미정규화한 문제. 요청/PCAP 없음, 전부 정리 |
| `20261102T010204Z-4c46ccb4f68b` | 정상 1회 HTTP 200·12패킷 수집 후 Docker cp의 tmpfs 회수 실패. 나머지 11회 미착수. 원본 컨테이너 보존 후 `normal-1-recovered/`로 해시 검증 회수·정리, 새 요청 0회 |
| `20261102T010355Z-156ac597e142` | 12회 수집 후 기존 TCP 검증기가 TShark True/False를 거부. 원본 CSV·PCAP·실패 manifest 유지. 정상/DROP/RST/403 자료를 수정 판독기로 오프라인 확인 |

위 실패를 정상 DROP이나 성공 묶음으로 덮어쓰지 않았다. 실패/미착수 상태를 그대로 유지하며
최종 검증은 별도 고유 실행 ID로 분리한다. 수정은 로그 압축 해제, 정확한 capability 표기 정규화,
바이너리 증거 회수, TShark 표기 호환이며 허용 권한·상한·기대 조건을 완화하지 않았다.

## P5-4 보존 증거와 비교 한계

[P5-4 최종 실측](2026-10-30-p5-4-live-results.md),
[SSH 성공/Web 기준선 실패](2026-10-30-p5-4-live-retry.md),
공개 선별 증거 `evidence/p5-4/live-retry-2026-10-30/ssh-success-web-baseline.public.json`과
`evidence/p5-4/web-success-2026-10-30/web-roundtrip.public.json`을 읽기 전용으로 비교했다.

| P5-4 보존 관측 | 이번 로컬 비교와 한계 |
| --- | --- |
| SSH 정상 handshake 1/2/3, timeout 후보의 SYN 213, 복구 handshake 252/253/254 | 정상/DROP 관측 형태를 설명하는 대조군이다. timeout만으로 AWS SG 원인을 증명하지 않는다 |
| 과거 Web 기준선에서 ALB 두 주소 각각 SYN 7개·응답 없음 | 서버 응답 이전의 실패 형태다. WAF HTTP 거부와 구별되며 현재 로컬 DROP 원인을 과거에 소급하지 않는다 |
| Web HEAD 200(frame 6) → HEAD 403(frame 226) → HEAD 200(frame 236) | 로컬 GET 403은 연결 성공 뒤 HTTP 거부를 설명한다. 메서드·프로토콜·대상은 서로 다르다 |
| 별도 WAF 원문 ALLOW/BLOCK과 승인 ALB·출발지 대조 | 과거 WAF 판정의 별도 근거다. 이번 로컬 403 자체는 WAF 실행 증거가 아니다 |
| Web 첫 GET→루트 403 21.291308초, 탐지→API 반환 0.4463초 | 기존 값과 10초 SLA 미충족 기록을 보존한다. 로컬 응답 시간을 AWS 전파나 전체 SLA로 대체하지 않는다 |

공개 선별 JSON에는 좌표·선별 해시가 있지만 원본 PCAP 전체가 포함되지는 않는다. 이번 작업에서
과거 비공개 PCAP 전체의 재판독·해시 재검증을 수행한 것으로 표현하지 않는다. 과거 SSH 첫 공격
패킷·키 인증·장비 간 최대 시계 오차·연결 재사용의 미확보 상태도 로컬 실험으로 채우지 않는다.

## 분산 인프라 5대 제약

1. 수명주기: Lambda·호출 간 공유 상태가 없어 DB는 불필요하며 회차 파일로 부분 상태를 보존한다.
2. 스토리지: DynamoDB 400KB/TTL은 비적용이며 파일·회차·묶음 상한과 독점 생성으로 제한한다.
3. 일관성: 분산 DB 읽기는 없고 캡처 종료·flush·해시 확인 후 완성 결과로 게시한다.
4. 순서 역전: 슬라이딩 윈도우는 없고 원본 프레임 순서·역순 시각을 보존하며 stream·seq/ack를 대조한다.
5. 장애 전파: DLQ는 비적용이며 도구·저장·정리 실패는 비정상 종료와 부분 증거·잔여 ID로 전달한다.

## 최종 단위 테스트·실험·품질 게이트

단위 테스트와 실제 실험은 별도 검증이다. 기본 pytest는 Docker나 외부 통신을 실행하지 않는다.
합성 CSV·가짜 Docker 응답·소유 로컬 자식으로 판독, 잘못된 입력, 32비트 필드·시간·패킷·바이트
상한, 캡처 누락·중단·실행 실패·저장 실패, 바이너리 전송, 정확한 소유권·권한·정리를 검증한다.
실제 Linux RLIMIT·iptables·Docker·캡처 동작은 별도 12회 실험에서 확인한다.

최종 실행 묶음은 `20261102T010742Z-7b5b730760fd`이며 **12/12 통과, exit 0**이다.
실제 캡처 구간은 2026-11-02 **10:07:46~10:11:10 KST**, 생성·검증·정리를 포함한 묶음은
**213.797초**다. 전체 증거 1,197,041바이트, PCAP 12개 총 91프레임을 보존했다.
별도 해시 재검증에서 **파일 210개**, 회차 manifest 12개, 실제 실행 소스 11개의 해시가 일치했다.
조회 시 `cs-packet-` 컨테이너·네트워크 잔여는 0개였다.

신규 `test_packet_*`는 **80건**이며, `-k packet` 집중 실행은 기존 관련 5건을 포함해
**85 passed**다. 원본 checkout의 기존 `.pytest_cache` ACL 경고가 1건 있었다.
실험 12회 결과를 단위 테스트 성공 건수에 포함하지 않는다.

필수 `powershell .\scripts\check.ps1`은 **exit 0**, **1665 passed / 4 skipped / 1 warning,
192.73초**로 통과했다. R&R 7개 파일·테스트 경로·Ruff lint·185개 Python 파일 format 검사도
통과했다. 기존 skip 4건은 네트워크/WAF Terraform 도구·provider 준비 조건 각 2건이며,
새 skip은 없다. warning은 기존 smoke 테스트의 DNS 소켓 차단 확인이다.

원본 `C:/Aleph/.pytest_cache`의 기존 ACL 때문에 최초 게이트가 파일 탐색 단계에서 막혔다.
ACL·캐시·게이트 코드를 변경하지 않고 기준 커밋의 관리형 분리 worktree에 해당 7개 파일만
복사해 바이트 일치를 확인했다. 최초 분리 환경은 dev 도구가 없어 Ruff 시작 전 실패했으며,
이후 **Python 3.12.14 + `uv sync --locked --extra dev`**로 원본과 같은 잠긴 환경을 준비해
동일 명령을 다시 실행했다. 우회 플래그는 사용하지 않았다. 검증 경로는
`C:/Users/User/.codex/worktrees/network-packet-validation/Aleph`다. 앱이 이를 현재 채팅의 기본
체크아웃으로 등록해 archive를 거부했으므로 검증 사본은 보존한다. 실제 작업 브랜치·커밋은
`C:/Aleph`에 있으며, 이 보호를 우회해 검증 worktree를 삭제하지 않았다.
기존 테스트·fixture 226개의 AST도 기준 커밋과 같음을 확인했다.

품질 게이트 원본 로그는 `network/lab/runs/quality-a70c26bdf27d42cc8adc3103110b2cf8/check-separated-dev.log`,
SHA-256은 `014b1b7b876c27b7a1fd875efad0f049db865ef4e759e2da40167042de395fa5`다.
검증 후 변경은 본 Markdown 결과 기록뿐이며 실행 코드·테스트는 게이트와 같은 바이트를 유지한다.

| 상황·회차 | 패킷 수 | handshake | SYN 재전송 | curl 종료 / HTTP | 관측 종료 |
| --- | ---: | --- | ---: | --- | --- |
| normal-1 | 12 | 1→2→3 | 0 | 0 / 200 | S FIN(10)→C FIN(11) |
| normal-2 | 12 | 1→2→3 | 0 | 0 / 200 | S FIN(10)→C FIN(11) |
| normal-3 | 12 | 1→2→3 | 0 | 0 / 200 | S FIN(10)→C FIN(11) |
| drop-1 | 4 | 미수립 | 3 | 28 / 없음 | 응답·FIN/RST 없음 |
| drop-2 | 4 | 미수립 | 3 | 28 / 없음 | 응답·FIN/RST 없음 |
| drop-3 | 4 | 미수립 | 3 | 28 / 없음 | 응답·FIN/RST 없음 |
| rst-1 | 2 | 미수립 | 0 | 7 / 없음 | S RST/ACK(2) |
| rst-2 | 2 | 미수립 | 0 | 7 / 없음 | S RST/ACK(2) |
| rst-3 | 2 | 미수립 | 0 | 7 / 없음 | S RST/ACK(2) |
| http403-1 | 12 | 1→2→3 | 0 | 0 / 403 | S FIN(10)→C FIN(11) |
| http403-2 | 12 | 1→2→3 | 0 | 0 / 403 | S FIN(10)→C FIN(11) |
| http403-3 | 13 | 1→2→3 | 0 | 0 / 403 | S FIN(10)→C FIN(11) |

정상·403의 재전송은 모두 0회다. `http403-3`의 13번째 프레임은 양방향 FIN 이후
클라이언트의 최종 ACK이며 제외하지 않았다. 다른 정상/403 회차는 12프레임이었다.
DROP은 같은 신규 연결 하나에서 SYN 4개(초기 1+재전송 3), 실제 DROP 카운터도 4개였다.
RST는 SYN과 서버 RST/ACK 2개, REJECT 카운터 1개였다.

DROP curl 전체 시간은 4.001326 / 3.999891 / 4.001134초이며 HTTP 송수신 전 connect timeout이다.
RST는 curl 7, stderr의 연결 거부와 PCAP RST/ACK를 함께 확인했다.
SYN→RST 관측 간격은 30 / 22 / 22µs이며 이 값은 해당 VM 경로의 패킷 간격이다.
정상·403 curl 전체 시간은 0.000560~0.000903초였다. 서버 최초 SYN-ACK까지의 간격과
HTTP 요청 완료 시간을 혼동하지 않는다.

모든 PCAP magic은 `d4c3b2a1`로 **마이크로초 해상도**다. TShark의 소수 9자리 뒤 000은
나노초 정확도 근거가 아니다. 같은 VM이라도 스케줄링·bridge·오프로딩 영향을 받으며,
호스트/커널 시계의 절대 오차나 AWS 경로 성능으로 일반화하지 않는다.

### 증거 해시

원본은 ignored `network/lab/runs/`에 보존한다. summary→회차 manifest→파일 해시로 연결하며
각 manifest 자체 SHA-256도 별도 파일에 있다. 아래 해시는 바이트 동일성을 확인하는 값이며
발급 주체 인증이나 원본의 외부 공개를 뜻하지 않는다.

- 최종 `summary.json` SHA-256: `73431b7fe89447b373fa172861c53511061f9c45fd64e9d26897ecda69068596`

| 회차 | capture.pcap SHA-256 | manifest.json SHA-256 |
| --- | --- | --- |
| normal-1 | `c4d2bab8fb75aa26cda504e4e65573fabaecf3d73108670e515aa129073d7aa7` | `bb0fb4ac46663c8696bffddb97db5ba480e19710f2618f5fd4e4d38a43a4a38f` |
| normal-2 | `1b7919fd94043fedab9dc33c2d758bd33ff2a4af4f795edc6aa2afa09d09103e` | `e7280956065ebe06b8b57f5e572f3c4cbde14b63f4ecbb8cf7e7aa0bbe4c7088` |
| normal-3 | `15bb44d4e6fe31bd47a460ddddc707732d2161c15f5570f6762b732af98b7744` | `2913a70eaf3bdf2a6b29cb9668a1388028033aec9099ec721954c04e294b8ec8` |
| drop-1 | `7fc1d2ef0833ca1c927ee02266fc995bc728e35d07cc23d564c0a7cae397db1d` | `e1fbf453e66da53fa040584f1e43c18bf70764ebd9485e6bd03c66599afe1c26` |
| drop-2 | `20191e0f12fe9b2632bf7fda636818805e759aa81d35e07aa7a4fc5404ea60b6` | `4d975616a277d8147e2ef98187cce1c06d61f0dfe653fe454b38d14be10edb9f` |
| drop-3 | `08d26dc3e7e68bcea22897425907e2adc1508a562c5c7f10acce65cf2799986a` | `49d93483eb2fee51037c5179d869bf69a355e11f1917fd600b9a8db171cd8390` |
| rst-1 | `33f1dfc155e10621bd5e4042cf60f157a2cc432766ed2a5d17ff44b2a6eb5c16` | `999dda1e21e8d4eb6ea38c7b1d0a13070fb0ec533f7fc91032399571087176d0` |
| rst-2 | `ceebbebbbb6199a4f5b70be5e52baa45460dd0bda4be6f27904f9dc2d243d7df` | `0cdc5c3cd4c3b3d3a7c2a8cd3376c0aabc1770f5a7341457dee1f59203e8c28c` |
| rst-3 | `f8a6d657bfa58f374be8e60909f726f380759f9bd80838ca1be3dfb90f05421e` | `f7a2cd506b9104e5725c861a1a9ff9c6cdec44fd0faecaa34e33118b77e7b550` |
| http403-1 | `45d2996acf82a33f672db58ed3d0b0e644548efdbc1e4468c5c0b5c59d210178` | `e5825153b1a5a60160f66e38708e765a87063db1dc68606786276a20efbab6a0` |
| http403-2 | `99ca399af083f7f1fbe8f8e0a59f3daae32d051dadb72cc402e473405b381d42` | `722da407329b76759b7d709f4420ca7b48d845a2afbb5a4dc285d32e5f9228f8` |
| http403-3 | `b8bc660d4b10cf6dfd8308aa045423232eb3bceac7552a258b782cd27f7bc933` | `73f7f63f111908925854f8a87d75dc1300148a715b2ad0863989b1712b4bf862` |

실패 묶음도 summary 해시로 식별한다. 회차별 상세 해시는 각 보존 manifest에 있다.

| 실패 묶음 | summary.json SHA-256 |
| --- | --- |
| 20261102T005957Z-3cc558948671 | `8f99daa3f62f3838a12e6811375987070bcb555293bbc8cd5bbd9c355e2c7805` |
| 20261102T010035Z-97807bd1b806 | `6b178fe720b59457bc0ff2bc0506ed5808571adb1af6ae8578d9b1e6999dcfec` |
| 20261102T010204Z-4c46ccb4f68b | `6449b6373cb6b5be9309ed25ecd92594fe8be1e8576e651a8301600bd918fbc6` |
| 20261102T010355Z-156ac597e142 | `526c9f2863ff28361a1cca8d437549326ba918ab3e9336033049e62d4073ca7a` |

보존 컨테이너 회수본 `normal-1-recovered/manifest.json` SHA-256: `6093e0ca9efddc52f595fd843b31c3c3b3cfcdc3ea19d2952a502066bc7d5a04`. 원래 실패 manifest와 연결하며 실패 상태는 유지한다.
