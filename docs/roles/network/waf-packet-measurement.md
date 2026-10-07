# WAF 차단 패킷 실측 준비

- Notion Task: https://notion.so/3e904d37c225815bbc8bcc63603f5323
- GitHub Issue: https://github.com/mmmphyun/aleph-project/issues/141
- 기준: 2026-10-07 main `379bfcf48f3b83c9470ec5ebc81c1efbfdee8876`
- 상태: **환경 준비 전, 실측 미수행**. 사용자가 준비 산출물 작성을 승인했다.

## 요구사항과 확인한 사실

노션 본문은 IPSet 차단 적용 시점의 HTTP 트랜잭션·TCP 패킷 실측과 Wireshark 보고서를
요구한다. 본문에는 대상·승인 한도·복구 정보가 없다. 원래 보고서 경로
`network/reports/2026-09-29-waf-block-packet-analysis.md`는 보존하되 날짜는 티켓의
예정 산출물 이름이며 실제 실행일을 의미하지 않는다. 아래 유한 계획은 **제안**이다.

| 확인 항목 | 현재 코드 및 근거 | 실측에 남은 확인 |
| --- | --- | --- |
| 선행 네트워크 | PR #125 머지, `web_dir_scan.sh`의 경로 순서·중복·간격·전체 한도 보완 | 반복 요청은 고유 경로 수가 아님 |
| Web 연결 | PR #123/#127/#133/#135 머지. #135 merge `7d68bc8`, 2026-10-07 03:22:58 UTC | 배포된 Lambda 코드 해시·환경·버전 |
| 수집 | `nginx.conf` cloudshield_combined → `/var/log/nginx/access.log` → CW Agent `/cloudshield/target/nginx-access-log`, flush 2초 | 실행 인스턴스의 설정·구독 필터 실제 설치 여부 |
| 라우팅 | `cw_processor.py` 및 `orchestrator.py`가 logGroup 기반 Nginx 파싱 | 실제 로그 스트림·이벤트 ID와 전달 지연 |
| 정책 | `rules.py`의 의심 고유 경로 ≥5, 실패 고유 경로 ≥3, 동일 IP의 10초 창 양 끝 포함. 실패는 401/403/404 | 실제 응답·서버 이벤트 시각으로 기존 함수 검증 |
| 수집 차이 | `NGINX_SUBSCRIPTION_FILTER_SPEC`는 401/403/404 선택. `/health`는 access_log off | 성공 경로가 수집에서 빠져 계획 5개가 누적 5개를 보장하지 않음 |
| 영속 창 | `WebAttackWindow`의 DynamoDB 버킷·청크·TTL 및 이벤트 ID 중복 억제, 참조 시각 기반 조회 | 배포 테이블·권한·장애·역순 전달 운영 확인 |
| 보고서/차단 | Web 매퍼가 BLOCK_WAF 생성. 오케스트레이터가 `apply_remediation` 호출 | WAF의 clientIp와 Nginx source_ip, 등록 /32 일치 |
| 결과 | `block_ip_wafv2`가 최신 LockToken 조회·주소 병합·갱신/멱등 성공 후 True. 결과는 waf_blocked 등 불리언 | 이미 등록된 주소의 True도 있음. API 완료 시각·실제 효력 시각은 별도 증거 필요 |
| 알림 | Web 대응 결과를 `send_slack_alert`에 전달, webhook 없으면 생략, 알림 장애는 차단과 격리 | 실제 Slack 연결·시각·사건 식별자. 이 작업은 발송하지 않음 |
| 식별자/시각 | CW event.id/밀리초 timestamp, Nginx 초 단위 timestamp_str, INCIDENT ID `INC-<epoch 초>-<IP 끝 4자리>`, Lambda 실행 로그 | Incident ID 단독 고유성을 가정하지 않고 AWS RequestId·source_ip·rule·event.id를 함께 대조 |
| 인프라/배포 | 루트 Terraform의 VPC/EC2/WAF 결합은 주석 상태. main CI 성공은 lint/테스트이며 배포 job 없음 | WebACL association·IPSet rule·보호 리소스·배포 실행 기록 |

읽기 전용 정찰 범위는 `src/contracts`, `src/detection`, `src/collector`, `src/remediation`,
`src/reporter`, `infra`, `.github`이다. 해당 영역·공통 데이터·의존성은 수정하지 않는다.
과거 `web-dir-scan.md`의 2026-10-02 SSH 중심 설명은 당시 기록이며 현재 상태는 위 표다.
공통 모델·탐지 함수를 새로 정의하지 않는다.

## 실측 전 확정할 승인 범위

모든 값이 정해진 실행 명세를 먼저 제시하고 그 승인 범위 내에서만 실행한다.
환경이 준비 전이므로 이 문서의 예시·한도는 실행 승인으로 취급하지 않는다.

| 필수 항목 | 현재 상태 | 실행 전 기록 |
| --- | --- | --- |
| 계정·리전·테스트 VPC/EC2·Lambda·테이블 | 미확정 | 승인자·계정·리전·리소스 ID·배포 버전 |
| 보호 경로 | 미확정 | 클라이언트 → ALB/CloudFront 등 WAF 연결 대상 → Nginx, WebACL/IPSet ARN·scope·룰 ID·우선순위 |
| URL·포트·주소 | 미확정 | 단일 정확한 origin, 정상 확인 경로, 인증 없는 합성 후보, 승인 DNS 응답·접속 IPv4 |
| IP 의미 | 미확정 | 클라이언트 주소·NAT 후 주소·프록시·forwarded-IP 설정·공유 여부·WAF clientIp와 /32 |
| 캡처 | Windows에 tcpdump/tshark/dumpcap 미확인 | 장비·위치·단일 인터페이스·권한·도구 버전·BPF·snaplen |
| 실행 한도 | 미승인 | 시간대·1회·최대 요청 수·간격·동시성·timeout·총 시간·패킷/바이트 상한 |
| 변경/복구 | 미확정 | 자동 IPSet 추가 및 알림 영향, 담당자·복구 권한·절차·기존 주소 스냅샷 |

공유 IP이면 다른 사용자가 함께 차단될 수 있으므로 전용 출발지와 승인 여부를 먼저 확정한다.
Nginx `$remote_addr`가 로드밸런서 주소이면 이를 차단해도 기대한 클라이언트 차단이 아닐 수 있다.
forwarded IP의 신뢰 설정·WAF 판정 주소를 보안/클라우드 담당자가 확인해야 한다.
원본 직접 접근은 보호 경로 검증이 아니므로 대체하지 않는다.

## 유한한 실험 계획 제안

HTTP/1.1, 동시성 1, 자동 재시도 0, 리다이렉션 0, 인증/쿠키 없음, 요청 timeout 3초,
1회 최대 21요청, 요청 단계 90초·캡처 120초를 제안한다. 복구는 담당자가 수행하며
90초 내 완료가 안 되면 요청을 멈추고 복구 확인은 별도 승인 시간대로 남긴다.
단계가 실패하면 이후 요청은 중지하고 이미 관측한 결과를 보존한다.

| 순서 | 최대 요청 | 목적 및 기록 |
| --- | ---: | --- |
| 1 기준선 | 2 | 동일 정상 경로 1회는 지속 연결 세션 A에서 실행 후 유지, 1회는 별도 새 세션 B. 응답 상태·실제 TCP 4-tuple 기록 |
| 2 룰 재현 | 5 | 기존 후보 admin/login/dashboard/api/backup 각각 1회, 간격 0초, 순차. 실제 수집 이벤트가 기존 룰 조건을 충족했는지 확인; 부족해도 자동 추가 금지 |
| 3 대응 확인 | 0 | 사건·룰·Lambda RequestId·대응 결과·IPSet API/주소 증거 조회. API 성공은 차단 효력으로 간주하지 않음 |
| 4 정상 경로 탐침 | 10 | 1초 이상 간격, 응답 지연 포함. 매번 새 세션. 승인된 차단 응답 관측 시 반복 종료. 미관측이면 한도 종료 |
| 5 연결 비교 | 2 | 세션 A에서 정상 경로 1회, 새 세션 C에서 1회. A가 끊겨 라이브러리가 새 연결을 만들면 재사용 실패/새 연결로 기록 |
| 6 복구 확인 | 2 | 담당자가 승인된 /32만 제거한 뒤 동일 정상 경로에서 새 연결·유지 연결 응답 확인. 회복 미확인은 미확인으로 종료 |

전체 한도에는 확인 요청도 포함한다. 요청 5개가 의심/실패 고유 경로 5개를 의미하지 않는다.
현재 수집 필터에서는 5개 중 성공·리다이렉션 응답이 빠질 수 있다. 서버 응답 지연으로
10초를 벗어나거나 실제 실패 고유 경로가 부족하면 이번 실행은 탐지 미충족으로 보고한다.
기존 `NginxAccessLogEvent.parse_line`, `matches_subscription_filter`, `evaluate_web_rules`로
사후 확인하며 네트워크 코드에 정책을 복제하지 않는다.

세션 A는 동일 프로세스의 persistent HTTP/1.1 클라이언트로 요청 사이 소켓을 유지해야 한다.
각 요청에 새 curl 프로세스를 시작하는 기존 스크립트는 세션 A 실험에 사용할 수 없다.
자동 reconnect 및 연결 재사용은 패킷의 주소/포트·SYN 생성 기록으로 검증한다.
TCP stream 번호는 파일마다 로컬 식별자이므로 다른 PCAP의 stream 번호를 결합하지 않는다.
HTTP/2는 별도 설계 없이는 사용하지 않으며 HTTP/3·QUIC/UDP는 TCP 분석에서 제외한다.

## 기존 도구 재사용과 원격 지원 설계 경계

`web_dir_scan.sh`의 기본 dry-run·명시적 --execute·loopback 제한과 유한 후보 계획은 유지한다.
`tcpdump_capture.sh`는 단일 IPv4/포트/인터페이스·새 출력·시간/패킷 제한을 제공하지만
**캡처 준비 확인·바이트 상한·요청 연동·기본 dry-run을 제공하지 않는다**. 두 스크립트를
그대로 묶어 원격 실측 준비가 끝났다고 주장하지 않는다. 이번 변경은 오프라인 분석만 추가한다.

원격 지원이 필요한 다음 단계의 최소 설계는 승인 명세의 정확한 origin/포트/IPv4만 허용하는
별도 실행 경로다. 현재 loopback 제한은 완화하지 않는다. DNS 결과를 사전에 대조하고 승인
IP에 접속을 고정하면서 TLS 호스트명 검증을 유지한다. 프록시·redirect·curl 설정 파일·재시도와
사용자 인증 헤더를 끈다. 다른 DNS 주소·새 목적지는 fail closed로 거부한다.
manifest에는 경로·요청 수·간격·동시성·timeout·총 한도·인터페이스·고정 필터·새 출력·용량을
검증한다. 캡처의 listening 증거 및 PID 생존을 확인한 뒤 요청을 시작하고 죽으면 후속 요청을 멈춘다.
캡처와 요청의 소유 PID만 추적하여 정상/연결실패/timeout/도구실패/중단을 구분한다.
자체 임시 파일만 정리하고 부분 PCAP/관측 기록·기존 파일은 보존한다. 자동 sudo는 하지 않는다.

용량은 패킷 수만으로 승인됐다고 간주하지 않는다. 예컨대 classic PCAP snaplen ≤262144,
200패킷이면 24+200×(16+262144)=52,432,024바이트 상한이다. 실제 포맷·snaplen 확인이
전제이며 별도 바이트 감시를 더해야 한다. payload 전체가 불필요하면 제한된 snaplen을 선택하되
TCP 옵션·IPv4 헤더 절단 여부와 분석 한계를 기록한다. PCAPNG에는 이 계산을 적용하지 않는다.
클라이언트 전용 장비의 해당 흐름만 캡처하고 다른 사용자 트래픽을 섞지 않는다.
현재 캡처 스크립트는 임의 BPF를 받지 않으므로 승인 범위보다 넓으면 사용하지 않는다.

## 시각과 차단 원인

요청 송신/응답 수신, Nginx 이벤트, 탐지/대응 시작, IPSet API 완료, 첫 차단 응답,
FIN/RST 시각을 각각 적는다. 없는 시각은 null/미확인으로 두고 Incident ID의 초 값을
탐지 시작으로 대입하지 않는다. Lambda 로그 시각도 API 응답 직후 로그 관측 시각과 구분한다.
UTC epoch를 기본으로 장비 timezone·NTP 오프셋·정밀도·스케줄링 오차와 캡처 drop을 기록한다.
서버 로그는 초 단위이고 CW는 밀리초여서 정밀도와 이벤트 의미가 다르다.

마지막 미차단 탐침과 첫 원인 확정 차단 탐침 사이가 전환 관측 구간이다. 요청/응답
지연과 양 장비 시계 오차를 포함해 구간을 넓혀 보고하며 중간 누락·timeout이 있으면 경계를
좁히지 않는다. 여러 WAF 지점의 전파는 달라질 수 있어 이후 모든 요청의 차단을 보증하지 않는다.
AWS는 IPSet 변경이 수초~수분 전파되고 지점별 결과가 달라질 수 있음을 설명한다.
[AWS WAF 변경 전파 및 사용자 지정 응답](https://docs.aws.amazon.com/waf/latest/developerguide/waf-custom-request-response.html)

403은 클라이언트에서 관측한 상태일 뿐 원인 확정이 아니다. WAF 로그의 action=BLOCK,
terminatingRuleId, httpRequest.clientIp/requestId, 시간·URI·method를 제한된 관측 기록과 대조한다.
정상 확인 경로와 다른 룰 차단을 혼동하지 않는다. 원본 로그의 부재만으로는 WAF 차단 증거가
되지 않는다. custom block response, CloudFront 오류 변환이 있으면 403 외 상태도 가능하다.
증거가 부족하면 **403 관측, WAF 원인 미확정**으로 쓴다.
[AWS WAF 로그 필드](https://docs.aws.amazon.com/waf/latest/developerguide/logging-fields.html),
[사용자 지정 차단 응답](https://docs.aws.amazon.com/waf/latest/developerguide/customizing-the-response-for-blocked-requests.html)

## 오프라인 TCP 분석

`network/waf_packet_timeline.py`는 아래 순서의 헤더가 있는 CSV만 읽는다.
실측 전 도구 버전별 필드 지원과 classic CSV 헤더/구분자 설정을 확인한다.
이는 PCAP을 직접 파싱하거나 tcpdump/tshark를 실행하는 도구가 아니다.

```text
frame.time_epoch,tcp.stream,ip.src,tcp.srcport,ip.dst,tcp.dstport,tcp.flags.syn,tcp.flags.ack,tcp.flags.fin,tcp.flags.reset
```

Wireshark/tshark에서 승인 PCAP의 IPv4 TCP 단일 흐름들을 필터링한 뒤 해당 필드만 내보낸다.
TLS 복호화 키·HTTP 헤더/쿠키·응답 본문은 수집하지 않는다. QUIC·IPv6는 이 분석기 범위 밖이다.
신뢰하는 저장소에서 새 JSON 출력 경로를 지정한다.

```bash
python network/waf_packet_timeline.py sanitized-tcp.csv new-timeline.json --start 1791331200 --end 1791331320
```

위 명령은 오프라인 형식 예시이며 실제 파일·시각을 의미하지 않는다. 입력 1MiB/10000행 상한,
IPv4·포트·플래그·관측 구간·스트림의 주소/포트 일치 검증을 적용한다. 입력 역순은 정렬하되
그 사실을 보고하고 중복/재전송은 삭제하지 않는다. 오류 시 원시 행이나 경로를 콘솔에 출력하지
않으며 실제 도구로 폴백하지 않는다. 출력은 독점 생성하여 기존 파일/심볼릭 링크를 보존한다.
SYN/ACK 목록은 핸드셰이크 후보이고 seq/ack를 원본 PCAP과 대조해야 완전한 3-Way 확인이 된다.
FIN은 한 방향 종료, RST는 해당 송신 주체의 재설정 흔적이며 WAF의 강제 종료 판정은 아니다.
플래그 미관측은 패킷 누락·캡처 시작 전 연결·종료 후 이벤트와도 양립한다.

합성 CSV 모의 검증과 기존 mock curl/tcpdump 테스트는 실측 PCAP 증거와 분리한다.
새 기능은 시간 경과를 기다리지 않고 입력 epoch로 검증하므로 공유 시계 파일을 새로 사용하지 않는다.
기존 시간 테스트는 임시 시계 값을 원자적으로 교체하는 PR #125 구현을 재사용한다.

## 증거 보관과 협업 대기

원본 PCAP·TLS 키·인증 정보는 커밋하지 않는다. 응답 본문·Authorization·Cookie는 콘솔/증거에서
제외하며 run_id·요청 순번·phase·승인된 path·송수신 UTC·HTTP 버전/상태·연결 tuple과 제한된
관측 메타데이터만 남긴다. 원본 서버/WAF 기록도 필요한 필드만 추출해 비공개 보관한다.
공유 보고서에는 식별자·SHA-256·보관 위치·권한·보존기한을 쓰며 공개 IP는 검토 후 마스킹한다.

클라우드 A에는 배포·Lambda/테이블/IPSet 연결과 API/실행 식별자 증거를, 클라우드 B에는
실제 수집 설정·원본 로그·Slack 결과를, 보안에는 WebACL 연결·차단 룰·client IP 판정·custom
response를 확인받는다. 새로운 타 직무 이슈를 임의로 만들지 않는다.
사용자 확정 환경이 준비되면 실행 명세를 구체화하고 누락된 승인만 확인한다.
실제 실측·복구·10초 E2E 검증은 모두 남아 있으며 Draft PR로 리뷰를 기다린다.
