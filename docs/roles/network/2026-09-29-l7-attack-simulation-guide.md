# Stateful SG 교체와 기존 TCP 연결 유지 한계: 실측 준비 및 분석 보고서

- Notion Task: https://notion.so/3e904d37c2258128b5a0cd5e28418d9e
- GitHub Issue: https://github.com/mmmphyun/aleph-project/issues/146
- 작성 기준: 2026-10-08 KST, main `703caeb7a0e278b228b1a57a59c968d7cd6cfc19`
- 상태: **준비 산출물 작성, 실제 AWS 실측·SG 변경·복구 미수행**
- 파일명의 2026-09-29는 노션 지정 산출물 이름이며 실측일이 아니다.
- 준비 작성 승인: 사용자의 “알았어 시작하자”. AWS 대상 접속·SG 변경 실행 승인은 없음.

## 노션 요구와 준비 제안의 구분

노션 GET 조회로 상태 `시작 전`, 담당 네트워크, 일정 2026-10-06~10-09를 확인했다.
본문은 “L4 SG 교체 시 커널 conntrack 세션 유지 현상 실측”, L4+L7 복합 차단 분석,
이 문서 경로 및 보안 리뷰어 `gkacksdnjs22-stack`을 지정한다. 환경·실행 한도·복구
정보와 network/ 하위 보고서 경로는 지정하지 않았다. 노션 속성·상태를 직접 변경하지 않았다.

AWS SG의 connection tracking, 호스트 커널 conntrack, TCP 소켓 ESTABLISHED는
서로 다른 상태다. 호스트 상태만으로 AWS 추적 상태나 실제 데이터 전달을 증명하지 않는다.
노션의 목적을 결과로 미리 확정하지 않고 유지·전달 중단·정상 종료·재설정·관측 내 종료 없음·
증거 부족을 모두 허용한다. 아래 한도와 실행기는 **에이전트 제안**이며 AWS 실행 승인이 아니다.

## 코드 머지·배포·데이터 플레인 검증

PR #142는 2026-10-07 07:45:45 UTC에 머지됐다. 준비 문서·TCP CSV 분석기가 머지된
사실만 확인했으며 당시 실제 WAF 패킷 실측·차단·복구는 수행하지 않았다.
이번 main 최신화는 reporter 변경 등을 포함하지만 SG 엔진의 아래 동작은 그대로다.

| 항목 | 현재 main 코드에서 확인 | 실측 전 필요한 증거 |
| --- | --- | --- |
| SG 액션 | `IncidentReport.action_required`의 QUARANTINE_EC2, BLOCK_AND_QUARANTINE | 실제 사건 action·incident_id·source_ip·target_identifier |
| 사건 대상 | orchestrator는 logStream이 i-로 시작하면 사용, 아니면 TARGET_INSTANCE_ID 및 fallback | 실제 CW logGroup/logStream/event.id·timestamp, 환경 변수·배포 버전; fallback을 실험 대상으로 채택하지 않음 |
| EC2 조회 | `quarantine_ec2_instance`가 describe_instances로 VPC·SecurityGroups 조회 | 실제 계정·리전·인스턴스·모든 ENI·DeviceIndex·주소·경로 |
| 변경 대상 | modify_instance_attribute(InstanceId, Groups=[격리 SG]); ENI ID 직접 선택 없음 | 주 ENI와 관측 서비스 ENI 일치 여부, 변경 후 각 ENI의 실제 SG 목록 |
| 변경 방식 | 기존 SG 목록을 단일 격리 SG로 대체; 추가 방식 아님 | 변경 전 목록을 ENI별 비공개 보존, 동시 변경 여부 |
| 격리 규칙 | describe_security_groups의 IpPermissions와 IpPermissionsEgress 모두 빈 목록 요구 | 실제 GroupId·VpcId·양방향 규칙·조회 시각, 동일 VPC 여부 |
| 멱등성 | SG 규칙 재검증 후 현재 목록이 격리 SG 하나이면 쓰기 없이 True | True가 이번 API 호출·데이터 차단·기존 연결 종료를 의미하지 않음 |
| 실패 | SG 조회·검증·변경 ClientError를 로그 후 None/False로 반환 | 단계별 오류·AWS request ID, 실패를 성공으로 취급하지 않음; 계층 간 완전 롤백 없음 |
| 결과 기록 | quarantine_applied/waf_blocked/iam_revoked 불리언, orchestrator incidents/remediation_results | API 시작·완료·설정 조회 시각과 RequestId를 별도 확보; 엔진 반환에 타임스탬프·ENI·원래 SG 없음 |
| 동반 조치 | BLOCK_AND_QUARANTINE은 SG와 WAF, QUARANTINE_EC2는 SG. IAM 경로는 TODO로 False | 자동 실험은 WAF·Slack·DynamoDB 마킹 및 영향 범위를 함께 승인 |
| 자동 트리거 | SSH_BRUTE_FORCE → BLOCK_AND_QUARANTINE; Web 룰 → BLOCK_WAF; SSH_PASSWORD_SPRAYING → BLOCK_IP_ONLY | 합성 TCP echo만으로 탐지가 발생한다고 가정하지 않음 |
| Slack | webhook 설정 시 대응 결과 전달; 알림 실패는 차단과 격리 | 실제 발송·수신 증거는 없음. 이 작업은 Slack 발송하지 않음 |
| 복구 | 기존 SG 목록은 로컬 변수/로그, 영구 보존·자동 복구 구현 없음 | 외부 제어 경로·권한·담당자·원래 SG 스냅샷 필수 |
| 인프라 | Terraform 루트 VPC/EC2/WAF 결합은 주석. CI는 검사·테스트 | apply 기록·배포 코드 해시·실제 리소스 조회 없으므로 배포 완료 미확인 |

읽기 전용으로 `src/contracts/`, `src/detection/`, `src/remediation/`, `src/reporter/`,
`tests/unit/test_remediation.py`, `infra/`, `docs/roles/cloud-a/`를 확인했다.
계약·정책·영속 창·격리·복구 엔진을 네트워크 영역에 복제하지 않는다.
클라우드 A의 2026-09-10 문서 “검증 완료”는 moto 제어 API 테스트이며 실제 AWS 패킷
차단·복구 증거가 아니다. 원자적 SG 목록 교체와 다계층 트랜잭션 롤백도 구분한다.

## AWS 공식 문서의 적용 조건

2026-10-08 조회 기준, AWS는 tracked 연결이 SG 규칙 변경 후에도 timeout까지 허용될
수 있음을 설명한다. 넓은 양방향 TCP 허용 규칙은 자동 추적 예외가 없을 때 untracked가
될 수 있고, 이를 허용한 규칙 제거는 기존 흐름에 영향을 줄 수 있다. 모든 SG에 일반화하지 않는다.
NAT Gateway·NLB·PrivateLink 등은 자동 추적 조건에 포함된다. 실제 경로·모든 연결 SG의
규칙을 대조하지 못하면 tracked/untracked는 **판단 불가**로 기록한다.
[EC2 connection tracking](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/security-group-connection-tracking.html)

SG 연결 교체는 규칙 편집과 다른 작업이다. SG는 ENI에 연결되며, 인스턴스 SG 변경은
주 ENI와 관련된다. ModifyInstanceAttribute의 Groups는 목록을 교체하고, 다중 ENI에서는
오류가 날 수 있어 AWS는 ENI API 사용을 권고한다. 현재 엔진이 관측 ENI를 명시적으로
선택하지 않는 한계를 클라우드 A와 확인한다. API를 바꿔 대신 구현하지 않는다.
[SG 변경](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/changing-security-group.html),
[ModifyInstanceAttribute](https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_ModifyInstanceAttribute.html)

ENI의 TcpEstablishedTimeout과 인스턴스 유형을 기록한다. 현재 문서는 60~432000초,
Nitro v6 기본 350초(P6e-GB200 제외), 다른 유형 기본 432000초를 설명한다.
이 값은 SG 추적 idle timeout이며 호스트 TCP 종료 시간이나 모든 경로의 idle timeout이 아니다.
이번에는 timeout 설정 변경·conntrack 고갈·대량 부하·NACL/호스트 방화벽 변경을 하지 않는다.
능동 송수신이 idle 상태를 바꾸므로 아래 120초 관측으로 idle 수명을 증명하지 않는다.

L4+L7 복합 조치는 각 계층의 서로 다른 통제를 제공할 수 있지만 WAF는 연결된 HTTP
보호 경로에서만 효과를 평가해야 한다. 임의 SSH/TCP 세션의 즉시 종료 수단으로 표현하지
않는다. 합성 echo 실험은 SG 연결 유지 한계만 평가한다. 실제 완전 격리나 10초 E2E 성공은
별도 증거가 필요하다. 타 직무의 통제 확대는 협업사항이며 이번 구현·실험에 포함하지 않는다.

## 실행 전 확정할 승인 명세

기존 WAF 준비 문서와 Docker SSH 실측에는 이번 AWS 대상으로 재사용할 승인이 없다.
아래 값과 승인 기록이 없으면 AWS 접속·트래픽·SG 변경을 실행하지 않는다.

| 항목 | 현재 상태 | 실행 전 기록 |
| --- | --- | --- |
| 계정·리전·VPC | 미확정 | 단일 테스트 계정·리전·VPC 및 승인자 |
| EC2·ENI·주소 | 미확정 | 인스턴스 ID·전체 ENI/DeviceIndex·사설/공인 IP·관측 ENI |
| SG 변경 | 미확정 | ENI별 원래 SG 목록·규칙, 단일 격리 SG ID/VPC·빈 인/아웃 규칙 |
| 경로·출발지 | 미확정 | 클라이언트 실제 IP·NAT 후 IP·서버 경로·NAT/프록시/LB·비대칭 경로 |
| 서비스 | 미확정 | 합성 비인증 TCP echo 등 정확한 프로토콜·단일 포트·연결 정책·서비스 상태 |
| 추적 조건 | 미확정 | 실제 양방향 SG·경로·자동 추적 예외·ENI timeout·호스트 상태 별도 |
| 캡처 | 미확정 | 클라이언트/서버 장비·단일 인터페이스·권한·버전·최소 BPF·snaplen/drop |
| 복구 | 미확정 | 외부 EC2 제어 API 경로·담당자·권한·복구 절차·중단 후 연락 경로 |
| 공유 여부 | 미확정 | 인스턴스·네트워크·IP·SG의 다른 사용자/서비스 영향 |
| 시간·횟수 | 제안만 있음 | 실행 시간대·1회·소켓/메시지 수·간격·동시성·바이트·timeout·관측 한도 |
| 용량·보관 | 제안만 있음 | 장비별 packet/byte 한도·새 출력 경로·비공개 보관·SHA-256·보존 기간 |
| 변경 방식 | 제안: 수동 SG 단독 | 클라우드 A 승인된 제어 경로, 자동이면 WAF/IAM/Slack/마킹 영향 별도 |

빈 아웃바운드 SG에서 SSM이 반드시 유지된다고 가정하지 않는다. 대상 EC2의 SSH/SSM
세션에 의존하지 않는 제어 API 접근과 복구 권한을 사전에 검증한다. 복구 담당자가 없거나
원래 SG/동시 변경을 확인할 수 없으면 실험 시작을 금지한다. 키·토큰은 문서나 콘솔에 넣지 않는다.

## 유한 능동 실험 제안

동시성 1, 실행 1회, 자동 reconnect/retry 0, A/B/복구 R 최대 3소켓, 메시지당 최대 256바이트,
합성 echo 요청 총 8개(최대 송신 2048바이트), 응답도 총 2048바이트를 제안한다.
connect·요청 timeout 각각 3초, A 교체 후 관측 15초, 전체 요청·변경 대기·관측 최대 90초,
캡처 최대 120초. 실제 TCP 재전송/헤더 바이트는 메시지 상한과 별도이며 캡처 한도로 제한한다.
timeout 발생 후 후속 트래픽은 멈추고 A/B 비교 미완료를 기록한다. 실패 후 복구는 승인 담당자만
수행하며 정상 회복 확인은 원래 관측 한도 안에서 가능할 때만 한다; 넘으면 별도 시간대로 남긴다.

| 단계 | 메시지 상한 | 수행·관측 |
| --- | ---: | --- |
| 1 변경 전 | 0 | 계정·EC2/ENI/SG·경로·서비스·관리/복구·시계 오차·도구 버전 기록 |
| 2 기준선 A | 1 | 같은 프로세스의 소켓 A 생성, 3-way handshake 후보·seq/ack 대조, 순번 1 echo 서버 수신/응답 확인 |
| 3 SG 교체 | 0 | 클라우드 A 승인 경로로 SG 교체; API 시작/완료·RequestId·SG 목록 조회·동반 조치 기록 |
| 4 A 능동 관측 | 4 | 같은 소켓 A에서 순번 2~5를 ≥1초 간격으로 송신; 실제 서버 수신·응답 확인; 실패 시 멈춤 |
| 5 새 연결 B | 1 | A와 다른 소켓·클라이언트 포트로 한 번만 connect; SYN/SYN-ACK/ACK 또는 timeout; 성공할 때만 echo |
| 6 A 관측 종료 | 0 | 교체 후 15초 한도까지 기존 소켓·패킷·마지막 정상 왕복 관측; 능동 송신 추가 없음 |
| 7 복구·회복 | 2 | 승인 담당자가 SG 복구·ENI 조회 확인 후 A(아직 유효할 때)와 새 R에서 각 1 echo. A를 재연결하지 않음 |

SG 교체 담당자의 조작 지연도 전체 기한에 포함한다. A의 실패가 먼저 발생하면 B는
미수행으로 남기며 실패를 숨기려고 다시 실행하지 않는다. 비교 전체가 필요하면 별도 승인
실행으로 설계한다. 연결 실패·timeout·도구 실패·사용자 중단·정상 완료를 각각 기록한다.
SG 변경·복구 호출 코드는 네트워크 도구에 구현하지 않는다.

idle 실험은 별도 실행으로 설계한다. A 기준선 후 애플리케이션 송신/keepalive/heartbeat를
중지하고 실제 ENI·NAT/LB·서비스 timeout에 맞는 별도 유한 관측 시간 승인을 받는다.
120초 능동 계획을 timeout 소진 실험으로 확대하지 않는다. HTTP를 선택하면 버전·keepalive·
Connection 헤더·라이브러리 reconnect 정책을 기록한다. HTTP/3·QUIC·UDP는 제외한다.
프록시/LB가 있으면 클라이언트↔중간 지점과 중간 지점↔원본 TCP 연결을 별도 증거로 기록한다.

## 기존 도구 재사용과 원격 실행기 최소 설계

`network/tcpdump_capture.sh`의 입력·단일 인터페이스·시간/패킷 제한·독점 출력·소유 PID
정리를 유지한다. 현재는 dry-run·캡처 준비/생존 연동·바이트 상한이 없어 바로 원격 실측에
묶지 않는다. `ssh_single_connect.sh`는 단일 연결 확인 도구이며 새 프로세스 실행을 A 재사용으로
표현하지 않는다. `network/lab/run.py`의 readiness/소유 프로세스 패턴과 기존 모의 테스트를
확인했지만 Docker/loopback 통신은 AWS SG 데이터 플레인 실측이 아니다.

원격 실행 지원은 환경 승인 후 정확한 숫자형 IP·포트·클라이언트 바인드·A/B 소켓 수·
메시지 수/바이트/간격·동시성·deadline·timeout·인터페이스·고정 BPF·새 출력·용량을 검증하는
별도 실행기를 제안한다. 기본 dry-run과 명시적 --execute를 분리하며 기존 loopback/소유
리소스 제한을 완화하지 않는다. DNS·프록시·리다이렉션·자동 reconnect/retry를 사용하지 않는다.
TCP echo 서버 설치·설정이 필요하면 클라우드 B와 협업하고 대신 수정하지 않는다.

양측 캡처 준비 메시지와 소유 PID 생존·서버 LISTEN을 확인한 뒤 트래픽을 시작한다.
서버 준비 확인을 위해 사전 TCP 연결을 몰래 추가하지 않는다. 캡처 실패·용량 초과·기한·
사용자 중단·주소 변화·SG 동시 변경·관측 소켓 오류에 후속 트래픽을 멈춘다.
자체 PID·임시 파일만 정리하고 부분 PCAP/메타데이터·기존 파일은 보존한다. 모의 명령
실패에 실제 도구·AWS로 폴백하지 않는다. 새 셸 wrapper에는 set -euo pipefail을 적용한다.

복구 담당자는 변경 직전 ENI별 원래 SG 목록·규칙·조회 시각을 비공개 보존한다.
복구 직전 실제 SG 목록이 이번 실행에서 기대한 격리 SG 목록과 같은지 다시 비교하고,
다르거나 규칙/리소스에 동시 변경이 있으면 복구 쓰기를 중단해 소유자와 조율한다.
스냅샷 목록을 무조건 덮어쓰지 않는다. 승인된 복구 실행·API 결과·ENI별 목록을 기록한 뒤
새 연결 R의 handshake/서버 수신/응답을 확인한다. API 성공만으로 정상 회복을 보고하지 않는다.

장비별 classic PCAP을 snaplen 256/최대 2000패킷/120초로 승인한다면 이론적 상한은
24 + 2000×(16+256) = 544024바이트다. 포맷·버전 확인과 별도 바이트 감시를 요구하며
PCAPNG에는 이 계산을 적용하지 않는다. 정확한 IPv4 TCP 클라이언트↔서버/서비스 필터만
허용한다. SYN/옵션/순번 절단 가능성과 payload 256바이트 전체가 보이지 않는 한계를 기록한다.
합성·비인증 메시지만 사용하고 SSH 비밀키·쿠키·Authorization·응답 본문·TLS 복호화 키는
수집하지 않는다. 원본 PCAP은 커밋하지 않으며 비공개 보관 식별자·SHA-256만 보고서에 남긴다.

## 시각·패킷·원인 판별 규칙

장비별 UTC epoch·timezone·NTP 오프셋/최대 오차·정밀도·스케줄링 지연을 기록한다.
시계 오차 미확정이면 장비 간 정밀 순서·지연을 단정하지 않는다. monotonic은 로컬 기한에만
사용하고 장비 간 절대 시각 대체로 쓰지 않는다. 모의 테스트는 합성 시각만 사용한다.
연결/소켓 생성, handshake 완료, 메시지 송신/서버 수신/응답 수신, API 시작/완료,
SG 목록 확인, 최초 전달/전달 실패, 새 연결 handshake/timeout, FIN/RST/재전송,
마지막 정상 왕복, 복구 요청/완료/회복을 서로 다른 이벤트로 남긴다.

API 완료나 SG 목록 확인을 패킷 효력 시각으로 대입하지 않는다. SG 확인 후 새 메시지
송신에 시계 오차 여유를 두며 교체 전 송신의 지연 응답은 따로 표시한다. 탐침 간격으로
변화가 구간으로만 추정되면 마지막 정상/첫 실패와 시계 오차·요청 지연·누락을 포함한
구간만 제시한다. 현재 오프라인 분석기는 효력 발생 시각이나 SG 원인 구간을 자동 산출하지 않는다.

| 패킷·상태 | 확인 내용 | 단정하지 않을 내용 |
| --- | --- | --- |
| SYN→SYN/ACK→ACK | 방향·4-tuple·seq/ack·캡처 위치별 기록 | 플래그 후보만으로 handshake 완성 |
| 로컬 send 성공·ESTABLISHED | 클라이언트 로컬 상태 | 서버 수신·양방향 전달 |
| TCP ACK | 전송 계층 수신 확인 범위 | 애플리케이션 메시지 처리·응답 |
| 순번 echo | 같은 소켓·교체 후 새 송신·서버 수신·응답 메타데이터와 제한된 합성 증거 대조 | 교체 전 요청의 지연 응답을 새 전달로 판정 |
| FIN | 송신 주체·half-close·후속 ACK/FIN | SG가 강제 종료 또는 완전 종료 |
| RST | 실제 송신 주체·소켓/서비스 상태 | SG 원인 확정 |
| 재전송·무응답 | 같은 tuple/seq·관측 위치·timeout·drop | 재전송 단독으로 SG 원인 확정 |
| FIN/RST 미관측 | 캡처 completeness·종료 전 관측 끝 | 영구 유지; 표현은 “관측 구간 내 종료 없음” |

클라이언트 close는 관측 종료 후 별도 표시하고 종료 원인으로 분리한다. 서버 idle timeout·
NACL·호스트 방화벽·서비스 장애·라우팅·NAT/프록시·다른 SG·동시 변경을 가능한 증거로
대조한다. VPC Flow Logs는 집계 구간·지연·상태/필드 한계가 있어 TCP handshake·앱
처리·정확한 전환 시각의 대체 증거가 아니다.
[Flow Logs 한계](https://docs.aws.amazon.com/vpc/latest/userguide/flow-logs-limitations.html),
[Flow Logs 레코드](https://docs.aws.amazon.com/vpc/latest/userguide/flow-log-records.html)
근거가 부족하면 “SG 교체 후 전달 실패 관측, 원인 미확정”으로 쓴다.

## 오프라인 메시지 분석 인터페이스

`network/sg_connection_timeline.py`는 네트워크·AWS·캡처 도구를 실행하지 않는다.
기존 `waf_packet_timeline.analyze_csv`로 동일 캡처의 TCP 필드를 분석할 수 있다.
TCP stream 번호는 파일마다 로컬이므로 서로 다른 PCAP 번호를 결합하지 않는다.
TCP 결과의 HTTP/WAF 판정 불가 필드는 기존 모듈 그대로 유지하며 SG 판정으로 바꾸지 않는다.

입력 CSV 헤더 순서:

```text
event_id,connection,socket_id,client_ip,client_port,server_ip,server_port,sequence,event,epoch,bytes
```

event_id/socket_id는 1~999999999 정수, connection은 A(기존)/B(새)/R(복구 새 연결).
단일 IPv4 클라이언트·서버·서비스를 요구하며 연결별 소켓/4-tuple은 고정한다.
서로 다른 연결은 소켓 ID와 클라이언트 포트가 달라야 한다. sequence는 메시지 1~20,
bytes는 **합성 echo의 앱 바이트** 1~256이며 send/server_receive/response_receive/tcp_ack에
사용한다. 나머지 상태 이벤트 socket_open/timeout/socket_close/socket_reset/observed_established는
sequence=bytes=0이다. TCP ACK를 메시지에 연결할 수 없으면 sequence를 임의 추정해 입력하지 않는다.
시각은 초 단위 epoch 소수 9자리 이내. 자유 텍스트·payload·인증 정보 필드는 거부한다.
분석기는 NAT/LB의 tuple 변환을 추론하거나 주소를 자동 치환하지 않는다. 양단 tuple이 다르면
그 기록을 하나의 동일 tuple CSV로 억지 병합하지 않고 별도 분석과 확인된 변환 증거로 대조한다.

입력당 1MiB/10000행, 관측 최대 120초, 장비별 최대 절대 시계 오차 0~5초를 검증한다.
알려진 상한 오차를 입력해야 하며 모르면 0으로 대신하지 않는다. 각 connection 20메시지
상한은 분석 입력 한도이고, 위 실측 제안의 총 8메시지보다 넓다. 분석기가 실제 실행 계획을
승인하거나 송신을 제한하는 실행기는 아니다. 다른 오차/시간대 계획은 별도 설계가 필요하다.

CSV는 제한된 메타데이터를 사람이 허용 필드로 내보낸 입력이다. socket_id는 선언이며
동일 실제 소켓·메시지 body 일치 증명은 생성 로그·SYN·tuple·합성 echo 증거로 별도 대조한다.
메타데이터상 동일 socket_id를 재사용해 적는 거짓 입력을 자동 판별할 수 없다.
baseline 왕복/생성 기록이 없으면 기존 A 유지 판정을 보류한다. 새 소켓 생성 기록도 별도로
표시하며 B의 SYN/handshake/timeout은 TCP 결과·실행 로그와 대조한다.

```powershell
uv run python network/sg_connection_timeline.py <비공개-events.csv> <새-report.json> `
  --packets <허용-TCP-fields.csv> --start <epoch> --end <epoch> `
  --change-start <epoch> --api-complete <epoch> --sg-confirmed <epoch> --clock-error <초>
```

--packets는 선택이며 기존 모듈의 10개 TCP 필드 CSV만 허용한다. 시각·내용 검증 후
독점 새 파일로 생성하고 입력 SHA-256을 남긴다. 오류는 원문·경로·토큰 없이 exit 2로
전파하며 부분 출력은 삭제하지 않는다. 동일 event_id의 동일 기록은 중복 수로 표시하고
대조에는 한 번만 사용한다. 충돌 ID·재연결·두 번째 소켓 생성·중복 메시지 단계·바이트
불일치·시계 오차로 설명 불가능한 역인과·생성 전/종료 후 클라이언트 송신/응답 수신은 거부한다.
송신→서버 수신→클라이언트 응답 수신의 모든 선후 단계 쌍에 같은 2×clock_error
한도를 적용한다. 인접 단계마다 오차를 누적해 송신→응답의 더 큰 전체 역전을 허용하지 않는다.
클라이언트 소켓 수명은 같은 장비의 생성/close/reset/송신/응답 수신 시각으로 대조하며
장비 간 오차를 종료 후 앱 수신의 허용 여유로 사용하지 않는다. 서버의 지연 수신과
캡처 TCP ACK는 클라이언트 close 후에도 가능하므로 소켓 수명 제한을 동일하게 적용하지 않는다.
역순 입력은 표시하고 정렬하며 누락은 증거 부족으로 남긴다. 교체 후 새 송신은 SG 확인
시각보다 장비 오차의 2배를 넘어 늦은 경우만 후보로 표시한다. 후보 왕복도 SG 원인을 확정하지 않는다.
기존 TCP CSV에는 seq/ack 번호·tcp.len·재전송 분석 필드가 없다. 동일 플래그 반복을
재전송으로 자동 판정하지 않고 PCAP의 해당 필드·방향·캡처 누락을 수동 대조한다.
서버 측 별도 캡처는 별도 JSON으로 분석하고 장비별 시계 오차와 tuple 변환을 보고서에서 연결한다.

## 실제 관측 결과표: 미측정

현재 아래 실제값은 전부 미측정이다. 합성 테스트의 epoch와 IP를 채워 넣지 않는다.

| 연결·단계 | 생성/tuple/SYN | SYN-ACK·ACK·seq 확인 | 메시지 송신/서버 수신/응답 | FIN/RST·주체·재전송·마지막 왕복 | 결과 |
| --- | --- | --- | --- | --- | --- |
| A 변경 전 | 미측정 | 미측정 | 미측정 | 미측정 | 기준선 미확인 |
| A 교체 후 같은 소켓 | 미측정 | 동일 tuple·새 SYN 여부 미확인 | 새 순번 전달 미확인 | 미측정 | 유지·전달·종료 증거 부족 |
| B 교체 후 새 소켓 | 미측정 | 미측정 | 미측정 | 미측정 | 새 연결 결과 미확인 |
| A/R 복구 후 | 미측정 | 미측정 | 미측정 | 미측정 | 회복 미확인 |

| 제어·환경 사건 | UTC/오차 | 식별자·결과 |
| --- | --- | --- |
| SG 변경 요청·API 완료 | 미측정 | AWS RequestId·instance/ENI/SG 미확정 |
| 변경 후 ENI별 SG 목록 | 미측정 | 목록·규칙 미확인 |
| tracked/untracked 판정 | 미측정 | 조건·경로 미확정으로 판단 불가 |
| 복구 요청·API 완료·목록 확인 | 미측정 | 담당자·원래 SG·권한·동시 변경 대조 미확정 |
| 정상 데이터 회복 | 미측정 | 앱 왕복·PCAP·서비스 확인 없음 |

## 증거 보존·검증·남은 협업

| 증거 | 식별자·SHA-256·비공개 위치 | 상태 |
| --- | --- | --- |
| 승인 명세·시계·도구/프로토콜 버전 | 미확정 | 실측 전 필요 |
| 원래/격리/복구 SG·ENI 스냅샷 | 미확정 | 실측 전/후 필요 |
| 클라이언트·서버 PCAP 및 drop 기록 | 없음 | 미수집, 기본 커밋 제외 |
| 합성 메시지 메타데이터·소켓 로그 | 없음 | 실제 실행 후 필요, body 제외 |
| API RequestId/CloudTrail·사건/CW/Lambda 식별자 | 없음 | 실제 실행 후 필요 |
| 분석 JSON·파생 CSV | 없음 | 실제 증거 확보 후 새 경로 생성·해시 대조 |

사건 ID는 초 단위 생성 값이므로 단독 고유성·탐지 시작 시각을 가정하지 않는다.
AWS RequestId, Lambda request ID, CW event ID/밀리초 timestamp, source_ip,
rule/action, instance/ENI/SG, 클라이언트 실행 ID를 함께 대조한다. 엔진에 없는 시각은
추정해 채우지 않는다. 증거별 수집 위치·버전·시각 의미·해시·접근 제한·누락 여부를 남긴다.

신규 모의 테스트는 메시지/소켓 구분·시계 경계·지연 응답·역순/중복/누락·입력 용량/
행 수·민감 필드·기존 출력 보존·TCP 분석 재사용을 검증한다. 기존 캡처/요청의 대상·포트·
인터페이스·dry-run·실행 한도·중단·소유 PID 정리 테스트는 재사용한다. 새 실행기는 없어
원격 트래픽·캡처 readiness·AWS SG 추적 상태를 신규 분석기로 검증했다고 주장하지 않는다.
모의 시각은 상수 입력이며 공유 시계 파일을 추가하지 않았다.

최초 제출 검증 기록: 원본 C:\Aleph의 check.ps1은 기존 .pytest_cache 접근 거부로 테스트 경로
검사에서 중단됐다. 기존 자료·권한은 변경하지 않았다. 깨끗한 임시 체크아웃
`C:\Users\User\AppData\Local\Temp\cloudshield-sg-verify-1791419707482`에서
동일 파일을 복사하고 SHA-256으로 대조한 뒤 같은 check.ps1을 우회 없이 실행했다.
Windows/Git Bash, Python 3.14.7, pytest 8.4.2, uv sync --extra dev 환경이며
R&R·테스트 경로·Ruff lint·format(112파일)·pytest 단계 모두 통과했다.
결과는 **846 passed, 1 warning in 118.91s**. 경고는 기존 기본 소켓 차단 검증이다.
첫 임시 전체 실행은 CP949/UTF-8 subprocess 디코딩 불일치로 1 failed/845 passed였고,
PYTHONUTF8=1 및 PYTHONIOENCODING=utf-8을 적용해 해결했다. 테스트/검증 스크립트는
수정하지 않았다. 원본 신규 분석 테스트는 Python 3.12.14에서 46 passed였으며
기존 캐시 쓰기 경고가 있었다. 최초 제출 때 전체 검증 후에는 검증 기록과 문서만 보완했고,
당시 분석기·테스트 코드는 전체 게이트를 통과한 SHA-256과 동일함을 확인했다.

PR #147 리뷰 수정: 전체 송신→응답 역전과 close/reset 후 클라이언트 응답 수신의
잘못된 왕복 집계 두 건을 보완했다. 리뷰 입력 및 소켓 생성 전 응답 사례 총 8개가
수정 전 코드에서 실패함을 재현했다. 회귀 테스트 12개는 전체 오차 한도 경계·1나노초 초과,
close/reset·장비 오차 0/0.1초·서버 지연 수신 보존을 포함한다. 수정 후 검증 결과는
같은 PR의 검증 섹션에 최신 커밋·실행 환경과 함께 기록한다. 실제 AWS 실측은 계속 미수행이다.

클라우드 A 협업: 실제 ENI 대상·다중 ENI 지원·원래 SG 보존·외부 복구·API 식별자/시각
확보. 클라우드 B 협업: 승인 서비스·양측 로그·캡처 권한·수집 중단 가능성 확인.
보안 협업: tracked 조건 및 L7 보호 경로·동반 WAF 영향 검토. 별도 이슈를 임의 생성하지 않는다.

**현재 결론: 준비 산출물 범위이며 AWS 데이터 전달·기존 연결 종료·새 연결 차단·복구·
완전 격리·10초 E2E 성공은 모두 미검증이다.** 실측 대기 조건을 유지하고 Draft PR은
Refs #146으로 연결한다. Closes를 사용하지 않으며 이번 요청에서 머지하지 않는다.
