# [P3-6] 승인 ALB Web 스캔 초회 실측 — 403 미관측

- Notion Task: https://notion.so/3f704d37c225801592d4e0d0a10a6911
- GitHub Issue: https://github.com/mmmphyun/aleph-project/issues/185
- 실행 ID: `20261016T065016Z-p3-6`
- 실행 코드: `2eb0e22c6076dc82a257d932c21753acb0f2f89a`
- 판정: **15회 요청·응답 및 TCP 패킷 확보 / 클라우드 B 확인상 입력 계약 오류로 탐지 전 중단 / WAF 차단·10초 대응 SLA 미달성**

## 1. 실행 조건 및 요청 결과

Windows PC의 학원 유선망은 유지하고, Kali VM의 유일한 네트워크 어댑터를 휴대폰 `Remote NDIS based Internet Sharing Device`에 브리지했다. VM의 `eth0`에서 캡처하고 승인된 ALB의 HTTP 80에만 요청했다. 실측 전 단일 헬스체크 외의 디렉터리 스캔은 이 실행 한 번이다.

모바일 재연결 과정에서 호스트 DHCP 주소·RNDIS MAC 주소가 바뀌었고, VM은 이전 브리지 바인딩에서 DHCP/DNS 조회에 실패했다. 이때는 스캔 전에 중단했다. VM NIC를 `null`로 분리한 뒤 동일 RNDIS 브리지에 다시 연결해 DHCP/DNS를 복구했다. 실행 중 학원망 NAT로 우회하지 않았다.

공인 IP 확인 서비스가 반환한 모바일 주소는 조회 시점에 따라 달랐다. 실행 직전 `checkip.amazonaws.com` 관측값을 비공개 manifest에 보존했으며, **이를 ALB가 실제로 받은 clientIp라고 단정하지 않는다.** 실제 출발지는 해당 시각의 ALB/WAF/Nginx 원본 로그로 대조해야 한다.

```bash
bash network/web_dir_scan.sh \
  --url http://cloudshield-alb-dev-308142572.ap-southeast-2.elb.amazonaws.com \
  --tool curl --candidates 15 --interval 1 --max-runtime 60 \
  --evidence <새 실행 폴더>/web-dir-summary.txt --execute
```

| 항목 | 관측값 |
| --- | --- |
| 캡처 준비 | 2026-10-16 15:50:16.810 KST |
| 실행 전 루트 HEAD | 15:50:17.381에 200 관측 |
| 스캔 프로세스 | 15:50:17.381~15:50:46.967, 종료 코드 0 |
| GET 요청 수 / 응답 수 | 15 / 15 |
| 상태 분포 | 401 1건(`/admin`), 404 13건, 200 1건(`/health`), **403 0건** |
| 실행 후 루트 HEAD | 15:50:50.722에 200 관측 |
| 캡처 종료 | 15:50:50.787 KST |

`--interval 1`은 이전 응답 완료 후 다음 요청까지의 대기다. 응답 시간과 프로세스 오버헤드를 포함한 이번 실행은 29.586초였으며 15개 요청을 14초에 모두 전송한 것이 아니다. 첫 GET 송신은 15:50:17.667198, 마지막 GET 송신은 15:50:46.553604였다.

처음 5개 의심 경로는 `/admin`, `/login`, `/dashboard`, `/api`, `/backup`이다. 그 사이 `/health`가 들어가며, 첫/다섯 번째 의심 GET의 클라이언트 송신 간격은 약 10.009633초였다. 이는 서버 로그의 초 단위 시각·동일 source_ip·실패 경로 수와 별도다. 이 값만으로 서버 탐지 조건의 충족·미충족을 확정하지 않는다. 다음 실험을 결정하기 전에 원본 로그를 확인한다.

## 2. TCP 핸드셰이크와 종료 관측

캡처 조건은 `eth0`, `ip and tcp and port 80`, snaplen 4,096바이트, 최대 2,000패킷, 독립 타이머 90초였다. 요청 완료 후 소유한 캡처 프로세스 그룹에 SIGINT를 보내 정상 flush했고 강제 종료는 없었다.

| 지표 | 관측값 | 해석 범위 |
| --- | --- | --- |
| PCAP | 25,783바이트, 223 TCP 패킷, 32 stream | 보존한 원본 파일 범위 |
| tcpdump 통계 | captured 223 / received by filter 234 / kernel drop 0 | 전체 무누락을 보장하지 않음 |
| SYN / SYN-ACK | 32 / 32 | HTTP 요청 수와 TCP 연결 수는 같지 않다 |
| FIN / RST | 42 / 11 | 패킷 수이며 완전 종료한 연결 수가 아니다 |
| 재전송 표시 | 0 | 이번 PCAP의 TShark 판독 범위 |
| HTTP 해석 | 사전 HEAD 1건 + GET 15건의 요청·응답 | 사후 HEAD는 헤더 증거에만 존재 |

kernel drop 0을 전체 패킷의 무누락 증거로 해석하지 않는다. 특히 사후 HEAD 200은 클라이언트 헤더 파일에 있지만 PCAP에 없고, 캡처 통계의 received/captured도 다르므로 종료 직전 캡처 범위에 한계가 있다. 향후 캡처에서는 마지막 요청 뒤 버퍼 배출 대기 구간을 늘려야 한다.

대표 `/admin` 요청은 TCP stream 2에서 아래와 같이 관측했다. 상대 seq/ack를 표에 기록하고 원본 주소·임시 포트는 비공개 CSV에만 보존한다.

| frame | KST | 방향 | 플래그·페이로드 | seq / ack |
| --- | --- | --- | --- | --- |
| 12 | 15:50:17.423134 | VM → ALB | SYN | 0 / 0 |
| 16 | 15:50:17.666857 | ALB → VM | SYN, ACK | 0 / 1 |
| 17 | 15:50:17.666878 | VM → ALB | ACK, 3-way handshake 완료 | 1 / 1 |
| 18 | 15:50:17.667198 | VM → ALB | GET `/admin`, TCP payload 131바이트 | 1 / 1 |
| 21 | 15:50:18.079567 | ALB → VM | HTTP 401, TCP payload 378바이트 | 1 / 132 |
| 24 | 15:50:18.080050 | VM → ALB | FIN, ACK | 132 / 379 |
| 25 | 15:50:18.392216 | ALB → VM | FIN, ACK | 379 / 133 |
| 26 | 15:50:18.392233 | VM → ALB | ACK | 133 / 380 |

RST 11개는 모두 VM 송신 방향이며 HTTP 요청이 기록된 stream과 겹치지 않았다. 추가 TCP 연결 정리 원인은 아직 확정하지 않는다. **이를 WAF가 연결을 강제 종료한 증거로 사용할 수 없다.** 이번 캡처에는 HTTP 403이 없으므로 '403 이후 FIN/RST' 시점도 산출하지 않는다.

## 3. 증거 보존 및 검증

- 로컬 비공개 증거: `.codex-build/p3-6/20261016T065016Z-p3-6/` (Git 제외)
- VM 증거: `/home/kali/CloudShield/captures/20261016T065016Z-p3-6/`
- PCAP SHA-256: `7f681631dc9e0314c073b2eb1523c3a57193e195557758e00efc92866a479db4`
- 실행 스크립트 SHA-256: `14dca86ccb4310b11fbe4c2685f0497c2933a06708f35e2cf98ccf339a9aacd6`
- 요청별 요약 SHA-256: `dd9749a6c5f481fab34b6292c9431a021894c5dbaadc9220eaf8f5fc1843bffd`
- manifest의 원본·분석 파일 해시를 Windows 복사본과 대조했다. 원본 PCAP/CSV/헤더/manifest는 커밋하지 않는다.

TShark 4.6.6의 TCP 플래그 출력은 `True/False`였다. 원본 `tcp.csv`를 보존하고, 정확히 알려진 Boolean 표현만 `1/0`으로 변환한 `tcp-normalized.csv`를 기존 `network/waf_packet_timeline.py`에 전달했다. 기존 분석기의 용량·열·시각·플래그 검증을 변경하거나 우회하지 않았다. HTTP 값은 별도 `http.csv`, seq/ack는 `tcp-details.csv`로 대조했다.

필수 `powershell .\scripts\check.ps1`은 동일 기준 커밋 `019badf`와 수정 파일 3개의 SHA-256이 일치하는 깨끗한 검증용 작업 트리에서 **1,072 passed / 4 skipped**로 통과했다. 원본 작업 폴더의 기존 `.pytest_cache`가 Windows 사용자에게도 접근 불가여서 검증용 작업 트리를 사용했으며, 게이트·테스트·역할 검사나 의존성 설정은 변경하지 않았다. 기존 사용자 문서 파일도 보존했다.

## 4. 클라우드 B 대조 결과 및 입력 계약 장애

사용자가 전달한 클라우드 B 확인 결과다. 네트워크 담당은 AWS 조회 자격증명이 없어 아래 원본 로그를 직접 조회하지 않았다. 기본 대조 구간은 2026-10-16 **15:50:17~15:50:51 KST**이며 WAF 차단 조회는 **15:51:51 KST**까지 확장됐다.

| 단계 | 클라우드 B 확인 결과 | 판정 |
| --- | --- | --- |
| Nginx / WAF 수신 | curl 로그 15건 / WAF 로그 16건(`/health` 포함) | 대상 도달 확인. PCAP의 HEAD/GET 수와 로그의 포함 범위는 별도로 대조해야 함 |
| 실제 출발지 | 모바일 공인 IPv4 9개 | 실행 직전 IP 한 개로 전체 요청을 대표할 수 없음 |
| Lambda | 호출은 발생했으나 `CloudWatchLogsPayload.logEvents[].extractedFields`에 `Extra inputs are not permitted` 오류 11건 | 탐지 규칙 평가 및 `BLOCK_WAF` 전에 중단 |
| WAF | 16건 모두 `action=ALLOW`, `terminatingRuleId=Default_Action`; 확장 구간에도 BLOCK 없음 | 이번 실행의 차단 실패 확인 |

현재 기준 코드의 `src/contracts/events.py`에서 `CloudWatchLogEvent`는 `id`, `timestamp`, `message`만 정의하고 `extra="forbid"`를 적용한다. 수신된 `extractedFields`가 거부됐다는 클라우드 B 설명과 일치한다. **이번 직접 장애는 입력 계약 호환성이다. IP 분산이나 보안 규칙을 이번 Lambda 오류의 원인으로 취급하지 않는다.** 계약·수집·플랫폼 수정은 클라우드 A가 클라우드 B와 조율해야 하며, 네트워크 담당은 보호된 계약이나 다른 직무 코드를 변경하지 않았다.

## 5. 공인 IP 분산 추가 관측과 재실측 조건

공격을 재실행하지 않고 같은 VM에서 `curl -4 --noproxy '*'`로 `https://checkip.amazonaws.com`을 새 연결로 5회 조회했다. 2026-10-16 **16:00:15.855~16:00:26.014 KST**에 5개의 서로 다른 공인 IPv4가 관측됐다. 그 전후 `eth0`의 사설 주소 `10.229.53.204/24`, 기본 게이트웨이 `10.229.53.113`, 인터페이스는 같았다. 같은 조회 대상 IP `52.221.76.151`로 나간 첫 번째·세 번째 연결도 서로 다른 공인 IP를 반환했다. 진단 중 테더링·VM 네트워크 설정을 바꾸지 않았다. 개별 주소와 조회 시각은 Git 제외 증거 `public-ip-diagnostic.json`에 보존했다.

이는 로컬 사설 주소·기본 경로를 유지한 상태에서도 외부 관측 주소가 달라지는 현상의 재현이다. **휴대폰 또는 통신사 측 상위 NAT/출구 풀의 주소 선택이 유력한 추정**이나, 이 관측만으로 휴대폰과 통신사 중 어느 계층의 어떤 정책인지 확정할 수 없다. CGN은 가입자가 관리하지 않는 사업자 망의 주소 변환 계층이며, 표준상 기본 주소 pooling은 Paired를 요구하므로 '모든 모바일 CGN이 요청마다 IP를 바꾼다'고 일반화하지 않는다. [RFC 6888](https://www.rfc-editor.org/rfc/rfc6888.html)

1. 클라우드 A가 입력 호환성을 수정·배포하고 클라우드 B가 같은 수집 입력의 검증 통과를 확인한 뒤 재실측한다. 보안 담당은 그 다음 탐지 결과를 검증한다.
2. 학원망과 분리된 **고정 공인 출구**를 확보한다. 예를 들어 클라우드 A가 관리하는 별도 테스트용 공격 VM에 Elastic IP를 연결하는 방안을 협의할 수 있다. EIP는 고정 공인 IPv4다. 이 보고서는 리소스를 생성하지 않는다. VM을 NAT/브리지로 바꾸거나 사설 IP를 고정하는 것만으로 모바일 상위 출구가 고정되지는 않는다. [AWS Elastic IP 문서](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/elastic-ip-addresses-eip.html)
3. 재실측에서는 실행 전·도중·후 IP 관측 시각과 로컬 주소·경로를 기록한다. 아래 실행 가이드의 제한된 관측을 사용하되, **IP 조회 서비스의 주소는 보조 관측**이다. 클라우드 B가 실제 WAF `clientIp`를 요청 URI·시각별로 매핑해 동일 출발지 조건을 확정해야 한다.
4. 동일 IP여도 기본 15개·1초 간격이 탐지 조건을 보장하지 않는다. 첫 5개 의심 경로가 응답 지연을 포함한 서버 시간창에 들어오는지 보안 담당과 기존 `--paths`·`--interval` 설정을 조율한다. 탐지 임계값을 대신 수정하지 않는다.
5. 다음 결과에서 탐지 기준 시각, `BLOCK_WAF` 실행, WAF `action=BLOCK`·`terminatingRuleId`·차단 IP, 첫 403 수신을 대조한다. 클라우드 담당이 테스트 차단 IP의 복구를 맡는다. 이번 결과는 성공한 10초 관통 데모의 증빙으로 사용하지 않는다.
