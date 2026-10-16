# [P3-6] 승인 ALB Web 스캔 초회 실측 — 403 미관측

- Notion Task: https://notion.so/3f704d37c225801592d4e0d0a10a6911
- GitHub Issue: https://github.com/mmmphyun/aleph-project/issues/185
- 실행 ID: `20261016T065016Z-p3-6`
- 실행 코드: `2eb0e22c6076dc82a257d932c21753acb0f2f89a`
- 판정: **15회 요청·HTTP 응답 및 TCP 패킷 확보 / WAF 403 미관측 / 차단 원인·10초 대응 SLA 미판정**

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

위 표의 PCAP·tcpdump 행은 별도 해석 문구 없이 실제 계측값만 적었다. kernel drop 0을 전체 패킷의 무누락 증거로 해석하지 않는다. 특히 사후 HEAD 200은 클라이언트 헤더 파일에 있지만 PCAP에 없고, 캡처 통계의 received/captured도 다르므로 종료 직전 캡처 범위에 한계가 있다. 향후 캡처에서는 마지막 요청 뒤 버퍼 배출 대기 구간을 늘려야 한다.

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

## 4. 클라우드 담당자와 대조할 항목

현재 네트워크 측에 AWS 조회 자격증명이 없어 원본 로그 대조는 담당자에게 요청한 상태다. 대조 구간은 2026-10-16 **15:50:17~15:50:51 KST**다.

1. 클라우드 B: 실제 Nginx source_ip와 의심 경로·상태·서버 시각, CloudWatch 수신 시각을 확인한다. ALB가 실제 본 clientIp와 같은지 대조한다.
2. 클라우드 A·보안: 같은 출발지의 탐지 윈도우와 Lambda 탐지 결과, BLOCK_WAF 호출·예외·IPSet 갱신 및 WAF action/terminatingRuleId를 확인한다. 수집·탐지·차단 중 어디까지 도달했는지는 네트워크 결과만으로 단정하지 않는다.
3. 차단이 적용됐다면 클라우드 담당자가 해당 단일 IP를 복구하고 원본 로그와 정상 응답을 대조한다. 네트워크 담당이 타 직무 코드를 고치거나 WAF API로 직접 차단·해제하지 않는다.

대조 전에는 성공한 10초 관통 데모 또는 WAF 차단 성공으로 보고하지 않는다. 추가 공격 실행은 원인과 다음 측정 조건을 정한 뒤 진행한다.
