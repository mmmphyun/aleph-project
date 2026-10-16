# [P3-6] 고정 IP 노드 재실측 — 403 미관측

- Notion Task: https://notion.so/3f704d37c225801592d4e0d0a10a6911
- GitHub Issue: https://github.com/mmmphyun/aleph-project/issues/185
- 기존 작업 PR: https://github.com/mmmphyun/aleph-project/pull/186
- 입력 계약 수정: https://github.com/mmmphyun/aleph-project/pull/188
- 실행 ID: `20261016T075925Z-p3-6-fixed-ip`
- 판정: **고정 IP 및 WEB_DIRECTORY_SCANNING 탐지 확인 / WAF 결합 조회 권한 오류로 차단 실패 / 403 미관측**

IAM 권한 핫픽스 후 별도 1회 실행의 결과는 [HTTP 403 재실측 보고서](2026-10-16-p3-6-waf-403-retest.md)에 기록한다. 이 문서는 권한 오류가 있었던 첫 고정 IP 실행을 보존한다.

## 1. 실행 준비와 범위

클라우드 A가 제공한 일회용 Ubuntu 22.04.5 LTS 공격 노드에 SSH로 접속했다. `curl`, `tcpdump`, 비대화형 sudo 및 NTP 시각 동기화를 확인했다. SSH 개인키는 사용자만 접근하는 임시 폴더에 보관하고 출력·보고서·Git에 포함하지 않았다. AWS 계정 자격증명은 사용하지 않았다.

PR #188의 `CloudWatchLogEvent.extractedFields` 선택 필드, 기존 입력과의 호환 테스트, main 병합 및 병합 커밋 CI 성공을 읽기 전용으로 확인했다. 실제 Lambda 배포 완료는 사용자가 클라우드 A에게 확인받았으며, 네트워크 담당이 AWS API로 배포 상태를 직접 조회한 것은 아니다.

실행 코드는 초회와 같은 `2eb0e22c6076dc82a257d932c21753acb0f2f89a`의 스캔 스크립트다. SHA-256 `14dca86ccb4310b11fbe4c2685f0497c2933a06708f35e2cf98ccf339a9aacd6`를 배치 후 및 실행 직전에 대조하고 `bash -n`과 dry-run을 통과했다. 승인된 dev ALB의 HTTP 80에만 `--candidates 15 --interval 1 --max-runtime 60 --execute`를 **한 번** 실행했다.

예상 공인 출발지 `3.26.171.60`은 실행 전·도중·후 `checkip.amazonaws.com`에서 모두 같았다. 관측 시각은 각각 16:59:25.233, 16:59:32.966, 17:00:12.303 KST다. 로컬 주소·기본 경로도 유지됐다. 단, **실제 ALB/WAF의 clientIp는 별도 클라우드 로그로 확정해야 한다.**

## 2. HTTP 및 TCP 관측 결과

모든 시각은 2026-10-16 KST다. 캡처는 `ens5`, `ip and tcp and port 80`, snaplen 4,096바이트, 최대 2,000패킷·90초로 제한했다. `--immediate-mode`와 `-U`를 사용하고 마지막 응답 후 3초 이상 대기한 다음 소유한 캡처 프로세스 그룹에 SIGINT를 보냈다. 캡처 종료 코드 0이며 강제 종료는 없었다.

| 항목 | 결과 |
| --- | --- |
| 캡처 준비 / 종료 | 16:59:25.336 / 17:00:15.324 |
| 사전 루트 HEAD | 16:59:25.359에 200 관측 |
| 스캔 프로세스 | 16:59:25.359~16:59:41.684, 16.325초, 종료 코드 0 |
| GET | 계획·시도·응답 15개씩; 401 1건(`/admin`), 404 13건, 200 1건(`/health`), 403 0건 |
| 사후 루트 HEAD | 스캔 종료 약 3/10/20/30초 후 각 200; 마지막 관측 17:00:11.710 |
| PCAP의 HTTP | GET 15개 + HEAD 5개 = 요청·응답 각각 20개; 사후 HEAD도 모두 포함 |
| tcpdump | captured 200 / received by filter 200 / kernel drop 0 |
| TCP | 200패킷, 20 stream, SYN 20, SYN-ACK 20, FIN 40, RST 0, 재전송 표시 0 |

tcpdump 카운터와 요청별 증거가 일치하지만, 이 사실을 모든 네트워크 패킷의 무누락 보장으로 확대하지 않는다. PCAP에는 NAT 변환 전 공격 노드 사설 IP가 보이므로 그 주소를 WAF가 본 출발지라고 단정하지 않는다.

첫 5개 의심 경로(`/admin`, `/login`, `/dashboard`, `/api`, `/backup`)의 첫/마지막 GET 송신 간격은 **5.755639초**다. 모바일 초회의 약 10.009633초보다 짧았다. 서버 시각·로그 필터·IP별 이벤트 수집 및 영속 윈도우 결과를 확인하기 전에는 이 값만으로 탐지 평가 성공을 선언하지 않는다.

대표 `/admin`의 TCP stream 1을 seq/ack와 대조했다.

| frame | KST | 방향 | 플래그·페이로드 | 상대 seq / ack |
| --- | --- | --- | --- | --- |
| 11 | 16:59:25.381177 | 공격 노드 → ALB | SYN | 0 / 0 |
| 12 | 16:59:25.381507 | ALB → 공격 노드 | SYN, ACK | 0 / 1 |
| 13 | 16:59:25.381530 | 공격 노드 → ALB | ACK, 3-way handshake 완료 | 1 / 1 |
| 14 | 16:59:25.381585 | 공격 노드 → ALB | GET `/admin`, TCP payload 131바이트 | 1 / 1 |
| 16 | 16:59:25.389409 | ALB → 공격 노드 | HTTP 401, TCP payload 378바이트 | 1 / 132 |
| 18 | 16:59:25.389634 | 공격 노드 → ALB | FIN, ACK | 132 / 379 |
| 19 | 16:59:25.389939 | ALB → 공격 노드 | FIN, ACK | 379 / 133 |
| 20 | 16:59:25.389957 | 공격 노드 → ALB | ACK | 133 / 380 |

403과 RST가 없으므로 WAF 차단 또는 '403 이후 FIN/RST' 시각을 산출하지 않는다. FIN 관측은 연결 정리 증거이며 차단 주체를 증명하지 않는다. 이번 실측을 10초 관통 대응 성공으로 보고하지 않는다.

## 3. 증거 회수와 다음 대조

- 로컬 원본·분석 증거: `.codex-build/p3-6/20261016T075925Z-p3-6-fixed-ip/` (Git 제외)
- 원격 증거: `/home/ubuntu/cloudshield-p3-6.vBHby0/20261016T075925Z-p3-6-fixed-ip/`
- PCAP: 25,365바이트, SHA-256 `a4df25ccb36cfa6e2ad44b8593fdb26666619f01976e2025afe532c00aba8e3f`
- 요청별 요약 SHA-256: `7b542142bebdace6e0ee2f6258c9aa84b9fc8895e336d1113fe5e0dfbf708246`
- manifest에 기록된 모든 원본 파일의 SHA-256을 회수본과 대조했다. 후처리 파일은 별도 `analysis-manifest.json`으로 해시를 보존했다.

TShark 4.6.6의 원본 TCP CSV를 보존하고 정확한 `True/False` 값만 `1/0`으로 정규화해 기존 `network/waf_packet_timeline.py`를 재사용했다. 1MiB·10,000행 상한과 입력 검증을 변경하지 않았다. HTTP는 별도 CSV에서 요청 frame과 응답을 짝지었고, 20개 모두 대응 요청이 확인됐다.

이번 추가 변경은 실측 문서뿐이다. 스캔 코드·테스트는 PR #186에서 필수 `powershell .\scripts\check.ps1` 1,072 passed / 4 skipped 및 GitHub CI를 통과한 그대로다. 계약·탐지·수집·플랫폼·인프라 파일은 수정하지 않았다.

클라우드 B·A에게 **16:59:25~17:00:16 KST** 구간의 실제 source_ip/clientIp 및 요청 수, `extractedFields` 오류 해소 여부, Web 탐지·BLOCK_WAF 실행 또는 오류, WAF `action`·`terminatingRuleId`·차단 IP를 요청했고 아래 결과를 전달받았다. 증거는 로컬 회수됐으며 일회용 노드 삭제는 클라우드 A가 담당한다.

## 4. 클라우드 A 원본 로그 분석 결과

사용자가 전달한 클라우드 A의 확인 결과이며 네트워크 담당이 AWS 원본 로그를 직접 조회한 것은 아니다.

| 항목 | 클라우드 A 확인 결과 |
| --- | --- |
| 실제 출발지 | `3.26.171.60`, 공격 노드와 일치 |
| Nginx 수집 | 19건: 404 13건, 401 1건, 정상 200 5건 |
| WAF 원본 로그 | 19건, `ALLOW` / `Default_Action` |
| 입력 계약 | Pydantic 역직렬화 오류 0건, `extractedFields` 파싱 정상 |
| Web 탐지 | `WEB_DIRECTORY_SCANNING` 정상 탐지 |
| 차단 실행 | `waf_blocked: False`; ALB WebACL 결합 검증 중 `wafv2:GetWebACLForResource`의 `AccessDeniedException` |
| IPSet 반영 | 등록 API 호출 전 검증 실패, 차단 IP 0건 |

클라이언트 PCAP의 20쌍과 서버 측 19건을 같은 수라고 기술하지 않는다. Nginx는 `/health`의 access log 비활성화와 일치하는 수지만, WAF의 한 건 차이는 URI별 원본 매핑 없이는 확정하지 않는다.

이번 직접 실패 원인은 입력 계약이나 IP 분산이 아닌 **WAF 결합 조회 IAM 권한**이다. 클라우드 A가 Lambda의 `GetWebACLForResource` 조회 권한 인라인 핫픽스 배포를 완료했다고 전달했고 동일 조건의 1회 재실측을 요청했다. 네트워크 담당은 해당 IAM 정책을 변경하지 않았다. 후속 실행은 별도 실행 폴더·보고서로 보존한다.
