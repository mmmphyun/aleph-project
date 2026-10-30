# P5-4 첫 실측 시도: SSH 기준선 타임아웃

- 실행: 2026-10-30 **18:01:16~18:03:16 KST**, 최종 구성 재조회 18:05:08 KST
- run_id: `20261030T090116Z-1401680ef574`
- [Issue #242](https://github.com/mmmphyun/aleph-project/issues/242) · [Draft PR #243](https://github.com/mmmphyun/aleph-project/pull/243)
- [마스킹 선별 증거](evidence/p5-4/live-attempt-2026-10-30/ssh-baseline.public.json)

사용자의 실제 데모 실행 승인으로 기존 컨트롤러를 한 번 실행했다. SSH 공격 전 TCP 22 기준선이 timeout이어서 기존 계측기가 종료 코드 20으로 Hydra 실행을 막았다. 후속 Web은 실행하지 않았다. 실제 인증 공격·사건 생성·차단·복구 전이를 입증한 결과가 아니다.

| 항목 | 실제 관측 |
| --- | --- |
| TCP 기준선 | 18:01:26.359~18:01:27.169 KST, timeout, 단조 경과 809.833ms |
| 연속 PCAP | 7프레임, 서로 다른 7개 TCP 출발 포트에서 타깃 22로 SYN 7개 |
| 응답 | 타깃의 TCP 프레임 0개, SYN-ACK 0개, RST 0개. 3-way handshake 미성립 |
| 복구 호출 | 기존 A 함수 호출 성공. L4 상태 unchanged, Baseline SG와 WAF 출발 IP 차단 부재 재확인 |
| 복구 후 탐침 | 6회, 정상 연결 미확인 |
| 실제 사건·Slack | incident_id=null, 3차 카드 미전송. 가짜 사건을 만들지 않음 |
| 후속 실행 | Web 미실행, 자동 재공격 없음. controller exit 3 / complete=false |
| 증거 보존 | 원격 원본 14개 회수·SHA-256 전부 일치, PCAP과 파생 CSV는 Git 밖 보존 |

공격 노드 NIC에서 캡처하므로 출발지는 공인 NAT 이전 주소다. 패킷 방향은 승인 타깃 IP와 포트로 구분했다. 공인 출발 IP를 그대로 NIC 필터에 적용한 최초 비공개 집계는 정정했으며 공개 판정에는 사용하지 않는다. 차단 위치는 확정하지 않았다. SYN 무응답만으로 SG·NACL·라우팅·호스트 방화벽 중 하나를 단정하지 않는다.

사용자가 설치한 AWS CLI 2.39.2를 사용했지만 현재 컨트롤러 IAM 사용자의 DescribeSecurityGroups 조회가 권한 거부됐다. 실행 중 SG 규칙을 열거나 타 직무 인프라를 수정하지 않았다. 최종 Baseline SG 부착과 WAF 차단 부재는 승인된 조회 API로 확인했다. 이미 차단되지 않았던 상태라 실제 복구 전이·복구 지연도 미실증이다.

## A에게 필요한 확인

전달받은 공격자 공인 IP의 /32에서 현재 타깃 TCP 22로 신규 연결이 가능하도록, Baseline SG ingress와 NACL·라우팅·타깃 SSH/호스트 방화벽 상태를 확인해 주세요. 현재 로그·PCAP에는 SYN만 있고 응답이 없습니다. 기존 컨트롤러의 Baseline SG 재부착으로는 포트 허용 규칙 문제가 해소되지 않습니다. 필요한 원본은 비공개로 전달할 수 있으며 AWS 키를 추가로 보낼 필요는 없습니다.

정상 기준선이 확보된 뒤 새 유효 승인으로 재측정해야 한다. 이번 승인 ID는 이미 소비했으며 실패 회차를 재사용하거나 자동 재공격하지 않는다. 첫 실제 공격·10초 SLA·WAF 원문·SSH 키 인증은 모두 미확인이다.

## 검증 구분

실측을 수행한 코드 커밋 8a9ce67의 CI는 [run 41030070740](https://github.com/mmmphyun/aleph-project/actions/runs/41030070740)에서 통과했다. 로컬 필수 게이트는 1590 passed, 4 skipped, 1 warning이었다. 본 후속 변경은 실측 결과 문서·선별 증거뿐이며 제품 코드·테스트·인프라를 수정하지 않는다.
