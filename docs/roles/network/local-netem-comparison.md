# 지연·부분 손실·순서 역전 TCP/HTTP 로컬 비교 실험

- 담당: 네트워크 `RockCandy444`
- [Notion 카드](https://notion.so/40c04d37c22581d99fbbf01cfdca6c01), Phase 5
- [Issue #250](https://github.com/mmmphyun/aleph-project/issues/250)
- 기준 main: `2d2cb781953099a9c3ff81252369e4897a371d26`, 선행 [PR #249](https://github.com/mmmphyun/aleph-project/pull/249)

## 범위와 현재 상태

별도 `cloudshield-netem-v1` 프로파일을 구현했다. 기존 단일 요청·연결 수명주기의 판정과 기본 권한을 유지하고, 기존 runner의 bounded command·소유권 확인·바이너리 회수·전후 해시·manifest·정리를 재사용한다. PCAP 디코드와 TCP 재조립은 TShark가 수행한다. 공통 계약·타 직무 구현·공통 의존성·CI를 변경하지 않는다.

기존 Windows/WSL 환경은 필수 모듈이 로드되지 않아 전송 없이 사전 조회에서 중단했다. 사용자가 Ubuntu-Lab에 한정해 스냅샷 보존, 다운로드용 임시 NAT(포워딩 없음), Docker/TShark 설치, 필수 모듈 로드, 오프라인 복귀를 승인했다. 게스트 Ubuntu 24.04.4, 커널 6.8.0-139-generic에서 준비를 마쳤다. Windows 호스트 모듈·qdisc·방화벽·sysctl은 변경하지 않았다.

준비 중 무트래픽 기능 시험은 성공했다. tc 6.1.0은 seed를 지원하지 않는다. `gap 3 delay 50ms`만으로는 오류가 나므로 `delay 50ms reorder 100% gap 3`을 사용한다. 두 실패 기록도 보존한다. **아직 실제 12회 전송 결과를 기록하기 전이며, 설정 성공을 효과 재현으로 선언하지 않는다.**

## 토폴로지와 관측

소유 internal bridge의 서버와 클라이언트를 사용한다. 서버 eth0의 S, 클라이언트 eth0 ingress의 P, 수신측 IFB의 netem 송출 Q를 동시에 캡처한다. 서버→클라이언트 TCP/8080만 IFB로 redirect한다. NET_ADMIN은 주입 클라이언트만 보유한다. 각 캡처의 stream 번호를 독립 검증하고, 실제 4-tuple·seq/ack·IP ID·payload hash를 대조한다. Q tap의 유효성은 실제 P/Q 지연·누락·순서 대응으로 확인한다.

handshake 이후 양쪽 앱의 파일 barrier와 tc 조회가 끝나야 GET을 보낸다. 준비 확인은 ss와 파일 조회이며 추가 연결을 만들지 않는다. 회차당 신규 연결/GET 각 1회, 재연결·애플리케이션 재시도·리다이렉트는 없다. 서버는 동일 응답 헤더와 1KiB씩 64회, nominal 1ms 간격으로 보낸다. TCP_MAXSEG 1200을 사용하고 수신측 eth0/ifb0의 GRO/GSO/TSO 조정 결과를 모두 기록한다.

| 조건 | IFB root qdisc, limit 128 | 반복 |
| --- | --- | ---: |
| A baseline | netem, 장애 옵션 없음 | 3 |
| B delay | delay 50ms | 3 |
| C loss | loss random 10%, seed 미지원 | 3 |
| D reorder | delay 50ms reorder 100% gap 3 | 3 |

본문은 65,536B이며 `SHA256("cloudshield-netem-v1:%04d" % i)`의 32B 결과를 i=0..2047 순서로 연결한다. 기대 SHA-256은 `37b857dfabe9385104eebfab545643c6a1e06e42657d5de6c7e24229c4fab340`이다. Content-Length·실제 body.bin·앱 로그·TShark 재조립을 독립 대조한다.

## 상한과 재현

`python network/lab/netem_lab.py`는 부작용 없는 plan이다. 명시적 build 후, 필수 모듈과 로컬 Docker/TShark가 준비된 전용 Linux에서 `python3 network/lab/netem_lab.py run`을 실행한다. run은 무트래픽 기능 시험을 먼저 수행하며 실패하면 전송하지 않는다. 이번 실행은 Ubuntu-Lab의 외부 NIC와 공유 폴더를 끊고 수행할 예정이다.

동시성 1, 총 12회, connect 3초, 개별 I/O 5초, 클라이언트 15초, 캡처 준비 3초, 캡처별 20초 또는 1024패킷, PCAP/메타데이터/추출/분석별 1MiB, 로그별 64KiB, 회차 8MiB, 묶음 128MiB, 회차 작업 60초/정리 15초, TERM 2초/KILL 회수 1초, 묶음·최종 기록 16분, 명시적 이미지 빌드 별도 10분이다. 이미지 전송은 실험 전 준비이며 실험 증거 예산과 구분한다.

## 판독과 검증

연결 시간은 connect 호출 전후, 첫 바이트 시간은 요청 send 시작부터 최초 recv 반환, 완료 시간은 요청 send 시작부터 본문 길이·해시 검증 완료의 단조 시각 차이다. TCP ACK RTT는 S의 서버 데이터 프레임을 참조하는 클라이언트 ACK의 TShark ack_rtt이며, 재전송/겹치는 seq 구간의 모호한 표본을 제외한다. send 반환·TCP ACK·서버 앱 수신·클라이언트 본문 완료는 다른 사건이다.

설정·도구 실패, 전송 실패, effect_unobserved, effect_observed를 구분한다. drop 집계만으로 확률 손실과 큐 포화 원인을 동일시하지 않는다. retransmission/duplicate ACK/out-of-order 표시는 후보이며 주입 전후 패킷과 대조한다. kernel capture drop·패킷/파일 상한·잘림·저장 오류·중단은 장애 효과로 판정하지 않는다. 전송 성공과 주입 효과 관측은 별도 판정이다.

단위 검증은 합성 증거·가짜 소켓·도구 오류를 사용하며 기본 pytest에서 Docker/외부 통신을 자동 실행하지 않는다. 필수 게이트는 원본 캐시 ACL 오류를 보존한 채 `C:/Users/User/.codex/worktrees/network-netem-validation/Aleph`의 동일 바이트 사본에서 변경하지 않은 `powershell .\scripts\check.ps1`로 실행 중이다. UTF-8 실행 환경을 사용한다.

## 증거와 환경 준비 기록

ignored 원본은 `C:/Aleph/network/lab/runs/netem/` 아래 보존한다. WSL 사전 조회 `20261103T050356Z-eaaba7cb9b56/preflight/manifest.json` SHA-256은 `88793bbecf1ef84a9fcee7086f6014e081e5e46633acb3f00572f175b7523a3c`이며 연결/GET 0회다. 준비 로그는 `environment-20261103-ae492bf1/`, 전송·패키지·기능 시험 원본은 `transfer-ae492bf1/`에 있다.

VM 스냅샷 `cloudshield-before-netem-20261103-ae492bf1`(UUID `2ae0e3da-af3f-4216-a4d8-f820a643cc26`)을 보존했다. 기존 dormant NAT ssh 포워딩은 다운로드 전에 제거했으며 VM NIC를 none으로 복원한 뒤 기존 규칙을 비활성 상태로 복원한다. 첫 apt 작업은 상한으로 exit 124였고 별도 resume에서 패키지·모듈·Docker 준비 완료(exit 0)를 확인했다. 비밀번호는 사용자가 직접 변경했고 에이전트는 입력·기록하지 않았다.

## 분산 인프라 5대 제약

1. 수명주기: Lambda·호출 간 상태 공유는 없고 소유 프로세스 수명만 관리한다.
2. 스토리지: DB/400KB/TTL은 비적용이며 파일·회차·묶음·qdisc 큐 상한을 적용한다.
3. 일관성: worker 종료·fsync·전송 전후 해시 확인 후 분석한다.
4. 순서 역전: 패킷 도착 순서와 TCP가 앱에 전달한 본문 바이트 순서를 구분한다.
5. 장애 전파: DLQ는 비적용이며 도구·전송·저장·정리 오류와 부분 증거를 명시한다.

이 로컬 결과를 AWS SG/WAF 동작·전파 시간·10초 관통 SLA의 증거로 사용하지 않는다. 기존 DROP·최초 SYN RST·HTTP 403·연결 수명주기 실험은 반복하지 않는다. [netem 매뉴얼](https://man7.org/linux/man-pages/man8/tc-netem.8.html)의 TCP Small Queues 제약에 따라 수신측 ingress IFB를 선택했고, [mirred 매뉴얼](https://man7.org/linux/man-pages/man8/tc-mirred.8.html)의 redirect 구조를 사용한다.
