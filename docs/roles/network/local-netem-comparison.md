# 지연·부분 손실·순서 역전 TCP/HTTP 로컬 비교 실험

- 담당: 네트워크 `RockCandy444`, Phase 5
- [Notion 카드](https://notion.so/40c04d37c22581d99fbbf01cfdca6c01) · [Issue #250](https://github.com/mmmphyun/aleph-project/issues/250)
- 브랜치: `feat/network-netem-comparison`
- 기준 main: `2d2cb781953099a9c3ff81252369e4897a371d26`, 선행 [PR #249](https://github.com/mmmphyun/aleph-project/pull/249)

## 결과와 적용 범위

2026-11-03 전용 Ubuntu-Lab에서 계획한 4조건×3회, 총 **12회만** 실행했다. 모든 회차에서 신규 연결 1개·GET 1회, HTTP 200, Content-Length 65,536, 실제 본문 65,536B와 기대 SHA-256이 일치했다. 앱 재연결·재시도·리다이렉트·원하는 결과를 위한 추가 회차는 없다. 본문 완료와 정상 종료는 별개다. D2·D3는 FIN/ACK 교환 뒤 RST가 2개씩 관측돼 `closure_anomaly`이며, 프로파일 전체 통과는 **10/12**, 본문 전송 완료는 **12/12**다.

B의 대응 가능한 패킷에는 약 50–60ms 지연이 있었고 C에는 qdisc drop과 재전송 후보가 있었다. D의 대응 패킷에서는 원래 순서와 반대인 도착 쌍 11–12개를 관측하면서 앱 본문은 올바른 순서로 완료됐다. 다만 GSO 때문에 B 전체·C1·D 전체는 전후 세그먼트 단위가 달라 **전체 효과 판정 불충분**으로 남긴다. 이것은 효과가 0이었다는 뜻이 아니다. 일부 대응 패킷의 지연·역전과 전체 대응 한계를 함께 보존한다. 효과 미관측을 판정하는 정상 입력 사례는 단위 테스트로 별도 검증했다.

이 결과는 로컬 Linux/Docker TCP 동작의 관측이다. AWS SG/WAF 효력·전파 시간·10초 관통 SLA의 증거가 아니다. 기존 전면 DROP·최초 SYN RST·HTTP 403·연결 재사용/종료 실험을 반복하지 않았다.

## 기존 자산 재사용과 변경

| 파일 | 변경 이유 |
| --- | --- |
| `network/lab/packet_lab.py` | 기존 runner에 권한 선택·프로파일 상한·suite factory 확장점만 추가. 기존 기본값·4종 판정 유지 |
| `network/lab/netem_lab.py` | 별도 plan/build/probe/run, 무트래픽 기능 시험, 12회 실행과 양쪽 증거 회수 |
| `network/lab/netem_worker.py` | 소유 수신측 IFB/netem, handshake 이후 barrier, 단일 소켓·GET·64KiB 전송 |
| `network/netem_compare.py` | TShark 출력·앱·qdisc의 순수 오프라인 대조, 완료/종료/효과 판정 분리 |
| `network/lab/Netem.Dockerfile*` | 별도 이미지와 최소 빌드 컨텍스트 |
| `tests/unit/test_network.py` | 합성 증거·가짜 소켓·실패 경로 회귀 검증 |
| 이 문서 | 실제 측정·한계·증거 기록 |

기존 `packet_lab.py`/`run.py`의 로컬 엔진 제한, bounded command, 독점 실행 디렉터리, label/ID 소유 확인, 바이너리 회수, 전후 SHA-256, manifest, 정리를 재사용했다. 캡처는 기존 `tcpdump_capture.sh`와 래퍼를 사용한다. 직접 소켓·앱 식별·단조 시각 패턴은 연결 실험을 계승했고 TCP/JSON/시각 검증 헬퍼도 재사용했다. **PCAP 디코더·TCP 재조립기는 추가하지 않았다.** TShark가 디코드·재조립하며 분석기는 이미 디코드된 seq/ack와 고정 바이트 범위만 검증한다. 범용 증거 검증 CLI도 만들지 않았다.

기존 테스트·fixture 정의 269개의 AST는 main과 일치한다. 다른 직무 구현, 계약, 의존성, CI는 변경하지 않았다. 사용자 미추적 협업 문서 3개와 기존 검증 worktree 4개도 보존했다.

## 환경과 승인된 예외

Windows/WSL의 최초 읽기 전용 조회에서는 커널 `6.18.33.2-microsoft-standard-WSL2`의 필수 기능이 `=m`이지만 미로드 상태여서 연결/GET 0회로 중단했다. 사용자가 이후 Ubuntu-Lab에 한정해 스냅샷 → 다운로드용 NAT(포워딩 없음) → Docker/TShark 설치와 모듈 로드 → NIC none 복원을 승인했다. Windows 호스트 모듈·qdisc·sysctl·방화벽은 변경하지 않았다.

| 구분 | 실제 버전/식별 |
| --- | --- |
| VM | Ubuntu-Lab, VirtualBox 7.2.16, 2GiB, Ubuntu 24.04.4 LTS |
| 커널 | `6.8.0-139-generic`, x86_64 |
| Docker | 29.1.3, 로컬 Unix 엔진 |
| 이미지 | `sha256:74ef7beaf95586059e9d9f1bcf0be595c13dfad345aa594430f772255d19ce30` |
| 컨테이너 tc | iproute2 6.1.0, libbpf 1.1.2 |
| 컨테이너 tcpdump | 4.99.3, libpcap 1.10.3 |
| 컨테이너 Python / ethtool | 3.11.2 / 6.1 |
| 디코드·재조립 | Linux TShark 4.2.2, 필드 2-pass·desegment·out-of-order reassembly 활성화 |
| 실제 전송 소스 | `725954d2ac4a9750b9cb242bbc595719764c9c03`, 파일별 실제 작업 바이트 해시 별도 기록 |
| 수정 후 오프라인 분석 소스 | `99064fe1a774093b5fa6e17a159d5a37b380fb39` |

이미지는 Windows Docker에서 명시적으로 빌드해 오프라인 적재했다. Git bundle과 실제 파일 바이트를 따로 전달하고 이미지 내부 worker/기존 캡처 소스까지 SHA-256 일치를 검증했다. 이는 Windows와 Linux checkout의 줄바꿈 차이가 소스 식별을 흐리지 않게 하기 위함이다. 실제 12회 동안 VM 외부 NIC는 null, NIC2~8 none이었고 전송용 공유 폴더도 해제했다. 컨테이너에는 포트 공개·bind mount·Docker 소켓·privileged·host network를 사용하지 않았다.

준비 중 첫 apt 작업은 시간 상한으로 exit 124였고, 후속 resume에서 설치 상태·Docker·모듈을 확인해 exit 0이었다. 초기 gap 구문 실패와 seed 미지원 결과도 보존했다. 이들은 무트래픽 준비 실패이며 실제 12회 반복에 포함되지 않는다. 비밀번호는 사용자가 직접 변경했고 에이전트는 입력·기록하지 않았다.

## 토폴로지·방향·권한

```text
소유 internal bridge
  server eth0 [S] ── server→client TCP/8080 ──> client eth0 ingress [P]
                                                  │ u32 + mirred redirect
                                                  ▼
                                             ifb0 root netem
                                                  │ [Q] 송출 tap
                                                  ▼
                                             client TCP / 앱
  client→server 요청·ACK ─────────────────────────> server
```

S는 송신측, P는 수신측 주입 전, Q는 IFB qdisc 송출 관측이다. client→server는 주입하지 않는다. server→client의 데이터뿐 아니라 해당 연결의 ACK·FIN도 같은 필터를 지난다. SYN/ACK는 장애 없는 IFB 기준선을 통과하고, 양쪽 앱이 handshake 완료를 파일로 표시한 뒤 tc 적용·조회와 armed barrier가 완료돼야 GET을 보낸다. 준비 확인은 `ss`와 파일 조회로 하며 탐침 연결을 만들지 않는다.

NET_ADMIN은 IFB·tc·오프로딩을 담당하는 클라이언트만 보유한다. 양쪽 캡처에는 기존 NET_RAW/SETUID/SETGID/KILL만 사용한다. 수신측 ingress를 택한 것은 [netem 매뉴얼](https://man7.org/linux/man-pages/man8/tc-netem.8.html)의 TCP Small Queues 제약을 반영한 것이다. 별도 중간 노드는 노드와 관리 권한을 늘리므로 사용하지 않았다. [mirred 매뉴얼](https://man7.org/linux/man-pages/man8/tc-mirred.8.html)의 IFB redirect 구조를 사용한다.

Q 위치는 [Linux 6.8 IFB 소스](https://github.com/torvalds/linux/blob/v6.8/drivers/net/ifb.c)와 [송출 경로 소스](https://github.com/torvalds/linux/blob/v6.8/net/core/dev.c)에 근거한 설계 해석이며, 이 VM에서 대응된 P/Q 패킷의 약 50ms 차이와 역전으로 관측 유효성을 추가 확인했다. Q를 실제 물리 링크 캡처라고 해석하지 않는다.

## 조건·페이로드·유한 상한

| 조건 | 실제 `tc qdisc change dev ifb0 root ...` | 회차 |
| --- | --- | ---: |
| A | `netem limit 128` | 3 |
| B | `netem limit 128 delay 50ms` | 3 |
| C | `netem limit 128 loss random 10%` | 3 |
| D | `netem limit 128 delay 50ms reorder 100% gap 3` | 3 |

모든 조건에서 동일 서버·클라이언트·토폴로지·송신 패턴을 사용했다. GET `/payload`, Host `local.test`, 고유 X-Run-ID, Connection close다. 응답 헤더 뒤 1KiB씩 64회, nominal 1ms 간격으로 보냈다. 양쪽 TCP_MAXSEG 1200과 TCP_NODELAY를 사용했다. 본문은 `SHA256("cloudshield-netem-v1:%04d" % i)`의 32B 결과를 i=0..2047 순서로 연결한다.

- Content-Length/기대·실제 본문: **65,536B**
- 모든 실제 body.bin SHA-256: `37b857dfabe9385104eebfab545643c6a1e06e42657d5de6c7e24229c4fab340`
- seed: tc 6.1.0에서 `What is "seed"?`로 미지원, 사용값 null. 같은 설정의 랜덤 패킷열 재현을 보장하지 않는다.
- bare `gap 3 delay 50ms`는 reorder 확률을 요구해 실패했고 위 명시적 100%/gap 구문으로 무트래픽 시험을 통과했다.

| 항목 | 상한 |
| --- | --- |
| 동시성·반복·요청 | 1, 4×3=12회, 회차당 신규 연결/GET 각 1회 |
| connect / 개별 I/O / 클라이언트 전체 | 3초 / 5초 / 15초 |
| 공통 캡처 준비 / 캡처별 | 3초 / 20초 또는 1,024패킷 |
| PCAP·메타데이터·필드·분석 파일별 | 1MiB |
| 도구·앱 로그별 / 회차 / 묶음 | 64KiB / 8MiB / 128MiB |
| 회차 작업 / 정리 / 자식 종료 | 60초 / 15초 / TERM 2초 후 KILL 회수 1초 |
| 묶음·최종 기록 / 별도 이미지 빌드 | 960초 / 600초 |
| qdisc queue | 128패킷 |

원래 묶음은 **327.016초**, manifest 내 검증 파일 합계 14,515,447B였다. 준비용 이미지·Git bundle은 실험 전에 전송한 별도 준비 자산이다. 캡처 36개 모두 kernel drop 0, 각 파일/패킷 상한 미만, 시간 제한 종료 124로 검증됐다. worker 종료·파일 fsync 후 바이너리 전송 전후 해시와 저장 해시를 확인했다. 이번 묶음 소유 컨테이너·네트워크 잔여는 0이다.

## 회차별 앱 시간과 ACK RTT

단위는 ms다. connect는 connect 호출 전후, 첫 바이트는 요청 send 시작→첫 recv 반환, 완료는 요청 send 시작→본문 길이·해시 확인 완료의 단조 시각 차이다. 완료 시간에 뒤따르는 FIN/RST를 포함하지 않는다.

ACK RTT는 **S 캡처**에서 서버 데이터 프레임을 참조하는 클라이언트 ACK의 TShark `ack_rtt`다. 해당 seq 범위의 재전송·겹침이 있는 모호한 표본을 제외하고 참조 프레임·시간 차·ACK 범위를 검증했다. 표의 RTT는 표본 개수와 최소–최대이며 전체 세그먼트 RTT 분포가 아니다. 특히 C1의 큰 표본에는 누적/지연 ACK와 손실 영향이 포함될 수 있어 지연 설정값으로 치환하지 않는다.

| 회차 | connect | 첫 바이트 | 본문 완료 | ACK RTT n / 최소–최대 | 종료 관측 |
| --- | ---: | ---: | ---: | --- | --- |
| A1 | 0.426 | 1.955 | 162.329 | 61 / 0.009–2.256 | FIN 정상 |
| A2 | 0.573 | 0.318 | 144.293 | 63 / 0.006–0.886 | FIN 정상 |
| A3 | 0.321 | 0.379 | 147.262 | 64 / 0.007–0.873 | FIN 정상 |
| B1 | 0.481 | 60.629 | 213.274 | 54 / 50.062–59.286 | FIN 정상 |
| B2 | 0.555 | 51.180 | 211.848 | 54 / 50.053–60.329 | FIN 정상 |
| B3 | 0.376 | 57.012 | 205.510 | 56 / 50.052–58.161 | FIN 정상 |
| C1 | 0.368 | 2.776 | 421.808 | 46 / 0.006–206.603 | FIN 정상 |
| C2 | 0.272 | 0.862 | 170.117 | 54 / 0.013–2.744 | FIN 정상 |
| C3 | 0.382 | 1.528 | 143.530 | 60 / 0.010–0.992 | FIN 정상 |
| D1 | 0.366 | 52.856 | 605.409 | 32 / 0.015–51.615 | FIN 정상 |
| D2 | 0.412 | 62.272 | 565.856 | 34 / 0.015–58.625 | FIN 후 RST 2개 |
| D3 | 0.368 | 53.051 | 559.129 | 34 / 0.014–51.862 | FIN 후 RST 2개 |

12회 모두 본문 무결성을 확인했으며 실패·이상 회차를 제외한 평균이나 성공률은 계산하지 않았다. B의 50ms는 한 방향 설정이다. 연결 수립 뒤 적용했으므로 connect가 50ms가 되어야 하는 실험이 아니다. 서버 send 반환·TCP ACK·서버 앱 요청 수신·클라이언트 본문 완료는 각각 다른 로그/패킷 사건이다.

## 패킷·주입 효과와 관측 한계

P/Q는 각각 전체 캡처 프레임 수다. 누락/미대응은 서버→클라이언트의 정확한 seq/ack·길이·IP ID·flags·payload hash 대응에서 P에만/Q에만 남은 수다. 크기가 달라진 GSO 프레임의 미대응을 손실로 세지 않는다. 지연은 정확히 대응된 데이터 프레임의 Q−P 시간이다. 재전송/중복 ACK는 S의 TShark 후보이며, 재전송 종류가 겹쳐도 프레임은 한 번 센다. Q OOO는 TShark out-of-order 후보다. 역전은 최초 관측 seq 범위의 P 순서와 Q 순서가 반대인 인접 대응 쌍으로, 재전송을 별도 새 데이터로 세지 않는다.

| 회차 | P/Q | P만/Q만 | 대응 지연 ms | S 재전송/중복ACK | Q OOO | 대응 역전 쌍 | 효과 전체 판정 |
| --- | --- | --- | --- | --- | ---: | ---: | --- |
| A1 | 134/68 | 0/0 | 0.001–0.017 | 0/0 | 0 | 0 | 기준선 |
| A2 | 136/68 | 0/0 | 0.001–0.005 | 0/0 | 0 | 0 | 기준선 |
| A3 | 137/68 | 0/0 | 0.001–0.006 | 0/0 | 0 | 0 | 기준선 |
| B1 | 127/68 | 1/6 | 50.034–59.218 | 0/0 | 0 | 0 | 전체 판정 불충분 |
| B2 | 125/68 | 3/10 | 50.033–60.244 | 0/0 | 0 | 0 | 전체 판정 불충분 |
| B3 | 126/67 | 2/8 | 50.025–58.071 | 0/0 | 0 | 0 | 전체 판정 불충분 |
| C1 | 123/62 | 10/10 | 0.000–0.005 | 7/3 | 3 | 0 | 전체 판정 불충분 |
| C2 | 147/67 | 11/0 | 0.000–0.009 | 10/6 | 10 | 0 | 전체 대응 확인 |
| C3 | 141/68 | 4/0 | 0.000–0.005 | 4/3 | 4 | 0 | 전체 대응 확인 |
| D1 | 153/79 | 3/8 | 0.000–51.527 | 18/23 | 1 | 12 | 전체 판정 불충분 |
| D2 | 147/76 | 4/10 | 0.000–58.618 | 15/18 | 0 | 11 | 전체 판정 불충분 |
| D3 | 147/76 | 4/10 | 0.000–51.902 | 15/19 | 0 | 11 | 전체 판정 불충분 |

A에는 재전송·중복 ACK·역전이 없었다. C2·C3는 qdisc drop, P/Q 누락, S 재전송 후보가 함께 관측됐다. C1도 drop 5·재전송 후보 7이 있지만 GSO로 대응이 불완전해 동일한 강도로 판정하지 않는다. D에는 Q의 TShark OOO가 0이어도 실제 대응 패킷 역전이 11–12쌍 있다. Q가 한 방향만 포함하고 프레임이 분할·재전송되는 만큼 단일 디섹터 표시만으로 효과를 확정하거나 부정할 수 없다.

클라이언트 eth0/ifb0의 GRO/GSO/TSO는 전후 `ethtool -k`와 각 설정 명령을 보존했고 최종 모두 off였다. 서버에는 NET_ADMIN을 추가하지 않아 송신 GSO를 조정하지 않았다. 그 결과 P/S 최대 TCP payload가 3,564–7,128B인 회차가 있고 Q는 1,188B 이하로 분할됐다. MSS 설정만으로 캡처 프레임 크기를 보장할 수 없었다. 전체 효과 판정은 이때 `effect_inconclusive`, `effect_observed: null`로 남기며, 수치 0의 `effect_unobserved`와 구분한다. 소표본 3회와 seed 미지원도 재현성 한계다.

## qdisc 전후 통계

arm 직후 모든 회차는 packets 1, bytes 74, drops 0, requeues 0이었다(SYN/ACK 기준선 통과). 아래는 해제 직전 절대 카운터다. 최종 backlog/qlen은 모두 0, overlimits도 0이다. 최종 queue 0은 실행 중 최고 점유율의 증거가 아니다. 설정 손실 10%를 관측 소표본의 drop 비율로 치환하지 않으며, 집계 drops만으로 랜덤 손실과 큐 포화 원인을 분리하지 않는다. qdisc의 skb/GSO 집계 수와 tcpdump 필터 프레임 수를 같은 분모로 취급하지 않는다.

| 회차 | packets | bytes | drops | requeues | 최대 TCP payload P/Q |
| --- | ---: | ---: | ---: | ---: | --- |
| A1 | 70 | 70286 | 0 | 0 | 1024/1024 |
| A2 | 70 | 70286 | 0 | 0 | 1024/1024 |
| A3 | 70 | 70286 | 0 | 0 | 1024/1024 |
| B1 | 70 | 70286 | 0 | 0 | 7128/1188 |
| B2 | 70 | 70286 | 0 | 0 | 4752/1188 |
| B3 | 69 | 70220 | 0 | 0 | 7128/1188 |
| C1 | 64 | 69890 | 5 | 0 | 3564/1188 |
| C2 | 68 | 70150 | 12 | 0 | 1188/1188 |
| C3 | 70 | 70286 | 4 | 0 | 1024/1024 |
| D1 | 81 | 93584 | 0 | 25 | 3564/1188 |
| D2 | 78 | 89822 | 0 | 23 | 3564/1188 |
| D3 | 78 | 89822 | 0 | 23 | 3564/1188 |

실제 옵션·적용/검증 시각은 각 `injection.json`, 해제 직전 통계·해제 시각·결과는 `final.json`, 설정 stdout/stderr와 오프로딩 내역은 그 안의 commands에 있다. qdisc는 Q 캡처가 끝난 뒤 해제했다.

## handshake·데이터·ACK·종료 흐름

| 단계 | TCP/앱 근거 | 관측과 해석 |
| --- | --- | --- |
| 연결 수립 | S의 SYN→SYN/ACK→ACK, 각 PCAP의 독립 stream/4-tuple | 연결 1개. 같은 stream 번호라는 이유로 PCAP 간 연결을 동일시하지 않음 |
| 장애 적용 | 양쪽 앱 connected/accepted → tc apply/query → armed → GET | 세 번째 handshake 패킷 ≤ 적용 ≤ 조회 완료 ≤ 요청 송신을 검증 |
| 요청·응답 | GET 1회, HTTP 200, CL 65536, 고정 X-Run-ID | 서버 앱 수신과 응답 send 반환을 별도 기록. 합성 페이로드의 비정상 내용은 없고 네트워크 전달만 제어 |
| 손실·재전송 | C의 drops·S 반복 seq·P/Q 누락·중복 ACK | TCP 자체 재전송이며 앱 재시도가 아님. 누적 ACK와 캡처 위치를 함께 해석 |
| 순서 역전 | D의 P/Q 대응 순서 역전, TShark 양방향/단방향 표시 차이 | 패킷 도착 순서와 앱의 올바른 본문 순서를 구분 |
| 본문 완료 | 양쪽 worker transfer_complete, 앱 body.bin, S/Q TShark 재조립·고정 seq 바이트 범위 | 12회 모두 65,536B와 해시 일치. ACK만으로 앱 완료를 추정하지 않음 |
| 일반 종료 | 양쪽 FIN과 해당 바이트 다음 ACK | 10회는 추가 RST 없이 정상 종료 판정 |
| D2·D3 종료 이상 | S 프레임 136 서버 FIN+data, 144 클라이언트 FIN, 145 서버 ACK, 146·147 클라이언트 RST | ACK 뒤 약 50ms에 RST가 기록됨. 본문 손상/전송 실패로 바꾸지 않고 closure_anomaly로 프로파일 실패 유지 |

D2·D3에서 지연된 패킷이 종료된 소켓에 뒤늦게 도달했을 가능성이 있다. 이는 타임라인에 근거한 해석이며 RST의 내부 커널 발생 원인을 별도 추적한 결과는 아니다. 불리한 두 회차를 삭제하거나 추가 실행으로 대체하지 않았다.

## 원본 분석 실패와 동일 증거 재분석

최초 run의 원본 summary는 `complete: false`, exit 1이다. A 3회는 공유 strict JSON 파서의 Decimal이 앱 로그 직렬화와 맞지 않았고 B/C/D 9회는 Decimal 비율과 float qdisc 비교가 실패했다. 이를 전송 실패나 netem 효과로 판정하지 않았다. 프로파일 경계에서 중복 키·비유한 값·1MiB 검증을 유지하면서 유한 float를 읽도록 수정하고 직렬화된 JSON 회귀 테스트를 추가했다.

원본 PCAP·CSV·TShark follow·앱·qdisc·manifest·summary는 **변경하지 않았다**. 원본 manifest 12개와 파일 해시를 다시 검증해 동일 Linux TShark 추출 결과만 별도 `offline-analysis-v3`에서 분석했다. 추가 TCP/GET은 0이다. 초기 오프라인 v2 결과도 보존했다. 최종 분석은 본문 완료와 종료 이상을 구분하고 GSO 대응 불충분을 효과 0으로 오인하지 않는다. 원본 자동 분석 12건 실패 기록은 성공으로 덮어쓰지 않는다.

## 단위 검증·필수 게이트

기본 pytest에서 실제 Docker/외부 통신을 자동 실행하지 않는다. 합성 TShark 필드/재조립과 가짜 소켓으로 4조건·seq wrap·효과 관측/미관측/판정 불충분·본문 순서·길이/해시·부분 수신·추가 응답·단일 connect/GET을 검증한다. 입력 혼합·시각/바이트/패킷 상한·tc/캡처/서버/클라이언트/저장/중단/정리 실패·ACK RTT 모호성·늦은 RST도 포함한다. 실측을 통과시키기 위해 기존 검증을 삭제·완화하지 않았다.

원본 `C:/Aleph`의 필수 게이트는 기존 `.pytest_cache` ACL 때문에 경로 순회에서 중단했다. ACL·캐시를 변경하지 않았다. 기존 dirty 검증 사본 4개도 손대지 않고 새 관리 worktree `C:/Users/User/.codex/worktrees/network-netem-validation/Aleph`에 허용된 파일만 복사해 SHA-256 일치를 확인했다. 잠금 파일 그대로 `uv sync --locked --extra dev`, `PYTHONUTF8=1` 환경에서 **변경하지 않은** `powershell .\scripts\check.ps1`을 실행했다.

최종 결과는 **1,825 passed, 4 skipped, 1 warning, 187.31초**, scope·표준 경로·Ruff lint/format도 통과했다(Python 3.14.7, Ruff 0.16.4). warning은 기본 socket 차단 확인 테스트의 예상 경고다. 초기 1,813 통과 후 분석 회귀 사례를 추가했다. 중간 대용량 테스트는 pytest 자동 ID가 Windows 환경 변수 상한을 넘겨 setup error였고 짧은 명시적 ID로 수정했다. 해당 실패 로그도 보존한다. 기존 테스트의 CP949 읽기 문제는 UTF-8 실행 환경으로 해결했고 기존 정의를 바꾸지 않았다. 최종 보고서 갱신은 코드 검증 후 문서만 변경한 것이다.

## 증거 위치와 해시

원본은 ignored `C:/Aleph/network/lab/runs/netem/` 아래 보존하며 PCAP·캐시·VM 파일을 Git에 넣지 않는다.

- 최초 WSL 읽기 전용 조회: `20261103T050356Z-eaaba7cb9b56/preflight/`
- 준비/검증: `environment-20261103-ae492bf1/`, 전송 원본: `transfer-ae492bf1/`
- 회수 아카이브: `transfer-ae492bf1/guest-evidence-ae492bf1.tar`
- 실제 원본 묶음: `actual-20261103-ae492bf1/source/network/lab/runs/netem/experiments/20261103T073139Z-d0e3746467de/`
- 별도 오프라인 최종 분석: `actual-20261103-ae492bf1/offline-analysis-v3/`
- 게스트 보존본: `/var/lib/cloudshield-netem/run-ae492bf1/`

| 파일 | SHA-256 |
| --- | --- |
| 최초 WSL 조회 manifest | `88793bbecf1ef84a9fcee7086f6014e081e5e46633acb3f00572f175b7523a3c` |
| 회수 tar, 게스트·Windows 일치 | `f9f64b1d7a055fc20cc206a7b21cf00afd1e15c2cef37168a2133966efda617b` |
| 실제 plan.json | `07d0d874700a40f0e73ffbabbeeeb985088497718d6feeac935afc97863cb22b` |
| 원본 summary.json, 실패 기록 유지 | `8e6bac181c1db2dedc42490aa25460cd2e54fe59bb5ef01da0024438dea98903` |
| 오프라인 v3 manifest.json | `17d5f6b650ee90bda8eabcb5036bb672e1c5597aec554f188557640eb7995cb6` |
| 최종 check-validation-3.log | `e5897b19a16bd9f10be846c80edae15ecbb7f80966b397b434480582b8f596cd` |
| 게이트 소스 일치 기록 validation-source-3.json | `a619fdbe45478764f3a77e7dbbb5c62974f31b5e3f09c29b1810978f2c371f34` |

| 회차 | 원본 manifest.json SHA-256 |
| --- | --- |
| A1 | `29fc356261ba64ae24273d5a4ec0ee9020d304031d5d6fc45f48f6623b106aff` |
| A2 | `5424d215b75c5ec854c25f1ed3e0192185e3fdb2da3cb952331baff7f5856d50` |
| A3 | `1e03796e96b9c8f152ad34d7c9d75e391d5a210f60bedeb25717c27537c2c5a2` |
| B1 | `8848ee16c5cc606e97f36c915efd3f50b406fce3fec28cc860570a61e15baf62` |
| B2 | `08c7956cd3106ffaa3aa480c9afa96bad485dc69465f24ff6311207d2e26e575` |
| B3 | `3f80a8ae9b7b9f19b1b651cb1048fb189e8167f50a2d8313d742caa28af206b0` |
| C1 | `ba59a2f1f73261da354cb6da083226ae8ae4a89cc2b9c50eade5a64e50ba17f0` |
| C2 | `5833ef972013636298fc307712ff2679a66b0487873e34850b46cf183a586302` |
| C3 | `58ef59308d1fdc0c7006349b71132283f8a5de20341421d2c710d35a6ffc456c` |
| D1 | `39723f3e10ea43d52a55da22babde252eaba45a859126971c6c63a4d4fcb15e9` |
| D2 | `6ece2742e5deb9b8277107e9604ffdf38df83f0daef3584024970ff11eba200b` |
| D3 | `501969889dfd7d722ab0fb48bbc0ebe9cda1dd01ced1b40dc4fc7420fbac42db` |

## VM 정리와 재현 명령

VM 스냅샷 `cloudshield-before-netem-20261103-ae492bf1`, UUID `2ae0e3da-af3f-4216-a4d8-f820a643cc26`을 보존했다. 최종 VM은 정상 종료, NIC1~8 none, 임시 공유 폴더 없음이다. 기존 `ssh,tcp,127.0.0.1,2222,,22` 규칙은 disabled NAT 설정에 복원했다. 활성 포트 포워딩은 없다. Windows 설정과 다른 VM은 변경하지 않았다. 게스트 패키지·이미지·소스·증거는 보존하며 커널 모듈 로드는 재부팅 후 다시 필요하다.

다음은 향후 새 실행을 위한 명령이다. 이번 12회를 다시 실행한 기록은 아니다. 모듈 준비는 **승인된 전용 Ubuntu-Lab 내부에서만** 수행하고, 이미지 빌드/다운로드 준비 후 외부 NIC를 끊어 run한다. 원본/기존 실행 디렉터리를 덮어쓰지 않는다.

```bash
# 전용 Linux VM 내부, 모듈 로드가 승인된 환경 준비 단계
for module in ifb sch_netem sch_ingress cls_u32 act_mirred; do
  sudo modprobe "$module"
done
sudo systemctl start docker
# Docker 권한이 있는 로컬 사용자, 명시적 준비 단계
python3 network/lab/netem_lab.py plan
python3 network/lab/netem_lab.py build
# 이미지·필수 기능이 준비되고 외부 연결을 끊은 뒤
python3 network/lab/netem_lab.py run
```

run은 무트래픽 기능 시험이 실패하면 실제 전송을 시작하지 않는다. 기본 plan에는 파일·Docker·네트워크 부작용이 없다. Notion 상태/PR/Commit 속성은 직접 갱신하지 않고 GitHub Actions에 맡긴다.

## 분산 인프라 5대 제약

1. 수명주기: Lambda·호출 간 상태 공유는 없고 소유 프로세스 수명을 관리한다.
2. 스토리지: DB/400KB/TTL은 비적용이며 파일·회차·묶음·qdisc 큐 상한을 적용한다.
3. 일관성: worker 종료·fsync·전송 전후 해시 확인 후 분석한다.
4. 순서 역전: 패킷 도착 순서와 TCP가 앱에 전달한 본문 바이트 순서를 구분한다.
5. 장애 전파: DLQ는 비적용이며 도구·전송·저장·정리 오류와 부분 증거를 명시한다.
