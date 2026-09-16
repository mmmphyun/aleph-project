# Docker SSH 단일 연결 SYN/ACK 실측 분석

- 상태: 실제 pcap 확보 및 tshark 분석 완료
- 담당: 네트워크
- GitHub Issue: https://github.com/mmmphyun/aleph-project/issues/28
- Notion Task: https://notion.so/3d404d37c22581bb995bf25b914b8abe
- 실험 일시: 2026-09-16 12:39:05 KST (UTC+09:00)
- 분석 방식: tshark CLI 완료, Wireshark GUI 확인 미수행

## 1. 목적과 실험 경계

격리된 로컬 Docker 내부 네트워크에서 SSH 서버의 TCP 2222 포트로 키 기반 연결을 정확히
한 번 수행하고, 같은 연결의 SYN → SYN/ACK → ACK와 정상 종료를 실제 pcap에서 확인했다.
Hydra, Nmap, 외부 서버, 호스트 포트 공개는 사용하지 않았다.

클라이언트와 서버는 하나의 Docker Desktop WSL2 호스트 안에 있는 전용 `--internal` bridge의
가상 인터페이스로 통신했다. 측정 경로에 호스트 포트 매핑이나 외부 NAT는 없지만 Docker bridge,
WSL2 가상 NIC, 호스트 스케줄링과 오프로딩의 영향을 받는다. 이 결과를 EC2/GCP의 RTT,
Security Group/WAF 동작, 외부 방화벽 또는 CloudShield 10초 대응 시간으로 일반화하지 않는다.

## 2. 환경과 실행 조건

| 항목 | 실측값 |
| --- | --- |
| 호스트 OS | Windows 11, 10.0.26200.9457 |
| Docker Desktop | 4.91.0, build 239619 |
| Docker client / server | 29.8.0 / 29.8.0 |
| Docker context / 엔진 | `desktop-linux` / Linux x86_64 |
| WSL / 커널 | WSL 2.7.14.0 / 6.18.33.2-microsoft-standard-WSL2 |
| 컨테이너 OS | Debian GNU/Linux 12 (bookworm) |
| 실측 이미지 | `sha256:46e9c925d2f0e656e8660150c10e5ef34e27fde99b798e1910836d6cb5f710ab` |
| 이미지 크기 | 154,032,566 bytes |
| tcpdump / libpcap | 4.99.3 / 1.10.3 (TPACKET_V3) |
| SSH | OpenSSH_9.2p1 Debian-2+deb12u10, OpenSSL 3.0.20 |
| 분석 도구 | TShark 4.6.8, v4.6.8-0-ge677bf052328 |
| 클라이언트 | `172.18.0.3`, 인터페이스 `eth0` |
| 서버 | `172.18.0.2:2222` |
| readiness | 서버 내부 LISTEN 상태 확인, 사전 TCP 연결 0회 |

실험 이미지는 빌드 단계에서만 Debian 이미지와 패키지를 다운로드했다. 실행 단계의 서버와
클라이언트는 전용 내부 bridge 하나에만 연결했다. 포트 공개, host 네트워크, privileged 모드,
Docker 소켓·호스트 개인 키·기존 known_hosts 마운트는 사용하지 않았다.

## 3. 실행 명령과 종료 결과

호스트에서 실행한 명령은 다음과 같다. 러너가 Docker inspect로 실제 IP와 인터페이스를 확인한 뒤
기존 `network/tcpdump_capture.sh`와 `network/ssh_single_connect.sh`를 호출했다.

```powershell
.\.venv\Scripts\python.exe network/lab/run.py build
.\.venv\Scripts\python.exe network/lab/run.py run
```

실제 캡처 명령의 핵심 인자는 다음과 같다.

```text
bash /opt/network/tcpdump_capture.sh 172.18.0.2 2222 eth0 /tmp/capture.pcap 10 1000
capture filter: ip and tcp and host 172.18.0.2 and port 2222
SSH: bash /opt/network/ssh_single_connect.sh 172.18.0.2 lab 2222 5
```

| 확인 항목 | 결과 |
| --- | --- |
| 캡처 준비 | stderr에서 `tcpdump: listening on eth0` 확인 후 SSH 실행 |
| SSH 실행 횟수 / 종료 코드 | 1회 / 0 |
| 인증 근거 | 서버 로그의 `Accepted publickey for lab from 172.18.0.3 port 53320` |
| 캡처 래퍼 종료 | 권한 강하 뒤 생존 확인 권한 부족으로 호스트 15초 대기 제한 발생, 최종 코드 1 |
| pcap 보존 / 읽기 | 성공 / tcpdump 코드 0 |
| 후속 시간 제한 검증 | 수정 이미지의 `--network none` loopback 캡처가 3초 뒤 코드 124, 0 packet, drop 0으로 종료 |

캡처 래퍼의 코드 1은 SSH 또는 pcap 실패를 뜻하지 않는다. tcpdump가 `tcpdump` UID로 권한을
낮춘 뒤 부모 셸에 다른 UID 프로세스를 감시할 `KILL` capability가 없어 `wait`에 머문 것이 원인이다.
pcap은 `-U` 패킷 단위 기록으로 복사됐고 39개 패킷 전체와 양방향 FIN 종료가 읽혔다.
수정본은 클라이언트에 `NET_RAW`, `SETUID`, `SETGID`, `KILL`만 부여하며 `NET_ADMIN`은 부여하지 않는다.

## 4. pcap 증거와 분석 명령

| 항목 | 값 |
| --- | --- |
| 로컬 경로 | `C:\Aleph\network\lab\runs\20260916T033900Z-707fb648\capture.pcap` |
| Git 추적 | `network/lab/.gitignore`의 `runs/` 규칙으로 제외 |
| 파일 크기 | 10,472 bytes |
| 패킷 수 | 39 |
| 캡처 시간 | 0.176109초 |
| 최초 / 최종 패킷 | 2026-09-16 12:39:05.168661 / 12:39:05.344770 KST |
| SHA-256 | `2a63b868f1f3334eaafeb60601811101263daf2287fc1bc4a13d9c6cc3ace667` |
| capinfos / tshark / tcpdump 읽기 | 모두 종료 코드 0 |
| tcpdump drop 통계 | 실측 래퍼가 정상 종료하지 않아 확보하지 못함 |

```powershell
$pcap = 'C:\Aleph\network\lab\runs\20260916T033900Z-707fb648\capture.pcap'
$tshark = 'C:\Program Files\Wireshark\tshark.exe'
& $tshark -r $pcap -n -o tcp.relative_sequence_numbers:TRUE `
  -Y 'tcp.port == 2222' -T fields -E header=y -E separator=, -E quote=d `
  -e frame.number -e frame.time_epoch -e frame.time_relative -e tcp.stream `
  -e ip.src -e tcp.srcport -e ip.dst -e tcp.dstport -e tcp.flags `
  -e tcp.seq -e tcp.ack -e tcp.len -e tcp.analysis.retransmission `
  -e tcp.analysis.fast_retransmission -e tcp.analysis.spurious_retransmission
```

tshark는 SSH의 `sntrup761x25519-sha512` 키 교환을 보고하면서 개인 키 복호화를 지원하지 않는다는
dissector 경고를 출력했다. 이 경고는 TCP 헤더 분석 실패가 아니다. SSH 암호화 이후 패킷에서
사용자 비밀번호나 인증 내용을 읽지 않았고, 인증 성공은 서버 로그와 SSH 종료 코드로 확인했다.

## 5. 연결 타임라인

분석 대상은 `tcp.stream == 0`, 4-tuple은
`172.18.0.3:53320 → 172.18.0.2:2222`이다. 시간은 프레임 1 SYN을 0으로 한 상대 시각이며,
Seq/Ack는 tshark의 상대 시퀀스 번호다.

| 단계 | 프레임 | SYN 대비 시간 | 방향 | 플래그 | Seq / Ack | 관측 사실 |
| --- | ---: | ---: | --- | --- | --- | --- |
| 연결 요청 | 1 | 0.000 ms | client:53320 → server:2222 | SYN (`0x0002`) | 0 / 0 | 최초 SYN |
| 서버 응답 | 2 | 0.023 ms | server:2222 → client:53320 | SYN, ACK (`0x0012`) | 0 / 1 | 클라이언트 SYN의 Seq+1 확인 |
| 연결 수립 | 3 | 0.030 ms | client:53320 → server:2222 | ACK (`0x0010`) | 1 / 1 | 서버 SYN의 Seq+1 확인 |
| 클라이언트 종료 | 36 | 175.410 ms | client:53320 → server:2222 | FIN, ACK (`0x0011`) | 3674 / 3562 | 클라이언트가 정상 종료 시작 |
| FIN 확인 | 37 | 175.446 ms | server:2222 → client:53320 | ACK (`0x0010`) | 3562 / 3675 | 클라이언트 FIN 확인 |
| 서버 종료 | 38 | 176.054 ms | server:2222 → client:53320 | FIN, ACK (`0x0011`) | 3562 / 3675 | 서버 FIN |
| 종료 완료 | 39 | 176.109 ms | client:53320 → server:2222 | ACK (`0x0010`) | 3675 / 3563 | 서버 FIN 확인 |

SYN/ACK은 최초 SYN 뒤 0.023 ms, 3-way handshake의 세 번째 ACK는 0.030 ms에 관측됐다.
이는 같은 호스트 내부 가상 bridge에서의 관측 간격이며 인터넷 RTT나 애플리케이션 응답 시간이 아니다.

RST 프레임은 0개, tshark가 표시한 일반·fast·spurious 재전송은 모두 0개였다.
FIN은 양방향에서 관측됐고 마지막 ACK까지 포함되어 정상적인 4-way 종료로 해석한다.

## 6. 정상 기준선과 향후 비교

이번 정상 단일 연결의 기준선은 TCP 스트림 1개, 최초 SYN 1개, 완전한 3-way handshake 1개,
SSH 종료 코드 0, 공개 키 인증 성공, RST·재전송 0개, 양방향 FIN 종료, 총 39패킷이다.

향후 별도로 승인된 Hydra 실험에서는 동일한 캡처 위치·필터·시간 기준을 유지하고 다음을 비교한다.

- 관측 구간당 고유 4-tuple과 최초 SYN 수
- 완전한 handshake와 미완성 handshake의 수 및 비율
- 연결 시도 간격과 SYN 재전송 중복 제거 결과
- RST/FIN의 방향·시점 및 tcpdump 드롭 통계
- 서버 인증 로그의 실패 시각·출발지와 패킷 타임라인의 상관관계

반복 SYN, RST 또는 연결 수만으로 SSH 무차별 대입을 확정하지 않는다. SSH 인증 내용은 암호화되므로
서버 로그를 함께 사용하고 관측 사실과 원인 해석을 구분한다.

## 7. 산출물과 정리 상태

원본 pcap, manifest, SSH/tcpdump 로그, capinfos와 tshark CSV는 위 `runs` 디렉터리에 보존했다.
바이너리 pcap과 로컬 로그는 Git에 추가하지 않는다. 실험용 개인 키와 host key는 컨테이너 제거와
함께 삭제됐다. 실험이 만든 서버·클라이언트 컨테이너와 내부 네트워크의 정리는 모두 성공했다.
기존 `hello-one` 컨테이너와 `hashicorp/http-echo:1.0.0` 이미지는 변경하지 않았다.

재현용 `cloudshield-network-ssh-lab:local` 이미지는 후속 실험을 위해 남겨 두었다. 광역 정리 명령은
사용하지 않았으며, 필요할 때 이 태그 하나만 명시적으로 제거한다.
