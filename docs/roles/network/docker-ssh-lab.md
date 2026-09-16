# Docker 로컬 SSH 단일 연결·캡처 실험

상태: 환경 구성 및 모의 검증용. Docker 실측은 아직 수행하지 않았다.
완료 범위는 [환경 준비 Issue](https://github.com/mmmphyun/aleph-project/issues/54)이며,
[실측 보고서 Issue](https://github.com/mmmphyun/aleph-project/issues/28)는 별도 대기 상태다.

## 구조와 경계

`network/lab/run.py`는 Python 표준 라이브러리만 사용한다. import만으로 Docker를 실행하지 않는다.
명시적인 `build`와 `run`을 분리하여 이미지 다운로드와 실험 트래픽을 구분한다.
빌드는 Debian bookworm slim과 apt 저장소에서 패키지를 다운로드한다. 이미지 크기는 빌드 전
확정할 수 없으며, 완료 후 `docker image inspect cloudshield-network-ssh-lab:local`의 Size를 확인한다.
베이스 태그·패키지 버전은 고정 digest가 아니므로 재빌드 결과가 달라질 수 있다.
실측 manifest에 이미지 ID/레이어·OS·도구 버전을 남겨 실행 결과를 식별한다.

런타임은 다음 경계를 적용한다.

- 매 실행 UUID 이름의 전용 `--internal` bridge 네트워크와 서버/클라이언트 컨테이너 각 1개.
- 포트 공개, host 네트워크, bind mount, Docker 소켓, privileged 모드 없음.
- `--cap-drop ALL` 뒤 클라이언트는 `NET_RAW`만 추가. `-p` 캡처로 promiscuous 모드를 사용하지 않는다.
- 서버는 sshd의 UID/GID 전환·privilege separation에 필요한 `SETUID`, `SETGID`, `SYS_CHROOT`만 추가.
  포트는 2222이므로 `NET_BIND_SERVICE`가 필요 없다. 실제 이미지에서의 동작은 후속 검증 대상이다.
- no-new-privileges, 메모리 256MiB 및 PID 64 제한. 권한 오류 시 자동으로 capability를 늘리지 않는다.
- 로컬 npipe/unix Docker context만 허용. TCP/SSH 원격 Docker 및 Windows 컨테이너 엔진 거부.
- Docker 내부 네트워크는 외부 라우팅을 제한한다. 호스트 관리자나 같은 네트워크에 임의로
  연결한 컨테이너까지 차단하는 보안 경계로 간주하지 않는다.

참조: [Docker 네트워크](https://docs.docker.com/engine/network/),
[bridge 격리와 포트](https://docs.docker.com/engine/network/drivers/bridge/).

## 실행 준비

Docker Desktop Linux 엔진이 필요하다. Windows에서는 WSL2와 가상화 지원을 먼저 확인한다.
설치, OS 기능 활성화, 관리자 권한, BIOS/가상화 변경 및 재부팅은 사용자 승인 후 별도 진행한다.
Git Bash는 기존 셸 모의 테스트에 사용하며 실험용 Bash는 컨테이너에 있다.

PowerShell, 저장소 루트에서:

```powershell
# 다운로드를 수반하는 명시적 이미지 빌드
.\.venv\Scripts\python.exe network/lab/run.py build
# 빌드된 로컬 이미지만 사용. 내부 SSH 연결은 정확히 한 번
.\.venv\Scripts\python.exe network/lab/run.py run
```

런타임 이미지가 없으면 실패하며 자동 pull/build 또는 실제 SSH 폴백을 하지 않는다.
Docker CLI가 PATH에 없을 때 표준 설치 경로·설치 목록·서비스를 먼저 확인한다.
동일 전용 이미지 태그를 사용하는 build와 run은 동시에 실행하지 않는다.

## 인증·준비 확인·캡처

1. 서버는 매번 새 Ed25519 호스트 키를 생성한다. lab 계정만 공개 키 인증을 허용한다.
   빈 계정 비밀번호는 계정 잠금 해제 목적이며 비밀번호·빈 비밀번호 인증은 sshd 설정으로 금지한다.
2. 서버 내부 `ss -H -lnt 'sport = :2222'`로 LISTEN 상태를 확인한다. readiness TCP 연결 수는 0이다.
3. Docker inspect로 두 IP를 확인하고 클라이언트 `ip -j route get <서버IP>`의 dev/prefsrc를 확인한다.
4. 클라이언트의 lab UID가 `/home/lab/.ssh/id_ed25519`를 임시 생성한다.
   공개 키만 서버 authorized_keys로 전달한다. 개인 키·호스트 known_hosts는 공유하지 않는다.
5. 서버 공개 호스트 키를 `docker exec ... cat /etc/ssh/ssh_host_ed25519_key.pub`로 읽어
   클라이언트 `/home/lab/.ssh/known_hosts`에 `[실제IP]:2222` 형식으로 등록한다.
   ssh-keyscan 연결이나 StrictHostKeyChecking 해제는 사용하지 않는다.
6. 기존 `network/tcpdump_capture.sh <서버IP> 2222 <dev> /tmp/capture.pcap 10 1000` 실행.
   stderr의 `listening on`과 프로세스 생존을 확인한 뒤에만 SSH를 실행한다.
7. 기존 `network/ssh_single_connect.sh <서버IP> lab 2222 5`를 lab UID와
   `HOME=/home/lab`에서 1회 실행한다. passwd의 홈도 동일하다.
   외부 `timeout 15`로 전체 SSH 실행 시간까지 제한한다. 성공 시 원격 `true`만 실행한다.
8. 캡처 종료 후 파일 복사·tcpdump 읽기·크기·SHA-256·종료 코드를 기록하고 해당 실행 자원만 정리한다.

tcpdump 실행 어댑터 `/usr/local/bin/tcpdump`는 `-Z root`를 추가한다.
Debian 기본 `-Z tcpdump`의 UID/GID 변경을 위해 불필요한 capability를 추가하지 않으려는 설정이다.
캡처 프로세스는 root UID이지만 capability는 NET_RAW뿐이다.
[Debian tcpdump 매뉴얼](https://manpages.debian.org/bookworm/tcpdump/tcpdump.8.en.html)의 `-Z` 참고.
기존 두 스크립트는 변경하지 않는다. 해당 권한 구성과 stdout FD flush는 실제 Docker에서 검증해야 한다.

## 증거와 실패 처리

각 실행 산출물은 `C:\Aleph\network\lab\runs\<UTC 시각-UUID>\`에 독점 생성한다.
Linux에서 실행하면 해당 저장소의 같은 상대 경로를 사용한다.
`network/lab/.gitignore`가 runs 전체를 제외하며 바이너리 pcap·로그를 커밋하지 않는다.

| 산출물 | 의미 |
| --- | --- |
| manifest.json | 호스트 OS, UTC, context/엔진/이미지 정보, 실제 명령과 stdout/stderr, IP/dev, 종료 코드, 해시, 정리 실패 ID |
| capture.pcap | 컨테이너 `/tmp/capture.pcap`에서 복사한 실제 파일. 실측 실행 전에는 없음 |
| capture.stderr / capture.stdout | 캡처 준비, 패킷/드롭 통계와 종료 사유 |
| ssh.stderr / ssh.stdout | 1회 SSH 실행 결과. 종료 코드는 manifest에 기록 |
| tcpdump-read.txt | 원본 pcap 읽기 결과. 읽기 종료 코드는 manifest에 기록 |

캡처 코드 124는 1000패킷 이전에 10초 제한이 도달한 경우다. 코드 0/124라도 파일 읽기 실패나
패킷 부재면 성공이 아니다. 읽기 성공도 SYN 3단계·인증 성공·무손실 캡처를 자동 보증하지 않는다.
SSH 코드 255는 SSH 오류, 124는 외부 timeout이다. 두 124를 혼동하지 않는다.
오류/사용자 중단 시에도 가능한 pcap을 복사하고 정확히 생성에 성공한 컨테이너 ID만 제거한다.
정리 실패는 manifest의 `remaining_resources`로 보고한다. pcap 복사가 실패하면 원본을 가진
클라이언트와 네트워크를 보존하여 수동 복구할 수 있게 한다(임시 키도 이 컨테이너에 남음).
강제 종료/엔진 장애 때는
복사 자체가 실패할 수 있으므로 삭제 전 컨테이너의 `/tmp/capture.pcap`을 먼저 보존한다.

자동 정리 후 임시 인증 키와 서버 호스트 키는 컨테이너와 함께 삭제된다.
호스트에는 pcap/로그만 남는다. 이미지 및 Docker 빌드 캐시는 재실행을 위해 보존한다.
정리 실패 시 manifest의 정확한 ID·label을 `docker inspect`로 확인한 뒤 다음처럼 정리한다.

```powershell
docker --context <manifest의-context> cp <이번-client-ID>:/tmp/capture.pcap <새로운-보존경로>
docker --context <manifest의-context> rm -f <이번-client-ID> <이번-server-ID>
docker --context <manifest의-context> network rm <이번-network-ID>
```

`docker system prune`, 다른 프로젝트 자원 삭제, 이름 패턴으로 일괄 삭제는 하지 않는다.
로그에는 컨테이너 메타데이터가 포함되므로 공유 전 검토한다. 개인 키 내용은 로그에 기록하지 않는다.

## 후속 tshark 분석 명령

실제 pcap을 확보한 뒤 PowerShell에서 실행한다. `$pcap`은 실제 새 실행 경로로 바꾼다.

```powershell
$pcap = 'C:\Aleph\network\lab\runs\<실제-run>\capture.pcap'
$tshark = 'C:\Program Files\Wireshark\tshark.exe'
& $tshark --version
Get-Item -LiteralPath $pcap | Select-Object Length
Get-FileHash -LiteralPath $pcap -Algorithm SHA256
& $tshark -r $pcap -n -o tcp.relative_sequence_numbers:TRUE -Y 'tcp.port == 2222' -T fields -E header=y -E separator=, -e frame.number -e frame.time_epoch -e frame.time_relative -e tcp.stream -e ip.src -e tcp.srcport -e ip.dst -e tcp.dstport -e tcp.flags -e tcp.seq -e tcp.ack -e tcp.len -e tcp.analysis.retransmission -e tcp.analysis.fast_retransmission -e tcp.analysis.spurious_retransmission
```

분석 명령의 `$LASTEXITCODE`, tshark stderr 및 결과 CSV도 같은 runs 폴더에 별도 저장한다.
실제 스트림 번호로 `tcp.stream == N`을 적용하고 4-tuple을 기록한다.
최초 SYN의 상대 시각을 빼서 연결 기준 시간을 계산한다. SYN의 Seq+1을 확인하는 SYN/ACK,
서버 SYN의 Seq+1을 확인하는 ACK인지 실제 헤더로 검증한다.
FIN/RST·재전송은 해당 프레임과 방향을 확인한 경우만 보고한다.
Wireshark GUI를 별도로 열지 않았다면 **tshark 분석 / GUI 확인 미수행**으로 명시한다.

## 테스트

`powershell .\scripts\check.ps1`을 우회 없이 실행한다.
새 단위 테스트는 기존 `tests/unit/test_network.py`에만 추가한다.
Docker 호출·캡처 프로세스·SSH를 모의 객체로 대체하여 기본 pytest에서 Docker나 다운로드,
실제 네트워크 연결을 실행하지 않는다. 모의 파일은 실측 증거가 아니다.
