# Docker 내부 Hydra 인증 실패 재현

실측 결과와 TCP 스트림 분석은
[Hydra SSH 인증 실패 격리 실험 보고서](2026-09-21-hydra-validation.md)에 기록한다.

## 목적과 승인 경계

기존 `network/lab/run.py`의 로컬 엔진 검사, LISTEN 준비 확인, PCAP 보존 및 소유 리소스
정리를 재사용한다. 기존 키 기반 Dockerfile·sshd_config·SSH 단일 연결 스크립트는 변경하지 않는다.
별도 Hydra 이미지의 비루트 계정 `hydralab` 하나에만 실패 후보를 전달한다.

호스트 SSH, 외부 서버, 클라우드, 다른 Docker 프로젝트, Nmap 및 실제 탐지·차단 파이프라인은
범위 밖이다. 사용자는 IP·호스트·계정·사전 경로를 지정할 수 없다. 서버 주소는 이번 실행에서
생성한 컨테이너 inspect 결과만 사용한다. 사설 IP라는 이유로 실행을 허용하지 않는다.

## 실행과 중단

PowerShell, 프로젝트 루트 `C:\Aleph`에서 실행한다. Docker Desktop의 Linux 엔진이 필요하다.
사용자별 설치 경로를 현재 셸 PATH에 추가하는 예이며 시스템 PATH는 변경하지 않는다.

```powershell
$env:PATH = 'C:\Users\User\AppData\Local\Programs\DockerDesktop\resources\bin;' + $env:PATH
uv run python network/lab/hydra_lab.py
uv run python network/lab/hydra_lab.py build
uv run python network/lab/hydra_lab.py run --execute --candidates 6 --seconds 30
```

Linux/Git Bash에서는 `bash network/hydra_ssh_lab.sh`에 같은 인자를 전달할 수 있다.
기본 호출과 `run` 단독 호출은 dry-run이며 Docker도 호출하지 않는다. `build`만 패키지를
다운로드한다. 실행 네트워크는 `--internal` bridge이고 호스트 포트를 공개하지 않는다.
host 네트워크·privileged·bind mount·Docker 소켓 마운트를 사용하지 않는다.

중단은 Ctrl+C 한 번이다. 러너는 증거 보존과 정리를 시도하므로 종료를 기다린다.
호스트 강제 종료, 엔진 장애, 두 번째 중단은 finally 처리까지 보장하지 않는다.
해당 경우 manifest의 정확한 소유 컨테이너 ID·네트워크 ID를 확인하고 PCAP을 먼저 복구한다.
다른 프로젝트가 포함되는 `docker system prune`, 이름 기반 일괄 삭제는 사용하지 않는다.

## 입력·자격증명·시간 제한

| 항목 | 제한 |
| --- | --- |
| 포트 / 동시성 | 2222 / 1 고정, 다른 입력 거부 |
| 후보 | 기본 6개, 1~10개; 실행 시 생성한 `WRONG-` 접두어의 무작위 합성값 |
| 서버 정답 | 서버 시작 시 `RIGHT-` 접두어의 별도 난수 생성, `chpasswd` stdin으로 전달 |
| 인증 설정 | password 전용, root 로그인 금지, AllowUsers hydralab, MaxAuthTries 6 |
| Hydra 시간 | 기본 30초, 입력 3~55초; 외부 timeout과 강제 종료 유예 포함 60초 이내 |
| 캡처 | Hydra 제한+3초, 최대 58초, 최대 5000패킷; 종료 flush 유예 최대 2초 |
| 빌드·준비·보존 | 공격 트래픽 시간과 별도, 각 Docker 호출에도 제한 적용 |

정답과 후보는 접두어가 달라 일치하지 않는다. 평문 정답은 파일·명령 인자·환경변수·로그에
저장하지 않는다. shadow 해시는 서버 컨테이너에만 남고 서버 삭제와 함께 제거된다.
후보·Hydra 원문·복구 파일은 클라이언트의 `/run/private` tmpfs 아래 0700 임시 폴더에서 생성한다.
임시 파일은 0600 권한이며 정상 종료·예외·중단 시 제거한다. 원문 출력을 호스트로 복사하지 않고
상태·버전·종료 코드·시각만 전달한다. PCAP 복사 실패로 클라이언트를 남길 때도 private 경로를
정리하고 결과를 기록한다. 엔진 장애로 정리가 실패하면 남은 리소스를 수동 확인해야 한다.

Hydra에는 `-t 1 -f -K -I`를 적용한다. 병렬도를 확대하거나 복구 실행·자동 재실행하지 않는다.
`-K`는 실패 시도의 재처리를 끄며, `-f`는 인증 성공 발견 시 종료한다.
지원 모듈과 옵션은 실행 이미지의 `hydra -h`에서 확인한다.
근거: [Hydra 공식 옵션 구현](https://github.com/vanhauser-thc/thc-hydra/blob/master/hydra.c).

## 증거 수집과 결과 판정

1. 서버 내부 `ss -H -lnt 'sport = :2222'`로 준비를 확인한다. 준비 확인용 SSH 접속은 만들지 않는다.
2. 소유 라벨, 서버·클라이언트의 정확한 ID, 전용 네트워크의 두 멤버, 이미지 ID, 포트 비공개,
   실제 `sshd -T` 설정을 검증한다. 실행 직전에도 다시 확인한다.
3. 클라이언트 `ip -j route get`의 실제 인터페이스와 출발 IP를 확인한다.
   필터는 `ip and tcp and host <서버 IP> and port 2222`이다.
4. tcpdump의 `listening on` 이후 Hydra를 한 번 실행한다. 성공·시간 초과·연결 오류·도구 오류·중단을
   별도 상태로 기록한다. Hydra 코드 0만으로 재현 성공을 선언하지 않는다.
5. 실제 `sshd -D -e`의 stderr를 `docker logs --timestamps`로 확보한다. `Failed password for
   hydralab from <클라이언트 IP> port ... ssh2`를 세고 `Accepted`가 하나라도 있으면 실패 처리한다.
6. 캡처 코드 124는 유한 시간 종료이며 캡처 오류와 구분한다. 코드 0/124에 더해 PCAP 복사,
   tcpdump 읽기, 비어 있지 않은 패킷, 크기와 SHA-256을 확인한다. 드롭 통계가 없으면 null이다.

`network/lab/runs/<UTC>-hydra-<식별자>/`는 Git 제외 로컬 경로다. manifest에 호스트 OS·시간대,
Docker 버전·이미지 ID·컨테이너 OS·OpenSSH·tcpdump·Hydra 버전, 주소·인터페이스·실행 시각,
종료 코드·로그 실패 수·PCAP 지표·정리 결과가 남는다. `sshd.log`, `capture.stderr`,
`capture.pcap`, `tcpdump-read.txt`는 컨테이너 정리 후에도 보존된다.
호스트 파일에는 평문 후보를 전달하지 않는다. Windows 증거 경로는 사용자 디렉터리 ACL을
확인하고 공유하지 않는다. 원본 대신 필요한 마스킹 발췌만 문서화한다.

후보 수, 로그의 실패 수, 최초 SYN 수, TCP 스트림 수는 독립적으로 측정한다.
Hydra SSH 모듈은 연결 상태와 서버 인증 제한에 따라 연결을 재사용하거나 새로 연결할 수 있다.
코드상의 가능성을 실측으로 단정하지 않는다.
근거: [Hydra 공식 SSH 모듈](https://github.com/vanhauser-thc/thc-hydra/blob/master/hydra-ssh.c).

## 패킷 분석 절차

```powershell
$run = 'C:\Aleph\network\lab\runs\<이번 실행 폴더>'
& 'C:\Program Files\Wireshark\capinfos.exe' -c -s -H "$run\capture.pcap"
& 'C:\Program Files\Wireshark\tshark.exe' -r "$run\capture.pcap" -T fields `
  -E header=y -E separator=, -e frame.number -e frame.time_relative `
  -e ip.src -e tcp.srcport -e ip.dst -e tcp.dstport -e tcp.stream `
  -e tcp.flags -e tcp.seq -e tcp.ack | Set-Content "$run\frames.csv"
& 'C:\Program Files\Wireshark\tshark.exe' -r "$run\capture.pcap" `
  -Y 'tcp.flags.syn == 1 || tcp.flags.fin == 1 || tcp.flags.reset == 1 || tcp.analysis.retransmission'
```

각 스트림의 최초 SYN·SYN/ACK·ACK와 종료 프레임을 분석 보고서의 4-tuple·프레임·상대 시각·
플래그·Seq/Ack 표에 기록한다. 서버 로그의 출발 포트와 연결해 실패 횟수를 비교한다.
반복 SYN/RST만으로 무차별 대입을 확정하지 않으며 SSH 암호문에서 비밀번호나 실패 메시지를
읽었다고 해석하지 않는다. tshark CLI 분석과 Wireshark GUI 확인 여부를 별도로 기록한다.

## 보안 직무 연계와 한계

읽기 전용 확인한 `src/detection/rules.py`의 현재 조건은 동일 IP·계정에서 300초 내 5회 실패이며,
다중 계정은 같은 기간 고유 계정 2개이다. 이번 실험은 계정 하나라 스프레이 조건 검증이 아니다.
정규식의 관심 필드는 `Failed password for [invalid user ]<계정> from <IPv4> port <포트> ssh2`다.
계약 파서는 시간·호스트·`sshd[PID]:` 접두어도 요구한다.

실험의 stderr + Docker 타임스탬프 형식은 운영 auth.log의 syslog 접두어와 다르다.
서버 원문을 탐지 조건에 맞춰 조작하지 않는다. 수집 담당과 타임스탬프·호스트·PID 보강 경로를
협의해야 하며, 배치 간 누적은 플랫폼 후속 작업이다. 로그가 5회 미만이면 그 차이를 기록하고
후보·동시성·시간을 승인 범위 밖으로 확대하지 않는다. 전체 탐지·차단 성공을 주장하지 않는다.

로컬 bridge·WSL2·오프로딩·스케줄러의 결과를 외부 클라우드 RTT, SG/WAF/IAM 차단이나
10초 대응 SLA로 일반화할 수 없다.

## 테스트와 리소스 정리

`powershell .\scripts\check.ps1`로 역할 범위·경로·Ruff·pytest를 실행한다.
단위 테스트는 Docker/네트워크 대신 모의 실행기를 사용하며 실제 Hydra로 폴백하지 않는다.
원래 SSH·tcpdump 테스트도 그대로 수집한다.

컨테이너와 내부 네트워크는 생성 성공한 정확한 ID만 정리한다. PCAP 복사가 실패하면
원본 클라이언트와 네트워크를 보존하므로 manifest의 `remaining_resources`를 확인한다.
복구 후 해당 ID만 `docker rm -f <ID>`, `docker network rm <ID>`로 제거한다.
빌드 이미지는 남긴다. 더 사용하지 않을 때 `docker image rm cloudshield-network-hydra-lab:local`로
전용 태그만 제거한다. 기존 `cloudshield-network-ssh-lab:local`은 유지한다.
