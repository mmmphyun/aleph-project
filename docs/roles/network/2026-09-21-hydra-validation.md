# Hydra SSH 인증 실패 격리 실험 보고서

## 1. 상태와 추적 관계

**Docker 내부 격리 환경에서 Hydra 인증 실패 재현과 PCAP 분석을 완료했다.**
인증 성공은 0건이고 서버 실패 로그는 7건이다. 이번 검증은 네트워크 담당 범위인
모의 공격·패킷 분석까지이며 CloudWatch, Lambda, 자동 차단과 Slack 전파는 실행하지 않았다.

- Notion: https://notion.so/3d404d37c225819b9e05fc015bc4df3d
- Issue: https://github.com/mmmphyun/aleph-project/issues/67
- 브랜치: `feat/network-hydra-isolated-lab`
- 실행 가이드: [hydra-ssh-lab.md](hydra-ssh-lab.md)
- 성공 실행 증거: `network/lab/runs/20260922T072454Z-hydra-0fed7e8a/`

분석은 `tshark`, `capinfos` CLI와 보존된 서버 로그·manifest를 사용했다. Wireshark GUI는
사용하지 않았다. 컨테이너 시각은 UTC, 호스트 보고 시각은 KST(UTC+09:00)로 구분한다.

## 2. 환경과 격리 조건

| 항목 | 확인값 |
| --- | --- |
| 실행 시각 | 2026-09-22 16:24:59~16:25:04 KST |
| 호스트 | Windows 11, WSL2 kernel 6.18.33.2 |
| Docker Desktop / Engine·CLI | 4.91.0 / 29.8.0, API 1.56 |
| 컨테이너 OS | Debian 12 bookworm |
| Hydra | 9.4 |
| OpenSSH / OpenSSL | 9.2p1 Debian-2+deb12u10 / 3.0.20 |
| tcpdump / libpcap | 4.99.3 / 1.10.3 |
| tshark / capinfos | 4.6.8 |
| 이미지 | `cloudshield-network-hydra-lab:local` |
| 이미지 ID | `sha256:a3292bb4b40bc105d0ad040dae798fafb621263e87fd0ded2d681172b66de7f9` |
| 대상 | `172.21.0.2:2222`, 인터페이스 `eth0` |
| 공격 클라이언트 | `172.21.0.3`, 동시성 1 |

러너가 소유한 `--internal` Docker bridge에서만 실행했으며 호스트 포트, 외부 서버,
privileged 모드, bind mount와 Docker 소켓 마운트를 사용하지 않았다. 실행 후 manifest의
`remaining_resources`는 빈 배열이고 CloudShield 라벨의 컨테이너와 네트워크가 남지 않았다.
재현용 이미지만 보존했으며 다른 Docker 프로젝트는 건드리지 않았다.

## 3. Hydra와 서버 인증 증거

| 지표 | 실측값 |
| --- | --- |
| 실행 ID | `cs-ssh-0e2ac094a4e64a4a859f8b09d4b3c4c0` |
| Hydra 시작·종료 | 16:25:00.685971~16:25:04.209992 KST |
| 합성 실패 후보 | 6개 |
| Hydra 작업 수 | 1 |
| Hydra 상태 / 종료 코드 | `exhausted_without_success` / 0 |
| SSH 성공 로그 | 0건 |
| SSH 실패 로그 | 7건 |
| 실패 로그의 클라이언트 포트 | 59420 6건, 59424 1건 |
| 로그 수집원 | sshd stderr |

후보 6개와 실패 로그 7건, TCP 스트림 3개는 서로 같은 단위가 아니다. Hydra는 준비·협상
연결 뒤 인증 연결을 만들었고, 스트림 1에서 `MaxAuthTries` 6회에 도달해 연결이 닫힌 후
스트림 2에서 실패 로그가 한 건 더 발생했다. SSH 페이로드는 암호화되어 있으며 원시 후보와
Hydra 복구 파일은 안전상 보존하지 않았으므로 각 후보를 개별 로그에 억지로 대응시키지 않는다.

보안 룰의 동일 IP·계정, 300초 내 5회 조건에는 수량과 시간 측면에서 부합한다. 그러나 이번
Docker 로그는 RFC3339 시각과 sshd stderr 조합이고 계약 파서가 요구하는
`host sshd[PID]:` syslog 접두어가 없다. 따라서 실제 탐지 파이프라인 성공으로 표시하지 않는다.

## 4. PCAP 무결성과 TCP 분석

| 항목 | 실측값 |
| --- | --- |
| 파일 | `network/lab/runs/20260922T072454Z-hydra-0fed7e8a/capture.pcap` |
| 크기 | 16,204 bytes |
| SHA-256 | `0b46b249ef082c0dbe404081c775d31e437f631d1fafae71a0ac533372e95e35` |
| 패킷 / TCP 스트림 | 78 / 3 |
| 캡처 구간 | 16:25:00.715897~16:25:04.183249 KST, 3.467352초 |
| SYN / SYN-ACK | 3 / 3 |
| FIN / RST | 6 / 0 |
| TCP 재전송 | 0 |
| 커널 드롭 | 0 (`78 captured`, `78 received by filter`) |
| tshark 읽기 | 성공, 종료 코드 0 |

스트림 0은 Hydra의 SSH 모듈 준비·협상 연결이며 서버 실패 로그가 없다. 스트림 1은 실패
6건과 `MaxAuthTries` 종료를 포함하고, 스트림 2는 실패 1건을 포함한다. 대표 스트림 1의
Seq/Ack는 tshark 상대값이다.

| 프레임 | 상대 시각(초) | 방향 | 플래그 | Seq | Ack |
| --- | --- | --- | --- | --- | --- |
| 23 | 0.270310 | `172.21.0.3:59420 → 172.21.0.2:2222` | SYN | 0 | 0 |
| 24 | 0.270358 | `172.21.0.2:2222 → 172.21.0.3:59420` | SYN, ACK | 0 | 1 |
| 25 | 0.270365 | client → server | ACK | 1 | 1 |
| 53 | 0.406042 | client → server | FIN, ACK | 1800 | 2038 |
| 54 | 0.406523 | server → client | FIN, ACK | 2038 | 1801 |
| 55 | 0.406531 | client → server | ACK | 1801 | 2039 |

RST와 재전송 없이 세 스트림 모두 정상 TCP 연결·종료 형태를 보였다. 공격성은 비정상 TCP
플래그보다 짧은 시간에 같은 출발지와 계정에서 반복된 SSH 인증 실패로 드러난다.

## 5. 정상 기준선 비교

정상 기준선은 기존 키 인증 단일 연결 PCAP
`network/lab/runs/20260916T033900Z-707fb648/capture.pcap`이다. 크기는 10,472 bytes,
SHA-256은 `2a63b868f1f3334eaafeb60601811101263daf2287fc1bc4a13d9c6cc3ace667`이다.

| 지표 | 정상 키 인증 | Hydra 실패 실험 |
| --- | ---: | ---: |
| TCP 스트림 | 1 | 3 |
| 패킷 | 39 | 78 |
| 캡처 시간 | 약 0.176초 | 3.467352초 |
| SYN / SYN-ACK | 1 / 1 | 3 / 3 |
| FIN | 2 | 6 |
| RST / 재전송 | 0 / 0 | 0 / 0 |
| 서버 실패 로그 | 0 | 7 |
| 드롭 | 원본 통계 미보존 | 0 |

Hydra 실험은 정상 기준선보다 스트림과 패킷이 늘고 인증 실패가 집중됐다. 두 캡처 모두
TCP 플래그 이상이나 재전송은 없으므로 탐지 근거는 반복 인증 실패 로그와 시간 창이어야 한다.

## 6. 첫 실행 실패와 러너 수정

첫 실측 `network/lab/runs/20260921T062044Z-hydra-c3549953/`은 78 packets, 서버 실패
7건, 성공 0건을 확보했지만 manifest가 exit 1이었다. 캡처 프로세스는 33초 제한인데 러너가
Hydra 종료 후 10초만 기다려 정상 캡처를 timeout으로 오판한 것이 원인이었다.

대기 상한을 `실험 seconds + 6초`로 바꾸고 단위 테스트에서 전달값을 검증했다. 수정 후 같은
격리 조건으로 재실행해 manifest exit 0, 캡처 제한 종료 코드 124, 증거 보존과 리소스 정리
성공을 확인했다. 캡처의 124는 유한한 `timeout`이 관측 구간을 끝낸 값이며 실험 실패가 아니다.

## 7. 검증 범위와 남은 연계

- `pwsh .\scripts\check.ps1`의 역할 경계, 테스트 경로, Ruff lint·format과 pytest를 통과했다.
  결과는 **278 passed, 1 warning**이며 경고는 기존 소켓 차단 검증에서 발생했다.
- 네트워크 단위 테스트는 입력 상한, dry-run, 소유 리소스 검증, 캡처 준비, 종료·정리와 실제
  로그 판정을 검증한다.
- 실제 CloudWatch 수집, 계약 파싱, Lambda 탐지, SG/WAF/IAM 차단과 Slack 전파는 수행하지 않았다.
- 수집 담당과 syslog 접두어 형식을 맞춘 뒤 보안 담당이 동일 IP·계정 5회/300초 룰을 통합
  환경에서 검증해야 한다.
- 실험 증거와 manifest는 보존했고 합성 비밀번호 후보·Hydra 복구 파일은 정리했다.
- 재현용 Docker 이미지는 후속 반복 실험을 위해 남겼다. 제거 시 정확한 이미지 ID를 사용한다.
