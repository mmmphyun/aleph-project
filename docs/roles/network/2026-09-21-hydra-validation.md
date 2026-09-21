# Hydra 실험 준비 검증 및 Docker 엔진 차단 기록

## 1. 상태와 추적 관계

**구현·모의 검증 완료, 실제 Hydra 실험 미실행.** 새 실패 로그나 PCAP을 확보하지 못했으며,
인증 실패 재현·탐지·차단 성공으로 표시하지 않는다.

- Notion: https://notion.so/3d404d37c225819b9e05fc015bc4df3d
- Issue: https://github.com/mmmphyun/aleph-project/issues/67
- 브랜치: `feat/network-hydra-isolated-lab`
- 실행 가이드: [hydra-ssh-lab.md](hydra-ssh-lab.md)

착수 시 네트워크 열린 PR은 없었고, `main`을 `git pull --ff-only origin main`으로 확인했다.
노션 카드는 `시작 전`, 본문 블록 0개였으며 활성 연결 이슈가 없어 새 이슈를 발행했다.
보관 PR 15는 CLOSED, 연결 이슈 미지정이며 브랜치 `feat/network-ssh-bruteforce`의
`d29080a5a0eb2c978ed290ddf90753bf02c45ba3`을 수정·삭제·재사용하지 않았다.
선행 PR 30·35·56·59는 원격 MERGED 상태다. 정상 기준선 머지 커밋은
`498f0bb2e46d92af3c23e6e1e4172a9c42a8f9bb`와 일치한다.

`notion_sync.yml`은 PR 본문의 모든 `#숫자`를 머지 시 이슈 종료 대상으로 해석한다.
따라서 PR에는 이번 이슈만 그 형식으로 적고 과거 작업은 URL로 연결한다.
노션 속성은 에이전트가 직접 수정하지 않는다.

## 2. 환경과 실제 실행 차단 근거

| 항목 | 확인값 |
| --- | --- |
| 확인일 | 2026-09-21, 호스트 Asia/Seoul, UTC+09:00 |
| 호스트 | Windows 11 / Python platform: Windows-11-10.0.26200-SP0 |
| Docker Desktop | 4.91.0, 사용자별 설치 |
| Docker CLI | 29.8.0 / API 1.56 / windows amd64 |
| 실행 파일 | `C:\Users\User\AppData\Local\Programs\DockerDesktop\resources\bin\docker.exe` |
| context | desktop-linux, 로컬 named pipe |
| tshark / capinfos | Wireshark 4.6.8 |
| Python / pytest | 3.12.14 / 8.4.2 |
| 이번 이미지 ID·Hydra·sshd·tcpdump 버전 | 이미지 미빌드, 확인 불가 |
| 이번 대상 IP·인터페이스·실제 필터 | 컨테이너 미생성, 미확정 |

설치 경로를 찾아 Docker Desktop 시작을 시도했다. 백엔드 로그의
2026-09-21T05:10:42Z(14:10:42 KST) 오류는 다음과 같다.

```text
starting services: initializing Ingest server
sailor-ingest.sock -> sailor-ingest.sock.stale
The file cannot be accessed by the system.
```

백엔드가 시작 실패 후 종료되었으며 엔진 named pipe가 존재하지 않았다.
초기화·재설치·소켓 파일 삭제·시스템 설정 변경·재부팅은 수행하지 않았다.
Docker Desktop 복구는 별도 승인 범위로 남긴다.

현재 러너로 명시적 `run --execute` 사전 점검을 수행한 시각은
2026-09-21T05:12:57Z~05:12:58.565010Z(14:12:57~14:12:58 KST)이다.
`docker info` 단계에서 중단했고 manifest의 exit는 1이다. Hydra 시작·종료 시각과 종료 코드는
**없음**이다. 후보 생성·서버 인증·캡처를 실행하기 전 단계에서 막혔다.

로컬 진단 증거:

- `C:\Aleph\network\lab\runs\20260921T051257Z-hydra-9706e4fd\manifest.json`
- Docker 원본 진단: `C:\Users\User\AppData\Local\Docker\log\host\com.docker.backend.exe.log`

새 PCAP 위치·크기·SHA-256·읽기 결과·패킷 수·드롭 통계·서버 실패 수는 모두 **미측정**이다.
이를 0으로 표기하지 않는다. 실행 가이드의 자동 보존 경로는 실제 실험 성공 증거가 아니다.

## 3. 기존 정상 기준선 재확인과 비교

기존 PCAP을 capinfos와 tshark CLI로 다시 읽었다. 새 Hydra 증거로 재사용하지 않는다.
Wireshark GUI 확인은 이번에도 미수행이다.

| 지표 | 기존 정상 단일 연결 | 이번 Hydra 시나리오 |
| --- | --- | --- |
| 실제 수행 | 2026-09-16 키 인증 연결 | 엔진 사전 점검 실패, 미실행 |
| 계정 / 후보 | lab / 키 인증 | 계획 hydralab / 합성 실패 후보 6개 |
| TCP 스트림 | 1개 | 미측정 |
| 인증 실패 수 | 기준선 실패 시나리오 아님 | 미측정 |
| 패킷 수 / 파일 크기 | 39 / 10,472 bytes | 미측정 |
| SYN / SYN-ACK | 각각 1개 | 미측정 |
| FIN | 양방향 FIN | 미측정 |
| RST / 재전송 | 0 / 0 | 미측정 |
| 드롭 | 원본 종료 통계 미확보, 알 수 없음 | 미측정 |
| 탐지·차단 | 검증 범위 밖 | 미실행 |

기준선 원본:
`C:\Aleph\network\lab\runs\20260916T033900Z-707fb648\capture.pcap`

SHA-256: `2a63b868f1f3334eaafeb60601811101263daf2287fc1bc4a13d9c6cc3ace667`

다음 표는 **기존 정상 PCAP의 재확인값**이다. Hydra 스트림 표는 새 PCAP 확보 전에는 작성할 수 없다.
4-tuple은 `172.18.0.3:53320 ↔ 172.18.0.2:2222`이며 Seq/Ack는 tshark 상대값이다.

| 프레임 | 상대 시각(초) | 방향 | 플래그 | Seq | Ack |
| --- | --- | --- | --- | --- | --- |
| 1 | 0.000000 | client → server | SYN | 0 | 0 |
| 2 | 0.000023 | server → client | SYN, ACK | 0 | 1 |
| 3 | 0.000030 | client → server | ACK | 1 | 1 |
| 36 | 0.175410 | client → server | FIN, ACK | 3674 | 3562 |
| 38 | 0.176054 | server → client | FIN, ACK | 3562 | 3675 |

재분석 시 tshark는 기존 SSH post-quantum KEX의 개인키 복호화 미지원 경고를 출력했다.
TCP 프레임 판독 실패는 아니며 SSH 인증 내용을 복호화했다는 의미도 아니다.
기존 실측의 캡처 종료 감시 문제와 이후 loopback 검증 이력은 원래 보고서에 보존한다.
수정된 캡처의 실제 시작·종료·보존·정리 전 구간을 이번 Hydra 환경에서 재검증하는 일은 남아 있다.

## 4. 모의 검증과 회귀

입력 상한, dry-run, 안전한 argv, 정확한 대상 소유권·내부 네트워크·포트 검증,
도구/SSH 모듈 부재, timeout·중단·예상 밖 성공·연결 오류 분류,
후보·복구 파일 정리, 캡처 준비 전 공격 금지, 서버 로그와 종료 코드의 독립 판정을 모의 검증했다.
기존 SSH·tcpdump 모의 테스트를 유지했다. 실제 Docker·이미지 다운로드·네트워크 실행은
기본 pytest에 포함하지 않는다.

최종 `powershell .\scripts\check.ps1` 결과는 역할 범위·테스트 경로·Ruff lint·format 모두 통과,
pytest **278 passed, 0 skipped, 1 warning**이다. Hydra 신규 모의 검증 46개를 포함한다.
기존 `test_network_socket_is_blocked_by_default`의 pytest-socket 경고 1건은 의도된 차단 검증에서
발생하며 새 Hydra 경고와 구분한다. 새 셸 파일 두 개의 `bash -n`도 통과했다.
PowerShell 5의 기존 한글 배너는 인코딩이 깨져 출력됐지만 각 단계 결과는 별도로 확인했다.

## 5. 남은 검증·협의·정리

- Docker 엔진 복구 후 이미지 빌드와 1회 제한 실험, 버전·IP·필터·실행 시각 확보.
- 실제 실패 로그 수와 후보·TCP 연결 수 비교, 스트림별 SYN/ACK/FIN/RST·재전송 분석.
- 드롭 통계와 PCAP 보존·컨테이너 정리 전 구간 검증. 예상치 못한 성공은 즉시 중단·원인 기록.
- 보안 담당 조건은 동일 IP·계정 300초 내 실패 5회. 현재 실제 실패 횟수는 확인되지 않았다.
- stderr 로그와 계약 파서의 syslog 접두어 차이는 수집 담당과 협의한다. 배치 간 누적도 별도 범위다.
- 전체 탐지·차단 및 외부 클라우드 성능은 미검증이다.

이번 실행은 컨테이너·네트워크·이미지·비밀번호 후보·Hydra 복구 파일을 생성하지 않았다.
manifest의 `remaining_resources`는 빈 배열이며 진단 폴더만 보존한다.
엔진이 내려가 있어 기존 Docker 전체 리소스의 현재 목록은 조회하지 못했다.
Docker Desktop 앱은 시작 오류 화면 상태일 수 있으며 사용자 설정이나 기존 이미지를 삭제하지 않았다.
기존 미추적 회의록은 수정·스테이징하지 않는다.
