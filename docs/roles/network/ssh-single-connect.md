# SSH 단일 연결 시도와 로컬 모의 검증

- Notion Task: https://notion.so/3d404d37c225815aa07ec2877ea6f060
- GitHub Issue: https://github.com/mmmphyun/aleph-project/issues/29
- 브랜치: `feat/network-ssh-single-connect`
- 실제 SSH 서버 연결 검증: **미수행 — 서버 미준비**

## 실행 계약

`network/ssh_single_connect.sh`는 IPv4 대상에 SSH 프로세스를 한 번 실행한다.
기존 `attack_simulation.sh`는 Hydra/Nmap 안내 스켈레톤이므로 수정하지 않았다.

```bash
bash network/ssh_single_connect.sh <IPv4> <사용자> [포트] [연결제한초]
```

| 입력 | 허용 범위 |
| --- | --- |
| 주소 | IPv4 4개 옥텟, 각각 0~255, 선행 0 금지; DNS/IPv6 미지원 |
| 사용자 | 영문/밑줄로 시작, 영숫자/밑줄/하이픈, 1~32자 |
| 포트 | 1~65535, 기본 22, 선행 0 금지 |
| 연결 제한 | 1~120초, 기본 5초, 선행 0 금지 |

명시적으로 빈 값을 전달하면 오류로 처리한다. 잘못된 입력은 SSH 호출 전에 종료 코드 2를
반환하고, 유효한 입력에서는 `exec`를 통해 SSH 종료 코드를 그대로 전달한다.
`set -euo pipefail`을 적용하며 반복 실행, 비밀번호 저장, Hydra 호출은 없다.

`-F /dev/null`은 개인 및 시스템 SSH 설정에 따른 프록시/연결 공유 등 변수를 배제한다.
`StrictHostKeyChecking=yes`를 사용하므로 신뢰할 수 있는 경로로 확인한 서버 키가
known_hosts에 사전 등록되어 있어야 한다. 미등록/변경된 키를 자동 승인하지 않는다.
`BatchMode=yes`와 `NumberOfPasswordPrompts=0`으로 비밀번호 입력을 요구하지 않으며,
OpenSSH 기본 키/에이전트 기반 인증이 준비되어 있어야 한다.
하나의 연결 내에서 OpenSSH가 여러 키를 제시할 수 있으므로 단일 인증 패킷을 뜻하지 않는다.
스크립트의 반복 인증 시도는 없다. 인증 성공 시 원격 `true`만 실행하고 종료한다.

`ConnectionAttempts=1`로 연결 재시도 횟수를 제한한다. `ConnectTimeout`은 TCP 연결 및
초기 SSH 핸드셰이크 대기 제한이며 DNS/전체 인증/원격 명령을 포함한 총 실행 제한이 아니다.
실제 실행 시 서버 접속 및 인증 로그가 발생할 수 있다.

## 로컬 모의 테스트

2026-09-09 Windows 환경에서 Git Bash 5.3.15 실행을 확인했다.
`tests/unit/test_network.py`는 임시 디렉터리의 가짜 `ssh`만 PATH에 넣는다.
실제 SSH로 폴백하지 않으며 외부 네트워크 연결 없이 인자를 기록하고 지정된 코드로 종료한다.
Bash가 없으면 테스트를 건너뛰지 않고 실패로 보고한다.

- 0, 1, 42, 255 종료 코드 전달 및 호출 횟수 1회 검증
- 기본/사용자 지정 포트와 연결 제한 및 경계값 검증
- 잘못된 IPv4, 사용자, 포트, 연결 제한, 인자 개수에서 SSH 호출 0회 검증
- 호스트 키 검증, 비대화형 실행, 연결 1회 제한 옵션 검증
- Bash 구문 검사

`powershell .\scripts\check.ps1` 실행 결과(우회 플래그 없음):

| 단계 | 결과 |
| --- | --- |
| 테스트 파일 표준 경로 검사 | 통과 |
| Ruff lint | All checks passed |
| Ruff format | 57개 파일 포맷 검사 통과 |
| pytest | 78 passed, 4 skipped, 1 warning; 네트워크 37개 전부 통과 |

4개 skip은 기존 타 직무 테스트이며 네트워크 테스트의 skip은 없다.
경고 1개는 기존 소켓 차단 smoke 테스트의 `getaddrinfo` 차단 경고다.

## 실제 환경에서 남은 검증

실제 TCP/SSH 연결 성공, 서버 키 검증 동작, 키 인증 성공/실패, 실제 타임아웃 경과 시간,
서버 인증 로그 및 패킷 캡처는 모두 미검증이다. 모의 테스트 통과를 실제 접속 성공이나
탐지·차단 파이프라인 성공의 증거로 사용하지 않는다.
Wireshark 초안 및 Issue #28은 별도 보류 작업으로 유지한다.
