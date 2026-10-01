# Password Spraying 재현

- Notion Task: https://notion.so/3eb04d37c22580cbb9b3c3936841c711
- GitHub Issue: https://github.com/mmmphyun/aleph-project/issues/115

## 확인된 요구사항과 구현 범위

2026-09-30 노션 티켓을 읽기 전용 조회했다. 상태는 시작 전이었고 본문은 안내용
템플릿뿐이었다. 세부 구현 요구사항은 사용자 요청과 아래 기존 코드 확인을 근거로 정했다.

| 기존 구현에서 확인한 사실 | 이번 구현에서 선택한 범위 |
| --- | --- |
| Hydra 러너는 소유한 로컬 Docker internal bridge의 서버만 허용한다 | 동일 소유권 검사, 캡처, 정리 및 기본 dry-run 재사용 |
| 기존 SSH 실험은 hydralab 한 계정에 여러 일회성 오답을 시도한다 | 여러 합성 계정에 같은 일회성 오답 하나를 목록 순서대로 한 번씩 시도 |
| 서버는 hydralab만 허용하며 공통 파서는 invalid user 실패를 지원한다 | 서버 설정을 확장하지 않고 spraylab1~spraylab10 미존재 계정 사용 |
| 탐지 조건은 rules.py와 auth_window.py에 이미 정의되어 있다 | 아래 조건을 문서로 연결하고 탐지·매퍼·공통 계약은 수정하지 않음 |

## 원리와 탐지 연결

| 구분 | 기존 SSH 무차별 대입 | Password Spraying |
| --- | --- | --- |
| 계정/후보 관계 | 한 계정 × 여러 후보 | 여러 계정 × 동일 후보 하나 |
| 실행 방식 | Hydra 한 번, 후보 1~10개 | 계정별 Hydra 한 번, 순차 실행, 재시도·추가 라운드 없음 |
| 읽기 확인한 탐지 조건 | 동일 IP·계정, 300초 내 5회 실패 | 동일 IP, 300초 내 고유 계정 2개 이상 실패 |
| 현재 매퍼 출력 | SSH_BRUTE_FORCE / T1110.001 / HIGH / BLOCK_AND_QUARANTINE | SSH_PASSWORD_SPRAYING / T1110.003 / MEDIUM / BLOCK_IP_ONLY |

근거는 `src/detection/rules.py`, `src/remediation/auth_window.py`,
`src/detection/incident_mapper.py`, `src/contracts/events.py`, `src/contracts/incident.py`의
읽기 전용 확인이다. 두 룰이 동시에 성립하면 기존 룰 엔진은 무차별 대입을 우선한다.
도구의 계정 수·간격·실행 한도는 실험 자원 제한이며 보안 정책이나 탐지 임계치가 아니다.

운영 연결 경로는 SSH 실패 → CW Agent → CloudWatch → Lambda/누적 윈도우 →
IncidentReport → 대응 엔진 → Slack이다. 현재 `BLOCK_IP_ONLY` 구현은 WAF IPSet을
사용하므로 SSH L4 차단 성공을 의미하지 않는다. 정책 정렬은 보안·플랫폼 담당 영역이다.

Docker `sshd -e` 원문과 Docker 타임스탬프에는 공통 파서가 요구하는 syslog의
호스트·`sshd[PID]:` 접두어가 모두 갖춰지지 않을 수 있다. 원문을 임의 변환하지 않는다.
이번 구현은 로그 수집 배포, 배치 간 전달, 클라우드 차단, Slack 및 10초 SLA의
E2E 성공을 증명하지 않는다. 실제 계정의 잠금 정책 검증도 범위 밖이다.

## 사용법

PowerShell에서 기본 계획을 확인한다. 아래 호출은 Docker나 Hydra를 실행하지 않는다.

```powershell
uv run python network/lab/hydra_lab.py --mode password-spraying
uv run python network/lab/hydra_lab.py run --mode password-spraying --accounts spraylab3 spraylab1 spraylab2 --interval 2 --max-attempts 3 --seconds 30
```

Bash에서는 전용 진입점을 사용할 수 있다. 기존 `hydra_ssh_lab.sh`에도
`--mode password-spraying`을 전달할 수 있다.

```bash
bash network/password_spraying.sh plan --accounts spraylab3 spraylab1 spraylab2 --interval 2 --max-attempts 3
```

실제 격리 실험이 별도로 필요한 경우 먼저 기존 Hydra 이미지를 **재빌드**해야 한다.
이미지에 worker 소스가 복사되므로 기존 빌드에는 새 모드가 없다.

```powershell
uv run python network/lab/hydra_lab.py build
uv run python network/lab/hydra_lab.py run --execute --mode password-spraying --target owned-docker --accounts spraylab3 spraylab1 spraylab2 --interval 2 --max-attempts 3 --seconds 30
```

이번 작업에서는 위 빌드/실행을 수행하지 않았다. 기존 [Hydra 실험 문서](hydra-ssh-lab.md)의
Docker 준비, PCAP 보존, 소유 리소스 정리 절차를 따른다. SSH 서버 설정과 이미지를
운영 서버에 배포하는 기능은 없다.

## 입력과 종료 제약

| 옵션 | 기본값과 검증 |
| --- | --- |
| `--target` | owned-docker만 허용. IP/호스트 입력 거부, 실제 IP는 소유 컨테이너 inspect로 결정 |
| `--accounts` | spraylab1 spraylab2. spraylab1~spraylab10 중 고유 계정 2~10개, 순서 보존 |
| `--interval` | 1초. 1~10 정수 초, 이전 호출 완료와 다음 호출 사이의 최소 간격 |
| `--max-attempts` | 10회. 2~10 정수, 계정 목록 길이 이상이어야 함. 초과 목록을 잘라 실행하지 않고 거부 |
| `--seconds` | 30초. 기존 3~55초, 전체 시도와 간격에 공통 deadline 적용 |
| `--tasks` / `--port` | 기존 1 / 2222 고정 |
| `--candidates` | 스프레이에서 지정 불가, 계정당 후보 하나 고정 |

필수 간격 합 `(계정 수 - 1) × 간격`이 전체 시간 이상이면 사전 거부한다.
네트워크 지연으로 모든 계정을 완료하지 못하면 시간 초과이며, 기한 내 완료를 보장하지 않는다.
외부 timeout과 종료 유예도 기존 제한을 재사용한다. 다음 간격을 확보할 시간이 없으면
후속 계정을 호출하지 않고 timeout으로 종료한다.

비정상 종료 코드, 연결 오류, 예상치 못한 인증 성공, 결과 미확인, 중단, 시간 초과는
후속 계정 실행을 중지한다. wrapper는 `set -euo pipefail`과 `exec`로 오류를 반환한다.
worker 정상 코드만으로 재현 성공을 판정하지 않으며 요청한 모든 계정의 실패가 동일
클라이언트 IP의 서버 원문 로그에 있어야 한다. 누락되면 원문 증거를 보존하고 실패한다.

## 자격증명과 증거

사용자로부터 비밀번호나 실제 자격증명을 받지 않는다. `WRONG-` 접두어 난수를 실행마다
하나 생성해 모든 계정에 재사용한다. Hydra에는 평문 `-p` 대신 기존 private tmpfs의
0600 후보 파일을 `-P`로 전달한다. argv, 환경변수, manifest에 비밀번호를 저장하지 않는다.
계정별 호출은 `-t 1 -f -K -I`를 유지해 병렬도·자동 재시도·복구 실행을 제한한다.

원문 출력과 복구 파일은 각 호출의 0700 임시 디렉터리에만 저장하고 정상·오류·중단 시
삭제한다. 프로세스 강제 종료나 엔진 장애 때의 한계와 수동 복구는 기존 문서를 따른다.
manifest에는 비밀 없는 실행 계획, 계정별 결과와 시각, 서버에서 확인한 계정/실패 수,
캡처 지표와 정리 결과를 기록한다. worker 자체가 시작 실패/강제 종료되면 계정별 결과는
부분 누락될 수 있으므로 최종 성공으로 해석하지 않는다.

## 검증

`tests/unit/test_network.py`에서 외부 명령을 모의화해 계정 순서, 동일 후보 사용,
간격, 단일 라운드와 실행 한도, 잘못된 입력, 부분 실패, 예상치 못한 성공, 전체 기한,
private 파일 정리, 서버 계정별 증거 요구를 검증한다. 실제 Hydra/SSH/Docker로 폴백하지 않는다.
공통 품질 게이트는 `powershell .\scripts\check.ps1`이다. 모의 검증은 실제 SSH 모듈의
동작 및 운영 탐지·차단 성공에 대한 실측 증거를 대신하지 않는다.
