# 타깃 EC2 리눅스 환경 구성 및 로그 파이프라인 수집 경로 검증

- **작성일**: 2026-09-09
- **작성자**: 클라우드 B 담당자
- **관련 파일**: `init_target_server.sh`, `nginx.conf`
- **목표**: Ubuntu Linux 인스턴스에 Nginx 웹 서버 및 SSH 데몬을 구성하고, 모의 공격(SSH Brute Force / Web L7 Scanning) 수용 및 CloudWatch Agent 실시간 수집 대상 로그 파일 경로 검증.

---

## 1. 개요 및 설계 원리

CloudShield의 침해 탐지 파이프라인이 정상 작동하기 위해서는 타깃 인스턴스에서 발생하는 보안 이벤트 로그가 유실 없이 실시간으로 생성되고 유지되어야 합니다.

1. **SSH 인증 로그 (`/var/log/auth.log`)**:
   - OpenSSH 데몬의 `LogLevel`을 `VERBOSE`로 설정하고 `PasswordAuthentication yes`를 적용하여, Hydra 등의 도구로 무차별 대입 공격 시도 시 실패한 사용자명, 출발지 IP, 포트 정보가 상세히 기록되도록 구성합니다.
   - Ubuntu 24.04/22.04 LTS에서 `rsyslog` 서비스를 활성화하여 systemd-journal 로그가 `/var/log/auth.log` 파일로 안정적으로 적재되도록 보장합니다.
2. **Nginx 웹 접근 로그 (`/var/log/nginx/access.log`)**:
   - 커스텀 로깅 포맷 `cloudshield_combined`를 정의하여, 표준 HTTP 요청 정보 외에 인시던트 분석에 필수적인 `$request_time` 및 `$http_x_forwarded_for` 헤더를 포함합니다.
   - 모의 L7 침해 시나리오 실증을 위한 엔드포인트(`/health`, `/admin`, `/api/v1/auth/login`)를 제공합니다.

---

## 2. 수집 대상 로그 및 포트 매트릭스

| 서비스 | 리스닝 포트 | 대상 로그 경로 | 발생 이벤트 유형 | 연계 침해 시나리오 |
| :--- | :---: | :--- | :--- | :--- |
| **OpenSSH** | `TCP 22` | `/var/log/auth.log` | `Failed password for ... from <IP>` | [시나리오 1] SSH Brute Force (L4) |
| **Nginx** | `TCP 80` | `/var/log/nginx/access.log` | `401 Unauthorized`, `404 Not Found` | [시나리오 2] Web L7 Scanning & Spraying |
| **Nginx (Error)** | - | `/var/log/nginx/error.log` | 비정상 요청 및 버퍼 오버플로우 에러 | 모의 공격 비정상 패턴 분석 |

---

## 3. 초기화 스크립트 실행 및 검증 절차

### 3.1 스크립트 실행
```bash
chmod +x init_target_server.sh
sudo ./init_target_server.sh
```

### 3.2 포트 및 프로세스 상태 점검
```bash
# 1. 활성화된 리스닝 포트 확인 (22, 80)
ss -tlpn | grep -E ':(22|80)\s'

# 2. Nginx 서비스 상태 및 헬스체크 응답 확인
curl -i http://127.0.0.1/health

# 3. 로그 파일 권한 확인
ls -l /var/log/auth.log /var/log/nginx/access.log
```

---

## 4. 후속 단계 연계 (Step 2 Preview)

- 본 단계에서 검증된 `/var/log/auth.log` 및 `/var/log/nginx/access.log`는 **2단계: CloudWatch Unified Agent** (`amazon-cloudwatch-agent.json`)의 수집 리스트(`collect_list`)에 등록되어 AWS CloudWatch Logs 그룹(`/cloudshield/target/auth-log`, `/cloudshield/target/nginx-access-log`)으로 실시간 스트리밍됩니다.
