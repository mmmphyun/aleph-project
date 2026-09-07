# CloudShield 테스트베드 모의 데이터 명세 및 공식 표준 검증서

> **최종 검증일**: 2026-09-04  
> **관리 책임**: 클라우드 A (플랫폼 & 데이터 계약)  
> **검증 대상**: `tests/mock_data/` 내 모의 데이터 7종

---

## 1. 개요 및 설계 원칙

본 문서는 CloudShield 파이프라인의 모의 데이터(Mock Data)가 실제 클라우드 및 OS 서비스 런타임 규격과 일치함을 입증하기 위해 작성된 기술 명세서입니다.  
모든 모의 데이터는 공식 RFC 표준, 클라우드 벤더(AWS) 공식 아키텍처 가이드라인, 그리고 글로벌 위협 프레임워크(MITRE ATT&CK)를 기반으로 작성 및 검증되었습니다.

---

## 2. 모의 데이터별 공식 표준 및 서비스 기준 검증 내역

### 2.1 Linux OS 인증 로그 (`mock_auth.log`, `mock_auth_noisy.log`)

* **기준 서비스**: Ubuntu 22.04 LTS / 24.04 LTS OpenSSH Daemon (`sshd`), `systemd-journald`, `rsyslog`
* **공식 표준 근거**:
  1. **IETF RFC 3164 (The BSD Syslog Protocol)**: `<Mmm> <dd> <hh:mm:ss> <hostname> <tag>: <content>` 포맷 준수.
  2. **IETF RFC 5424 (The Syslog Protocol)**: ISO 8601 고정밀도 타임스탬프(`YYYY-MM-DDTHH:MM:SS.ffffff+00:00`) 준수.
  3. **OpenSSH Portable Source Code (`auth-passwd.c`, `auth2.c`)**:
     - 인증 실패(일반 계정): `Failed password for <user> from <ip> port <port> ssh2`
     - 인증 실패(미존재 계정): `Failed password for invalid user <user> from <ip> port <port> ssh2`
     - 공개키 정상 인증: `Accepted publickey for <user> from <ip> port <port> ssh2: RSA SHA256:...`
     - 인증 전 연결 종료: `Connection closed by authenticating user <user> <ip> port <port> [preauth]`
* **검증 내용**:
  - `mock_auth.log`: RFC 3164 기반 골든 패스 데이터 (단일 IP 5회 연속 실패).
  - `mock_auth_noisy.log`: ISO 8601 + RFC 3164 혼재, 정상 로그인, `sudo` 명령어 실행, 미등록 계정 침투 시도, 사용자 정상 세션 종료 등 실제 운영 환경의 노이즈 로그를 반영하여 룰 엔진의 필터링 견고성 검증.

---

### 2.2 AWS CloudWatch Logs 구독 필터 페이로드 (`mock_cw_event.json`, `mock_cw_batch_event.json`)

* **기준 서비스**: Amazon CloudWatch Logs Subscription Filter $\rightarrow$ AWS Lambda 런타임
* **공식 표준 근거**:
  - **AWS 공식 개발자 안내서 ("Using CloudWatch Logs subscription filters with AWS Lambda")**:
    - Lambda에 인입되는 이벤트는 최상위 객체 `{"awslogs": {"data": "<base64_gzip_string>"}}` 구조를 가짐.
    - Base64 디코딩 및 Gzip 압축 해제 후 JSON 구조:
      ```json
      {
        "messageType": "DATA_MESSAGE",
        "owner": "123456789012",
        "logGroup": "/cloudshield/target/auth-log",
        "logStream": "i-0abcd1234ef567890",
        "subscriptionFilters": ["CloudShield-FailedPassword-Filter"],
        "logEvents": [
          {
            "id": "...",
            "timestamp": 1725344405000,
            "message": "..."
          }
        ]
      }
      ```
    - `timestamp`: Epoch 밀리초(13자리 정수).
* **검증 내용**:
  - `mock_cw_event.json`: 1개 로그 이벤트가 포함된 기본 단일 이벤트 페이로드.
  - `mock_cw_batch_event.json`: CloudWatch 에이전트의 1초/1MB 버퍼링 정책에 따라 5건 이상의 로그가 한 번에 묶여 전달되는 다건 배치 런타임 페이로드 재현.
  - 파이썬 `gzip` 및 `base64` 라이브러리를 통해 압축 해제 및 역직렬화 무결성(Roundtrip) 100% 검증.

---

### 2.3 침해사고 분석 보고서 (`mock_incident*.json`)

* **기준 서비스**: CloudShield Pydantic V2 Contract, AWS WAFv2, AWS EC2, MITRE ATT&CK
* **공식 표준 근거**:
  1. **MITRE ATT&CK Enterprise Matrix**:
     - `T1110.001`: Brute Force (Password Guessing) - 단일 계정 대상 무차별 대입.
     - `T1110.003`: Brute Force (Password Spraying) - 다수 계정 대상 동일/유사 암호 대입.
     - `T1046`: Network Service Discovery - 외부 포트 스캐닝 및 서비스 정찰.
  2. **AWS WAFv2 API Reference (`UpdateIPSet`)**:
     - 단일 IPv4 주소 차단 시 반드시 CIDR `/32` 표기(`198.51.100.50/32`)를 요구함.
  3. **AWS EC2 API Reference (`ModifyInstanceAttribute`)**:
     - 인스턴스 격리 시 기존 Security Group 목록을 단일 격리 보안 그룹(`Quarantine SG`)으로 원자적 교체.
  4. **Pydantic V2 Strict Validation**:
     - IPv4 `ipaddress` 표준 모듈 검증 및 EC2 인스턴스 ID 정규식(`^i-[0-9a-f]{8,17}$`) 검증 강제.
* **데이터셋 구성**:
  - `mock_incident.json`: T1110.001 / HIGH / `BLOCK_AND_QUARANTINE` (골든 패스)
  - `mock_incident_spray.json`: T1110.003 / HIGH / `BLOCK_AND_QUARANTINE` (다중 계정 대입)
  - `mock_incident_waf_only.json`: T1110.001 / MEDIUM / `BLOCK_WAF` (웹 단독 차단)
  - `mock_incident_alert_only.json`: T1046 / LOW / `ALERT_ONLY` (단순 정찰 상황 전파)

---

## 3. 직무별 활용 가이드

| 직무 | 활용 파일 | 테스트 목적 |
| :--- | :--- | :--- |
| **네트워크** | `mock_auth_noisy.log` | 모의 공격 스크립트 실행 후 타깃 서버의 실제 로그 라인과 일치 여부 비교 |
| **보안** | `mock_auth_noisy.log`, `mock_incident*.json` | 룰 엔진의 노이즈 필터링 능력 검증 및 LLM Few-shot 프롬프트 출력 정합성 검증 |
| **클라우드 B** | `mock_cw_batch_event.json`, `mock_incident*.json` | CW 압축 해제기(`cw_processor.py`)의 다건 배치 처리 및 Slack 알림 카드 렌더링 검증 |
| **클라우드 A** | `mock_incident*.json`, `mock_cw_batch_event.json` | Lambda 오케스트레이터 및 WAF/EC2 다중 계층 차단 엔진(`remediation.py`) 분기 검증 |
