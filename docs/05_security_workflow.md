# [직무 가이드 4] 보안 담당 — 작업 상세 흐름도

## 1. 개요 및 역할 정의
보안 담당은 인입된 로그 데이터에서 1차 이상징후를 판별하는 결정론적 룰(정규식/임계치)을 정의하고, 이를 글로벌 보안 프레임워크인 MITRE ATT&CK과 매핑하여 10초 관통 대응을 위한 표준 `IncidentReport` 계약 객체로 승격한다. 또한 실시간 차단 완료 후 사후 심층 분석을 위해 비동기 LLM 구조화 출력 파이프라인을 연계한다.

---

## 2. 세부 작업 단계 (Step-by-Step)

```mermaid
flowchart TD
    S1[1단계: 탐지 룰 정의 및 정규식 모듈화] --> S2[2단계: MITRE ATT&CK 기법 매핑]
    S2 --> S3[3단계: 실시간 룰 승격기 개발 (incident_mapper)]
    S3 --> S4[4단계: 사후 비동기 LLM 심층 분석기 연계]
    S4 --> S5[5단계: 오탐/정탐 검증 및 ReDoS 안전성 튜닝]
```

### 1단계: 탐지 룰 정의 및 정규식 모듈화
- **내용**:
  - 이미 검증된 브라우저용 로직을 순수 Python 모듈(`rules.py`)로 이식.
  - **룰 1: 단일 계정 무차별 대입 공격** (동일 IP에서 동일 계정 대상 실패 5회 이상).
  - **룰 2: 다중 계정 패스워드 스프레잉** (동일 IP에서 2개 이상의 서로 다른 계정 실패).
  - **룰 3: 비인가 권한 접근** (DENIED, UNAUTHORIZED 키워드 3회 이상).
- **산출물**:
  - 룰 기반 1차 탐지 함수(`src/detection/rules.py`).

### 2단계: MITRE ATT&CK 기법 매핑
- **내용**:
  - 각 탐지 룰을 글로벌 엔터프라이즈 보안 매트릭스에 1:1로 매핑하여 보고서의 객관성 확보.
    - SSH 패스워드 대입 $\rightarrow$ **T1110.001 (Brute Force: Password Guessing)**
    - 다중 계정 찔러보기 $\rightarrow$ **T1110.003 (Brute Force: Password Spraying)**
    - Nmap 포트 스캔 $\rightarrow$ **T1046 (Network Service Discovery)**
- **산출물**:
  - 위협 매핑 테이블 명세서 및 탐지 메타데이터.

### 3단계: 실시간 룰 승격기 개발 (incident_mapper)
- **내용**:
  - 10초 실시간 관통 대응(Critical Path)의 SLA를 충족하기 위해 외부 LLM API 동기 호출을 배제하고 결정론적 매핑(Rule Promotion) 구현.
  - 원문 Syslog를 파싱하여 출발지 IP, 피해 대상 계정, 타깃 EC2 식별자를 추출하고 공통 데이터 계약(`src/contracts/incident.py`의 `IncidentReport`) 객체로 변환.
  - 비탐지 또는 정상 로그 유입 시 `ValueError`를 발생시켜 조기 차단(Fail-Fast).
- **산출물**:
  - 실시간 룰 승격 모듈 (`src/detection/incident_mapper.py`).
  - 단위 테스트 (`tests/unit/test_incident_mapper.py`).

### 4단계: 사후 비동기 LLM 심층 분석기 연계 (Out-of-band)
- **내용**:
  - 실시간 L4/L7 차단이 완료된 후, 차단 이벤트 및 공격 로그를 비동기 큐/워커로 전달받아 심층 분석 수행.
  - MITRE ATT&CK 기술 지식베이스 및 보안 플레이북(Playbook) RAG를 결합하여 침해사고 종합 요약문과 사후 재발 방지 권고안을 구조화 출력(Structured Outputs)으로 생성.
- **산출물**:
  - 사후 분석 LLM 프롬프트 및 비동기 분석 모듈.

### 5단계: 오탐/정탐 검증 및 ReDoS 안전성 튜닝
- **내용**:
  - 정상적인 관리자 로그인 로그, 1~2회 오타 발생 로그, 실제 대량 공격 로그를 주입하여 회귀 테스트 수행.
  - 정규식 ReDoS(Catastrophic Backtracking) 방어 구조 검증 및 윤일(Leap day) 등 날짜 경계 처리 검증.
- **산출물**:
  - 탐지 정확도 및 오탐 검증 테스트 (`tests/unit/test_rules.py`).
  - 보안 구현 보고서 (`docs/roles/security/`).
