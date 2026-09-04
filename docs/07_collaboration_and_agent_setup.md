# CloudShield: 개발 하네스(Development Harness) 및 에이전트 협업 체계 구축 계획

## 1. 개요 및 하네스 구축 목적

* **배경**: 비전공자 3인(클라우드, 네트워크, 보안)과 전공자 1인(클라우드 A)으로 구성된 팀에서, 모든 팀원이 코딩 에이전트를 주 개발 도구로 활용함.
* **핵심 문제점**:
  * 비전공자의 Git/GitHub 조작 미숙으로 인한 브랜치 꼬임 및 머지 충돌.
  * 코딩 에이전트의 Context Drift(공통 스키마 및 디렉토리 구조 임의 변경).
  * 로컬 Mock과 실제 AWS 런타임 제약조건 간 괴리로 인한 배포 시점 장애.
  * 에이전트가 생성한 코드에 대한 팀원의 이해 부족(면접 블랙박스 리스크).
* **목적**:
  * 전공자 1인이 조기 착수 기간(Day 1~3)에 테스트베드, Mock 규격, 자동 검증 CI 파이프라인으로 구성된 **"개발 하네스(Development Harness)"**를 사전 구축하여 팀원 전원의 개발 환경을 통제하고 결과물 품질을 강제함.

---

## 2. 디렉토리 구조 및 코드 소유권(CODEOWNERS) 통제

에이전트가 타 직무 영역의 코드를 무단 수정하지 못하도록 디렉토리를 도메인별로 엄격히 격리하고 변경 권한을 제한함.

### 2.1 디렉토리 레이아웃
```text
aleph-project/
├── .github/
│   ├── CODEOWNERS                 # 영역별 필수 리뷰어 및 수정 제한 지정
│   ├── pull_request_template.md   # 원리 요약 및 검증 강제 템플릿
│   └── workflows/
│       ├── ci.yml                 # 코드 스타일, 테스트, 스키마 불변성 검증
│       └── cd.yml                 # Lambda 및 인프라 자동 배포
├── src/
│   ├── contracts/                 # [절대 동결] 공통 인터페이스 및 Pydantic 모델
│   │   ├── __init__.py
│   │   ├── incident.py            # IncidentReport 모델
│   │   └── events.py              # CloudWatch Logs, Syslog 모델
│   ├── collector/                 # 클라우드 B: CW Logs 수신 및 Gzip 디코더
│   ├── detection/                 # 보안: 룰 엔진(rules.py) 및 LLM 분석기
│   ├── remediation/               # 클라우드 A: Boto3 WAF/SG/NACL/IAM 조치 모듈
│   └── reporter/                  # 클라우드 B: Slack Block Kit 알림 모듈
├── network/                       # 네트워크: 공격 스크립트, pcap 파일, 분석 문서
├── infra/                         # 클라우드 A: Terraform IaC 모듈
├── tests/
│   ├── conftest.py                # Mock Fixture 및 moto AWS 환경 설정
│   ├── mock_data/                 # 표준 입력 Mock JSON/로그 파일
│   │   ├── mock_auth.log
│   │   ├── mock_cw_event.json
│   │   └── mock_incident.json
│   ├── test_contracts.py          # 스키마 유효성 및 파괴적 변경 감지 테스트
│   └── test_pipeline_e2e.py       # 파이프라인 모의 통합 테스트
├── AGENTS.md                      # 코딩 에이전트 전역 헌법
└── pyproject.toml                 # uv 기반 의존성 고정 (pydantic, boto3, moto 등)
```

### 2.2 CODEOWNERS 정책
* `src/contracts/`: 클라우드 A(전공자) 단독 승인 필수. 타 팀원의 에이전트 수정 원천 차단.
* `infra/`, `.github/`: 클라우드 A 단독 승인 필수.
* `network/`: 네트워크 담당 승인.
* `src/detection/`: 보안 담당 승인.
* `src/collector/`, `src/reporter/`: 클라우드 B 담당 승인.

---

## 3. Contract-First Mock 테스트베드 설계

실제 AWS 리소스 프로비저닝 전, 로컬에서 4개 직무가 100% 독립 병렬 개발할 수 있도록 사전에 정밀한 Mock 환경을 제공함.

### 3.1 Pydantic V2 기반 엄격한 Contract (`src/contracts/incident.py`)
AWS 런타임 에러를 방지하기 위해 정규식 및 유효성 검사기(Validator)를 내장:

```python
from pydantic import BaseModel, Field, field_validator
from typing import List, Literal
import re


class IncidentReport(BaseModel):
    incident_id: str = Field(..., description="식별자 (예: INC-20260904-001)")
    attack_type: str = Field(..., description="공격 유형 (예: SSH Brute Force, Web L7 Spraying)")
    mitre_id: str = Field(..., description="MITRE ATT&CK ID (예: T1110.001, T1046)")
    risk_level: Literal["HIGH", "MEDIUM", "LOW"]
    source_ip: str = Field(..., description="공격자 출발지 IP")
    target_identifier: str = Field(
        ..., description="타깃 EC2 Instance ID (예: i-0123456789abcdef0)"
    )
    target_accounts: List[str] = Field(default_factory=list)
    summary_ko: str = Field(..., description="침해 상황 한글 요약 (2~3문장)")
    action_required: Literal["BLOCK_WAF", "QUARANTINE_EC2", "REVOKE_IAM_SESSION", "ALERT_ONLY"]
    recommendations: List[str] = Field(default_factory=list)

    @field_validator("source_ip")
    @classmethod
    def validate_ip(cls, v: str) -> str:
        pattern = r"^(\d{1,3}\.){3}\d{1,3}$"
        if not re.match(pattern, v):
            raise ValueError(f"유효하지 않은 IPv4 주소 형식: {v}")
        return v

    @field_validator("target_identifier")
    @classmethod
    def validate_instance_id(cls, v: str) -> str:
        if not re.match(r"^i-[0-9a-f]{8,17}$", v):
            raise ValueError(f"유효하지 않은 EC2 인스턴스 ID 형식: {v}")
        return v
```

### 3.2 로컬 AWS Mocking 테스트 하네스 (`tests/conftest.py`)
`moto` 라이브러리를 도입하여 Boto3 호출을 로컬에서 가상 실행:
* WAFv2 IPSet 생성 및 업데이트 모킹.
* EC2 인스턴스 생성 및 Security Group 변경 모킹.
* IAM Role 및 자격증명 세션 취소(`RevokeSecurityTokens`) 모킹.
* CloudWatch Logs 이벤트 수신 및 Base64+Gzip 자동 인코딩/디코딩 유틸리티 제공.

---

## 4. CI/CD 파이프라인 및 품질 통제 (GitHub Actions)

### 4.1 CI 워크플로우 검증 단계 (`.github/workflows/ci.yml`)
모든 PR 생성 및 푸시 시 다음 4단계를 자동 실행하며, 실패 시 머지를 차단함:

1. **정적 분석 및 포맷팅**:
   * `uv run ruff check .`
   * `uv run ruff format --check .`
2. **인터페이스 불변성 검사 (Contract Drift Guard)**:
   * PR 변경 파일 목록 중 `src/contracts/`가 포함되어 있고 작성자가 클라우드 A가 아닌 경우 즉시 빌드 실패 처리.
3. **단위 및 통합 테스트**:
   * `uv run pytest tests/`
   * 테스트 커버리지 및 Mock 계약 준수 여부 검증.
4. **IaC 보안 검사**:
   * `trivy config infra/` (Terraform 보안 취약점 사전 스캔).

### 4.2 Pull Request 템플릿 (`.github/pull_request_template.md`)
에이전트가 작성한 코드를 팀원이 완전히 이해하도록 기술적 서술을 강제함:

```markdown
## 1. 작업 개요
- 관련 직무: [네트워크 / 클라우드 A / 클라우드 B / 보안]
- 관련 이슈 번호: #

## 2. 핵심 변경 사항
- 구현한 모듈 및 함수 명세:

## 3. 기술적 원리 요약 (★ 필수 작성)
> 에이전트가 작성한 코드의 핵심 동작 원리를 3줄 이내로 직접 설명하세요.
1. 
2. 
3. 

## 4. 로컬 테스트 및 검증 결과
- [ ] `uv run ruff check .` 통과
- [ ] `uv run pytest` 통과
- 터미널 출력 결과 또는 로그 캡처:
```

---

## 5. 코딩 에이전트 행동 지침 (AGENTS.md 표준)

리포지토리 루트의 `AGENTS.md`에 다음 4대 원칙을 강제하여 에이전트의 임의 코드 수정을 차단함:

1. **수정 금지 파일 명시**:
   * `src/contracts/*.py`, `.github/workflows/*.yml`, `pyproject.toml`은 사용자 명시적 지시 없이 수정 금지.
2. **커밋 메시지 규칙 준수**:
   * 포맷: `<type>(<scope>): <한글 요약>`
   * Scope: `network`, `cloud-a`, `cloud-b`, `security`, `infra`, `contract`
3. **코드 주석 필수화**:
   * 모든 작성 함수 상단에 입력값 제약(Constraints), 예외 처리 조건(Edge-cases), 사용 라이브러리 선정 이유(Why)를 프로덕션급 한국어 주석으로 명시.
4. **테스트 동반 생성**:
   * 신규 기능 추가 시 `tests/` 디렉토리 내에 해당 기능을 검증하는 `pytest` 테스트 코드를 반드시 세트로 작성.

---

## 6. 하네스 구축 3일 실행 로드맵 (전공자 주도)

| 일차 | 목표 | 상세 작업 내용 | 산출물 |
| :---: | :--- | :--- | :--- |
| **Day 1** | 레거시 정리 및 Contract 동결 | - 이전 SentinelHub 포렌식 코드 제거<br>- `src/contracts/` 내 Pydantic 모델 확정<br>- `tests/mock_data/` 3종(로그, CW 이벤트, 리포트) 생성 | `src/contracts/`<br>`tests/mock_data/` |
| **Day 2** | Mock Fixture 및 테스트베드 구축 | - `pyproject.toml`에 `moto`, `pytest`, `ruff` 세팅<br>- `tests/conftest.py`에 moto 기반 WAF/EC2/IAM Mock 환경 작성<br>- 계약 검증 테스트(`test_contracts.py`) 작성 | `tests/conftest.py`<br>`tests/test_contracts.py` |
| **Day 3** | CI 파이프라인 및 에이전트 헌법 배포 | - `.github/workflows/ci.yml` 작성 및 Branch Protection 설정<br>- `.github/pull_request_template.md` 및 `CODEOWNERS` 작성<br>- `AGENTS.md` 개정 후 팀원 로컬 클론 가이드 배포 | `.github/`<br>`AGENTS.md` |
