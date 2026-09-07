# CloudShield: 개발 하네스(Development Harness) 및 에이전트 협업 체계 구축 계획

## 1. 개요 및 하네스 구축 목적

* **배경**: 4개 직무(클라우드 A, 클라우드 B, 네트워크, 보안)의 분업 구조에서, 모든 팀원이 코딩 에이전트를 주 개발 도구로 활용함.
* **핵심 문제점**:
  * 도메인 분업 환경에서의 Git/GitHub 브랜치 꼬임 및 머지 충돌.
  * 코딩 에이전트의 Context Drift(공통 스키마 및 디렉토리 구조 임의 변경).
  * 로컬 Mock과 실제 AWS 런타임 제약조건 간 괴리로 인한 배포 시점 장애.
  * 에이전트가 생성한 코드에 대한 팀원의 이해 부족(면접 블랙박스 리스크).
* **목적**:
  * 플랫폼 리드(클라우드 A)가 조기 착수 기간(Day 1~3)에 테스트베드, Mock 규격, 자동 검증 CI 파이프라인으로 구성된 **"개발 하네스(Development Harness)"**를 사전 구축하여 팀원 전원의 개발 환경을 통제하고 결과물 품질을 강제함.

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
* `src/contracts/`: 클라우드 A(플랫폼 리드) 단독 승인 필수. 타 직무 에이전트의 임의 수정 원천 차단.
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

## 4. CI/CD 파이프라인 및 품질·거버넌스 통제 (GitHub Actions)

### 4.1 GitHub Actions 원격 자동화 배관
CloudShield는 코드 품질 검증뿐만 아니라 에이전트 거버넌스와 노션 칸반 보드 수명주기까지 완전 자동화합니다:

1. **품질 검증 및 Contract Drift Guard (`.github/workflows/ci.yml`)**:
   - `uv run ruff check .` 및 `uv run ruff format --check .` (코드 스타일 및 포맷팅).
   - `src/contracts/` 인터페이스 변경 감지 시 클라우드 A 외 작성자의 무단 수정 즉시 차단.
   - `uv run pytest tests/` (moto 가상 AWS 리소스 기반 계약 및 단위 검증).
2. **PR 제목 및 커밋 컨벤션 검사 (`.github/workflows/pr_title_lint.yml`)**:
   - Conventional Commits 형식 및 필수 직무 스코프(`<type>(<scope>): <한글 요약>`) 강제.
3. **경로 기반 자동 라벨러 (`.github/workflows/labeler.yml`)**:
   - 변경 파일 경로를 분석하여 `role:*`, `area:*`, `type:*` 라벨을 100% 자동 부착.
4. **노션 칸반 라이프사이클 동기화 (`.github/workflows/notion_sync.yml`)**:
   - Issue/PR 생성, 리뷰 요청, 머지 이벤트를 수신하여 노션 [프로젝트 일정] DB의 상태(`[진행 중]`, `[검토 중]`, `[완료]`) 및 작업 기간(start~end), 머지 요약 Callout 블록을 원자적 동기화.
   - 노션 미등록 일감 발생 시 신규 카드 자동 발급(`POST /v1/pages`) 안전망 탑재.

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
- [ ] uv run ruff check . 통과
- [ ] uv run pytest 통과
- 터미널 출력 결과 또는 로그 캡처:
```

---

## 5. 코딩 에이전트 행동 지침 및 세션 라이프사이클

리포지토리 루트의 `AGENTS.md` 및 `docs/agent_session_starter.md`에 정의된 핵심 통제 원칙:

1. **1세션 1이슈 원칙**: 하나의 대화창에서 여러 이슈를 연속 작업하지 않고 이슈별 새 세션 분기.
2. **로컬 역할 잠금 (`.agent-role`)**: 로컬 환경에서 본인 직무 외 디렉토리 수정을 차단.
3. **세션 기동 자동화**: 세션 시작 시 `node scripts/get_my_tasks.js`를 실행하여 노션 `[시작 전]` 티켓을 자동 바인딩.
4. **설명 선행 원칙**: 코딩 착수 전 사용자에게 2~3줄로 기술 개념 선행 설명.
5. **커밋 메시지 규칙 준수**: `<type>(<scope>): <한글 요약>` (마침표 없음, 필수 직무 스코프).

---

## 6. 침해 대응 시나리오별 하네스 지원 현황

| 구분 | 시나리오 1: SSH Brute Force (L4) | 시나리오 2: Web L7 Scanning/Spraying |
| :--- | :--- | :--- |
| **공격 벡터** | SSH 포트(22) 비인가 무차별 대입 | Web HTTP(80/443) 비인가 스캐닝 및 인증 우회 |
| **모의 공격 스크립트** | `network/attack_simulation.sh` (Hydra 완비) | `network/web_attack_simulation.sh` (확장 예정) |
| **로그 수집 규격** | `/var/log/auth.log` (`SyslogAuthEvent` 완비) | Nginx `access.log` (`NginxAccessEvent` 규격 확장 예정) |
| **탐지 룰 엔진** | `src/detection/rules.py` (임계치 5회) | `src/detection/rules.py` (HTTP 4xx/5xx 빈도 분석) |
| **차단 메커니즘** | EC2 Quarantine SG 단독 교체 (`quarantine_applied`) | AWS WAF IPSet `/32` 등록 (`waf_blocked`) |
| **Mock 테스트베드** | `mocked_ec2_target`, `mock_auth.log` 완비 | `mocked_waf_ipset`, `mock_incident_waf_only.json` 완비 |
| **현 상태** | **Vertical Slice 관통 완료 (Golden Path)** | **백엔드 차단/Mock 완비, 프론트 수집 파서 대기** |

---

## 7. 하네스 구축 실행 결과 및 지속성 관리

- **Day 1~3 완료 내역**:
  - `src/contracts/` Pydantic V2 불변성 계약 확정 및 Drift Guard 구축.
  - Moto 기반 가상 AWS(EC2, SG, WAFv2, IAM) 테스트베드 구축.
  - GitHub Actions 4대 워크플로우(CI, PR Title Lint, Labeler, Notion Sync) 가동.
  - `.agent-role` 로컬 가드 및 3대 에이전트(Cursor, Claude Code, Antigravity) 프롬프트 연동.
- **운영 원칙**:
  - 하네스 베이스라인은 동결(Freeze) 상태를 유지하며, 팀원들의 실무 구현 중 발생하는 인터페이스 변경은 반드시 버그 기반(Bug-driven) PR을 통해서만 점진적으로 반영함.
