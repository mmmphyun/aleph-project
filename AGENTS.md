# CloudShield: 프로젝트 에이전트 헌법 및 작업 지침 (AI Working Agreement)

너는 CloudShield(클라우드 하이브리드 위협 탐지·자동 대응 및 SecOps 파이프라인) 프로젝트의 팀원이다.
모든 코딩 에이전트는 본 헌법의 규정을 무조건적으로 준수해야 한다.

---

## 1. 프로젝트 정체성 및 핵심 목표

* **단일 10초 관통 데모 파이프라인**:
  - 웹/UI 개발 매몰을 방지하고, 실제 클라우드 인프라 침해 위협에 대한 10초 관통 자동 대응 능력을 증빙함.
  - 흐름: `공격 발생(Hydra/Nmap) -> 타깃 서버(EC2) -> CW Agent 중앙 수집 -> Lambda 오케스트레이터(시그니처/LLM) -> 다중 계층 원자적 차단(L4 SG / L7 WAF / IAM 세션) -> Slack 상황 전파`.

---

## 2. R&R 경계선 및 비전공자 포트폴리오 지분 절대 침범 금지

에이전트는 프롬프트를 수행할 때 **의뢰자의 담당 직무 영역 외 타 팀원의 고유 포트폴리오 영역을 절대 침범하거나 임의로 코드를 작성·수정하지 않는다.**

```text
[비전공자 팀원 3인 고유 도메인 - 면접 핵심 무기: 침범 절대 금지]
1. 네트워크: 모의 공격 스크립트, tcpdump/Wireshark L4 패킷 플래그 분석 보고서 (network/)
2. 클라우드 B: CW Agent 수집 설정, Slack Block Kit 알림 모듈 (src/collector/, src/reporter/)
3. 보안: 정규식 시그니처 룰(rules.py), LLM Few-shot 프롬프트/분석기 (src/detection/)

[전공자 클라우드 A 독점 플랫폼 영역 - 엔지니어링 깊이 확보]
- 공통 데이터 인터페이스 계약 (src/contracts/)
- Lambda 런타임 오케스트레이터 및 Boto3 원자적 복합 차단 엔진 (src/remediation/)
- Terraform IaC 모듈화 및 Trivy 검증 (infra/)
- GitHub Actions OIDC 무인증 CI/CD 파이프라인 (.github/)
- moto 기반 가상 AWS 테스트베드 및 개발 하네스 (tests/)
```

---

## 3. 절대 동결 및 수정 금지 파일 (Protected Contracts)

다음 파일 및 경로는 클라우드 A(테크 리드)의 명시적 지시 없이 **어떤 에이전트도 절대 임의 수정할 수 없다.**
- `src/contracts/*.py` (IncidentReport, Events 모델)
- `.github/workflows/*.yml` (CI/CD 파이프라인)
- `pyproject.toml` (공통 프로젝트 의존성)

---

## 4. Git 브랜치 및 커밋 메시지 컨벤션

### 4.1 브랜치 전략
- `feat/<직무>-<기능명>` (예: `feat/security-rules-engine`, `feat/cloud-b-slack-card`)
- `fix/<이슈명>`
- `chore/<작업명>`

### 4.2 커밋 메시지 컨벤션
- 형식: `<type>(<scope>): <한글 요약>` (마침표 없음)
- Type: `feat`, `fix`, `refactor`, `docs`, `chore`, `test`, `style`, `perf`, `ci`
- Scope: 반드시 담당 직무 및 도메인 명시
  - `contract`: 공통 인터페이스 규격
  - `cloud-a`: 오케스트레이터 및 복합 차단 엔진
  - `cloud-b`: 로그 수집 및 Slack 알림
  - `security`: 시그니처 룰 및 LLM 분석 엔진
  - `network`: 모의 공격 및 패킷 분석
  - `infra`: Terraform IaC
- 예시: `feat(security): SSH 무차별 대입 1차 시그니처 룰 구현`

---

## 5. 코드 주석 및 엔지니어링 표준

- **언어**: 한국어 (프로덕션급 기술 주석)
- **금지**: 단순 코드 동작 읊기, 튜토리얼식 설명.
- **필수 포함 항목**:
  1. **Why**: 해당 로직/라이브러리를 채택한 비즈니스 및 아키텍처적 이유.
  2. **Constraints**: 매개변수 유효성 제약조건, 단위, 정규식 규격.
  3. **Side-effects / Edge-cases**: 외부 API 호출, 예외 발생 조건, 동시성 주의사항.

---

## 6. 테스트 및 품질 검증 원칙

- 신규 기능 구현 또는 버그 수정 시 반드시 `tests/` 디렉토리에 `pytest` 테스트 코드를 함께 작성한다.
- 작업 완료 전 다음 명령어를 반드시 통과해야 한다:
  ```powershell
  uv run ruff check .
  uv run ruff format --check .
  uv run pytest
  ```
- 테스트를 통과시키기 위해 기존 검증 로직이나 제약조건을 임의 삭제하는 행위를 엄격히 금지한다.

---

## 7. 안전 및 보안 규칙

1. `main` 브랜치에 직접 push하지 않는다.
2. AWS Access Key, Secret Key, API 토큰 등 자격증명을 절대 하드코딩하거나 커밋하지 않는다.
3. 실제 인프라 변경 코드는 사전 승인된 영향 범위(단일 테스트 VPC/계정) 내로 제한한다.
4. 로컬 개발 및 테스트 시에는 `moto` 기반의 가상 Mock 환경을 우선 활용한다.
