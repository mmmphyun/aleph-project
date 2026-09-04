# CloudShield: Cloud Hybrid Threat Detection & Auto-Response Pipeline

**클라우드 하이브리드 위협 탐지·자동 대응 및 SecOps 파이프라인**

클라우드 워크로드 대상 침해 공격 발생 시, 10초 이내에 **로그 수집 → 위험도 판단(시그니처/LLM) → 복합 원자적 차단(L4 SG 격리 / L7 WAF IPSet 차단 / IAM 세션 무효화) → Slack 상황 전파**를 수행하는 엔드투엔드 보안 자동화 파이프라인입니다.

---

## 1. 핵심 관통 파이프라인

```text
[네트워크 공격 시뮬레이션 (Hydra/Nmap)]
               │
               ▼
[타깃 서버 (EC2 / auth.log, Nginx access.log)]
               │
               ▼ (< 3초)
[CloudWatch Agent 수집 & 중앙 전송]
               │ (Subscription Filter)
               ▼
[Lambda 런타임 오케스트레이터 & 보안 엔진]
       ├─ 1차: 정규식 시그니처 룰 (rules.py)
       └─ 2차: Few-shot LLM 분석 (IncidentReport 생성)
               │
               ▼ (< 5초)
[Boto3 다중 계층 원자적 차단 엔진 (remediation.py)]
       ├─ L4: EC2 격리 보안 그룹 (Quarantine SG) 단독 교체
       ├─ L7: AWS WAF IPSet 공격자 IP (/32) 등록
       └─ Identity: 침해 의심 IAM Role 임시 세션 무효화
               │
               ▼ (< 2초)
[SecOps 전파: Slack Block Kit 알림 (slack_notifier.py)]
```

---

## 2. 주요 문서

* [팀 프로젝트 메모리 스냅샷 (Project Memory)](docs/project-memory.md)
* [개발 하네스 및 협업 체계 계획](docs/07_collaboration_and_agent_setup.md)
* [직무 간 인터페이스 데이터 규격서](docs/08_interface_contracts.md)

---

## 3. 개발 원칙 및 협업

* **브랜치 전략**: GitHub Flow 기반 (`feat/<직무>-<기능>`, `fix/*`, `chore/*`)
* **커밋 메시지**: `<type>(<scope>): <한글 요약>` (scope: `contract`, `cloud-a`, `cloud-b`, `security`, `network`, `infra`)
* **코드 품질 검증**: `uv run ruff check .`, `uv run ruff format --check .`, `uv run pytest`
* **계약 준수**: `src/contracts/` 인터페이스 스키마는 절대 임의 수정 불가 (클라우드 A 전담)

