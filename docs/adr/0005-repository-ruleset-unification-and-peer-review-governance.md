# ADR 0005: Classic Branch Protection 제거 및 Repository Ruleset 기반 1:1 상호 리뷰 거버넌스 단일화

- **상태**: 승인됨 (Accepted)
- **결정자**: 클라우드 A (테크 리드 @mmmphyun)
- **일자**: 2026-09-09
- **소유 직무**: 클라우드 A (플랫폼 거버넌스)
- **관련 PR / Issue**: PR #16, PR #20, Issue #19

---

## 1. 배경 및 문제 제기 (Context)

- GitHub 브랜치 보호 정책 운영 중 구형 **Classic Branch Protection**과 최신 **Repository Ruleset (`protect-main`)**이 공존하면서 심각한 머지 차단(Block) 및 권한 충돌이 발생함:
  - **GitHub 정책 충돌 메커니즘**: 동일 타깃 브랜치(`main`)에 두 개의 보호 정책이 활성화되어 있을 경우, GitHub은 덮어쓰기가 아닌 **가장 엄격한 조건의 합집합(Most Restrictive Union)**을 강제함.
  - **코드오너와 결합된 머지 잠금**: Ruleset에서 `require_code_owner_review: false`로 설정했음에도, Classic 보호 규칙의 `require_code_owner_reviews: true`와 `.github/CODEOWNERS`의 전역 와일드카드(`* @mmmphyun`)가 결합되어 **저장소의 모든 PR에 대해 테크 리드의 승인이 필수 요구**됨.
  - **결과**: 보안/네트워크/클라우드 B 담당자가 상호 리뷰를 완료하더라도 리드의 승인이 없으면 머지 버튼이 활성화되지 않아, 테크 리드가 전체 파이프라인의 **단일 실패 지점(SPOF, Single Point of Failure)**이자 최대 병목으로 작용함.

---

## 2. 대안 검토 및 트레이드오프 분석 (Considered Options)

| 구분 | 방안 1: Classic 유지 및 리드 전담 승인 | 방안 2: CODEOWNERS 전면 삭제 | 방안 3: Classic 제거 + Ruleset 단일화 (채택) |
| :--- | :--- | :--- | :--- |
| **구조** | 모든 PR에 대해 리드 1인의 필수 Approve 강제 | `.github/CODEOWNERS` 파일을 제거하여 오너 개념 폐지 | Classic 완전 삭제, Ruleset 단일화 및 1:1 짝꿍 상호 승인 허용 |
| **장점** | 리드가 모든 코드를 100% 통제 가능 | 설정 충돌 즉시 해소, 단순 1인 승인 동작 | **리드 병목 완벽 해소**, 직무별 파일 소유권 보존, 상호 리뷰 활성화 |
| **단점** | 리드 부재 시 전 팀원 작업 블로킹, 상호 리뷰 동기 저하 | 직무별 포트폴리오 지분 및 핵심 컨트랙트 무단 수정 방어 불가 | 테크 리드가 상호 머지 내역을 사후 모니터링해야 함 |

---

## 3. 아키텍처 결정 (Decision)

1. **Classic Branch Protection 완전 삭제 및 Ruleset 단일화**:
   - `Settings -> Branches`의 구형 Classic 규칙을 전면 삭제(`HTTP 404`)하여 단일 진실 공급원(Single Source of Truth)을 Repository Ruleset(`protect-main`, ID: `20977496`)으로 확정함.
2. **상호 자율 승인 게이트 확립**:
   - Ruleset 파라미터 확정:
     - `required_approving_review_count`: **1**
     - `require_code_owner_review`: **false**
     - `allowed_merge_methods`: **["squash"]** (커밋 히스토리 단일화)
     - `dismiss_stale_reviews_on_push`: **true** (새 커밋 푸시 시 재검토 강제)
     - `strict_required_status_checks_policy`: **true** (최신 main 동기화 필수)
   - `.github/CODEOWNERS`로 인해 리드(`@mmmphyun`)가 리뷰어 목록에 자동 등록되더라도, **지정된 동료 짝꿍 1명의 `Approve`만으로 자율 머지가 가능**하도록 개방함.
3. **1:1 상호 짝꿍 리뷰 체계 공식화**:
   - `네트워크(@RockCandy444) -> 보안(@gkacksdnjs22-stack)`
   - `보안(@gkacksdnjs22-stack) -> 클라우드 B(@wkdtlgns99-cell)`
   - `클라우드 B(@wkdtlgns99-cell) -> 네트워크(@RockCandy444)`
   - 도메인 연계성이 높은 직무 간 1:1 상호 짝꿍 리뷰를 `AGENTS.md` 제4.2조에 헌법화함.

---

## 4. 기대 효과 및 결과 (Consequences)

- **긍정적 영향**:
  - 리드 승인 대기로 인한 작업 지연 완전 제거, 일일 3~5건의 마이크로 PR 신속 머지 달성.
  - 팀원 간 도메인 교차 검증(Cross-domain verification) 역량 강화 및 면접 시 상호 리뷰 기여도 증빙 확보.
  - 스쿼시 머지 강제를 통해 `main` 브랜치 히스토리의 높은 가독성과 원자성 유지.
- **관리 대상 한계점 (Operational Risk)**:
  - 짝꿍 팀원이 결함이 있는 코드를 실수로 승인할 위험이 존재함. 이는 Boto3/Terraform 등 플랫폼 핵심 영역에 대한 사전 CI 계약 테스트(`tests/test_contracts.py`)와 테크 리드의 비동기 거버넌스 스팟 체크(Spot Check)로 완화함.

