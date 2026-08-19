# 프로젝트 메모리 스냅샷

작성 시점: 2026-08-19

## 기억 저장 규칙

이 파일은 `C:\work\project` 프로젝트의 작업 맥락만 저장합니다.

- 중요한 결정과 결정 이유를 저장합니다.
- 구현 완료 내용, 실패한 접근과 원인을 저장합니다.
- 다음 작업 TODO와 주의사항을 저장합니다.
- API 키, 비밀번호, 토큰, `.env` 내용은 저장하지 않습니다.
- 불필요한 전체 로그와 민감한 개인정보는 저장하지 않습니다.

## 프로젝트

- 저장소: `C:\work\project`
- 원격: `https://github.com/mmmphyun/aleph-project.git`
- 현재 작업 브랜치: `chore/initialize-project-structure`
- 프로젝트: SentinelHub
- 목표: 멀티 계정 AWS 환경의 위험한 권한 사용과 네트워크 노출을 탐지하고, 승인 기반 JIT 권한과 자동 대응으로 처리

## 팀

- 4인 팀
- 보안 2명, 클라우드 1명, 네트워크 1명
- 모든 팀원이 LLM을 사용
- 코드는 LLM이 생성할 수 있지만, 담당자가 동작·보안 영향·테스트를 검증

## 확정된 설계

- 관리·보안·업무 AWS 3계정 구조
- Terraform 기반 재현 가능한 인프라
- CloudTrail S3 경로는 감사·재분석용
- EventBridge와 AWS Config 이벤트 경로는 탐지·대응용
- 이벤트 전달은 best effort이며 “수초 내 대응”을 보장하지 않음
- 이벤트 발생부터 대응 완료까지 실제 지연을 측정
- 공통 이벤트 스키마에 `region`, `event_name`, `event_source`, `outcome`, `user_agent`, `risk` 포함
- 수집·정규화와 위험도 평가를 분리
- JIT는 역할 정책 + Session Policy + TTL 만료로 구현
- 긴급 세션 무효화는 역할 단위 영향 범위를 문서화
- 승인 인터페이스는 MVP 필수
- Slack·Discord는 선택형 adapter
- 네트워크 MVP는 보안 그룹 노출 탐지와 안전한 원복
- NACL 기반 C2 자동 차단은 후순위 또는 제외

## MVP 필수 항목

- 비식별화한 CloudTrail Fixture 3종: `AssumeRole`, `PutBucketAcl`, `AuthorizeSecurityGroupIngress`
- Fixture 기반 파서 테스트
- 승인 인터페이스 1개: CLI 또는 간단한 웹
- Session Policy로 영구 백도어 생성 경로 제한
- TTL 만료 및 긴급 무효화 테스트
- 이벤트 지연 측정
- 레드팀 시나리오 3개

## 협업·Git

- `main` 직접 Push 금지
- Issue → 작업 브랜치 → 작은 커밋 → PR → 리뷰 → CI → `main` 병합
- 브랜치: `feat/*`, `fix/*`, `test/*`, `docs/*`, `chore/*`
- 커밋: `<영문 type>: <한국어 설명>`
- 기본적으로 커밋 본문과 불릿 포인트는 사용하지 않음
- 현재 초기화 브랜치에는 PR/Issue 템플릿, Python 설정, CI, 협업·보안 문서가 Push됨

## 구현 완료

- 초기 저장소 디렉터리 구조 생성
- `AGENTS.md`와 `CONTRIBUTING.md` 작성
- 브랜치·커밋 메시지 컨벤션 작성
- PR·Feature·Bug·Task 템플릿 추가
- Python `pyproject.toml` 작성
- Ruff·pytest·pre-commit 설정 추가
- GitHub Actions CI 추가
- 프로젝트 상세 계획·이벤트 스키마·보안 규칙·레드팀 계획 갱신
- CloudTrail Fixture 폴더와 비식별화 규칙 문서 추가
- 이 프로젝트 메모리 스냅샷 작성

## 실패한 접근과 원인

- `main` 직접 Push: 저장소 규칙과 안전 정책에 맞지 않아 중단. 초기화 브랜치 PR 방식으로 전환.
- 초기 커밋 메시지 수정 시도: 기존 커밋이 원격에 Push되지 않은 상태라 로컬 이력을 재작성해 한국어 설명으로 정리.
- 로컬 Ruff·pytest 실행: 현재 실행 환경에 도구가 설치되지 않아 실행하지 못함. GitHub Actions는 의존성을 설치하도록 구성.
- Slack을 MVP 필수 승인 수단으로 채택하는 방안: Webhook·서명 검증·공개 엔드포인트 복잡도가 커서 승인 인터페이스를 먼저 만들고 Slack은 adapter로 미룸.
- NACL 기반 C2 자동 차단: 서브넷 단위·상태 비저장 특성으로 오탐과 영향 범위가 커 MVP에서 제외.

## 현재 저장소 규칙

- `AGENTS.md`: LLM 공통 작업 규칙
- `CONTRIBUTING.md`: 사람용 협업 가이드
- `docs/event-schema.md`: 공통 이벤트 계약
- `docs/security-rules.md`: 보안·레드팀 안전 규칙
- `docs/프로젝트_상세계획.md`: 전체 실행 계획
- `docs/llm/`: 비전공자용 설명과 레드팀 계획

## 다음 작업

1. `assume_role.json`, `put_bucket_acl.json`, `authorize_security_group_ingress.json` Fixture 추가
2. Fixture 기반 파서와 공통 이벤트 변환 테스트 작성
3. 초기화 브랜치 PR 생성
4. CI 상태 확인 후 `main` 보호 규칙에 필수 검사 연결
5. GitHub Issue 라벨 확인: `type:feature`, `type:bug`, `type:task`
6. 팀원 로컬 온보딩
7. Mock 이벤트 기반 최소 수직 흐름 구현

## 다음 작업 주의사항

- CloudTrail S3 전달과 EventBridge 이벤트 수신을 같은 지연 특성으로 설명하지 않습니다.
- “실시간” 대신 실제 이벤트 지연을 측정하고 결과를 기록합니다.
- Session Policy는 권한 축소용이며 이미 발급된 세션의 중간 회수를 대체하지 않습니다.
- 긴급 세션 무효화는 같은 역할의 다른 세션에 영향을 줄 수 있습니다.
- Fixture에 실제 계정 식별자·자격증명·개인정보를 넣지 않습니다.
- AWS 테스트 리소스는 비용과 삭제 책임자를 정하고 사용 후 정리합니다.
