# 프로젝트 메모리 스냅샷

작성 시점: 2026-08-19

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

## 현재 저장소 규칙

- `AGENTS.md`: LLM 공통 작업 규칙
- `CONTRIBUTING.md`: 사람용 협업 가이드
- `docs/event-schema.md`: 공통 이벤트 계약
- `docs/security-rules.md`: 보안·레드팀 안전 규칙
- `docs/프로젝트_상세계획.md`: 전체 실행 계획
- `docs/llm/`: 비전공자용 설명과 레드팀 계획

## 다음 작업

1. 문서 변경을 커밋하고 Push
2. CloudTrail Fixture 파일 추가
3. 초기화 브랜치 PR 생성
4. CI 상태 확인 후 `main` 보호 규칙에 필수 검사 연결
5. 팀원 로컬 온보딩
6. Mock 이벤트 기반 최소 수직 흐름 구현
