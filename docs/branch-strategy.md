# 브랜치 전략

## 기본 원칙

- `main`에는 검증된 결과만 둡니다.
- 작업은 Issue를 만든 뒤 별도 브랜치에서 시작합니다.
- 하나의 Issue는 하나의 작업 브랜치와 하나의 PR로 처리합니다.
- PR 리뷰와 CI 검사를 통과한 뒤 `main`에 병합합니다.
- 작업이 끝난 브랜치는 원격에서도 정리합니다.

## 브랜치 이름

```text
feat/<기능명>      기능 개발
fix/<문제명>       버그 수정
test/<테스트명>    테스트 추가·수정
docs/<문서명>      문서 변경
chore/<작업명>     프로젝트 설정·구조·CI 변경
```

예시:

```text
feat/event-normalizer
feat/jit-access-request
fix/permission-revoke
test/privilege-escalation
docs/update-threat-model
chore/setup-ci
```

## 현재 초기화 작업

현재 저장소 초기 구조를 준비하는 작업은 다음 브랜치에서 진행합니다.

```text
chore/initialize-project-structure
```

이 브랜치는 저장소 구조와 프로젝트 문서를 원격에 올리기 위한 작업용 브랜치입니다. PR 템플릿, GitHub Actions, 브랜치 보호 규칙을 추가로 준비한 뒤 `main`에 병합합니다.

## 작업 흐름

```text
main에서 최신 내용 받기
→ 작업 브랜치 생성
→ 작은 단위로 구현·커밋
→ 테스트 실행
→ PR 생성
→ 리뷰 및 CI 통과
→ main 병합
→ 작업 브랜치 삭제
```

## 커밋 메시지

커밋 메시지는 다음 형식을 사용합니다.

```text
<type>: <짧은 설명>
```

허용하는 type:

```text
feat      기능 추가
fix       버그 수정
test      테스트 추가·수정
docs      문서 변경
chore     설정·구조·의존성 변경
refactor  동작 변경 없는 구조 개선
```

예시:

```text
feat: 비정상 로그인 이벤트 파서 추가
fix: 만료된 임시 역할 회수 오류 수정
docs: 이벤트 스키마 문서화
chore: 프로젝트 초기 구조 설정
```

## 브랜치 생성 예시

```bash
git switch main
git pull --ff-only origin main
git switch -c feat/event-normalizer
```

## 현재 원격 반영 절차

초기화 브랜치는 다음처럼 Push합니다.

```bash
git push -u origin chore/initialize-project-structure
```

이 단계에서는 PR을 만들거나 `main`에 직접 Push하지 않습니다. Git 세팅과 PR 템플릿을 준비한 뒤 PR을 생성합니다.
