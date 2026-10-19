# 사후 LLM 심층 분석 2차 Slack 카드

- Notion Task: https://app.notion.com/p/A-d5f04d37c22582ad9e7f81acd36191d0?p=3fe04d37c2258024aa1adac9da0012f1
- 직무: 클라우드 B
- 노션 상세 조회는 연결 권한 오류(404)로 확인하지 못했다. 사용자 요청 제목과 기존 계약을 기준으로 구현했다.
- 관련 이슈: https://github.com/mmmphyun/aleph-project/issues/200
- 최초 로컬 작업 이후 사용자의 PR 생성 요청에 따라 최신 main 기반 전용 브랜치로 분리했다.

`from reporter import build_llm_slack_payload`로 가져와 검증된 사후 분석 `IncidentReport`를 전달한다.
반환값은 기존 빌더와 동일한 `text`, `blocks`, 사건 메타데이터 구조이며 `is_llm_card=True`로 구분한다.
기존 `send_slack_alert`는 변경하지 않았다. 2차 분석 실행·전송 연결은 플랫폼 담당 영역이다.

1. 기존 IncidentReport를 받아 동일 incident_id로 1차 알림과 분석 결과를 연계한다.
2. 분석 요약, 위험도, MITRE, 대상 계정, 후속 권고를 표시하며 권고 액션을 집행 결과와 구분한다.
3. 기존 이스케이프·자르기 함수를 재사용하여 표시 문자열을 500자 이하로 제한한다.

빌더는 외부 API·저장소를 사용하지 않고 입력을 변경하지 않는다. 계약, AWS 자격증명, 인프라 변경은 없다.
회귀 테스트는 사건 연계·입력 불변성·빈 분석·긴 입력·멘션 이스케이프를 검증한다.

검증: 리포터·계약 테스트 152개 및 R&R·Ruff lint/format·diff 공백 검사는 통과했다.
`powershell .\scripts\check.ps1`은 실행 정책으로 차단되어 `pwsh -File`로 동일 스크립트를 실행했다.

## 전체 검증 실패 원인 재확인

TEMP·TMP·PYTEST_DEBUG_TEMPROOT를 쓰기 가능한 작업 폴더로 지정해 임시 폴더 권한 문제를
해소한 뒤, 전체 게이트와 변경 전 HEAD의 별도 복사본 전체 테스트를 끝까지 실행했다.

| 구분 | 통과 | 실패 | 오류 | 건너뜀 |
| --- | ---: | ---: | ---: | ---: |
| 변경 전 HEAD | 816 | 233 | 4 | 4 |
| 이번 변경 적용 | 819 | 233 | 4 | 4 |

실패·오류 테스트 ID 집합이 완전히 일치한다. 이번 변경으로 추가된 실패는 없다.

- 네트워크 205개·타깃 서버 28개 실패: Git Bash가 Windows 객체 생성 권한 오류
  `NtCreateDirectoryObject ... 0xC0000022`로 초기화되지 않는다(종료 코드 `0xC0000142`).
  Bash에 `exit 0`만 전달해도 동일하게 종료되어 카드 빌더와 무관함을 확인했다.
- Lambda 패키징 4개 오류: PyPI DNS 조회/접속 실패로 Linux용 pydantic 휠을 다운로드하지 못한다.
- 새 카드 테스트 3개는 모두 통과한다. 코드 수정은 필요하지 않아 검증 기록만 보완했다.

전체 게이트는 환경 문제로 여전히 미통과다. 재현 로그는 저장소 바깥 작업 폴더의
`verification-current.log`, `verification-baseline.log`에 보관했다.
