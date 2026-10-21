# P4 Bedrock 어댑터 및 장애 Fallback

## 1. 작업 범위

- 작업일: 2026-10-21
- 담당: 보안 (`@gkacksdnjs22-stack`)
- Notion Task: [Bedrock 어댑터·Fallback 테스트](https://notion.so/3fe04d37c225804cbf96ff03ed3d1e6c)
- GitHub Issue: [#205](https://github.com/mmmphyun/aleph-project/issues/205)
- 브랜치: `feat/security-p4-bedrock-adapter-fallback`
- 인터페이스: `analyze_incident_with_bedrock(report, raw_logs, bedrock_client=None, model_id="apac.amazon.nova-micro-v1:0") -> IncidentReport`

기존 결정론적 `IncidentReport`를 기준으로 Bedrock에 설명 보강을 요청한다.
[기존 프롬프트·파서](2026-10-19-p4-llm-prompt-parser.md)를 재사용하며
SDK 호출 장애나 잘못된 응답 때문에 이미 생성한 원본 보고서를 잃지 않도록 한다.
이 함수는 사후 분석용이며 아직 플랫폼 비동기 워커·실시간 오케스트레이터·Slack에 연결하지 않는다.

## 2. 요청과 응답 경계

Nova의 [Converse 지원](https://docs.aws.amazon.com/nova/latest/userguide/using-converse-api.html)과
[Boto3 요청·응답 규격](https://docs.aws.amazon.com/boto3/latest/reference/services/bedrock-runtime/client/converse.html)에
맞춰 비스트리밍 `converse`만 사용한다. 별도의 모델별 JSON/스트림 어댑터는 만들지 않는다.

| 항목 | 정책 |
| --- | --- |
| 기본 모델 | 티켓 및 플랫폼 변수와 동일한 `apac.amazon.nova-micro-v1:0`; 호출부가 명시적으로 교체 가능 |
| 입력 | 기존 프롬프트 빌더가 보고서·로그 타입, UTF-8 및 용량을 검증 |
| 요청 | `modelId`, 사용자 메시지의 단일 텍스트 프롬프트, `maxTokens=2048`, `temperature=0` |
| 호출 횟수 | 애플리케이션 1회, 기본 SDK 총 시도 1회 |
| 정상 종료 | `stopReason="end_turn"`, `output.message.role="assistant"` |
| 출력 블록 | 비어 있지 않은 text 전용 블록 1~32개를 순서대로 연결; 도구·혼합 블록 거부 |
| 출력 크기 | 결합 전부터 UTF-8 합계 32KiB를 검사하고 기존 파서에서도 다시 검증 |
| 보강 범위 | `summary_ko`, `recommendations`만 반영; 나머지 모든 필드는 원본 값 보존 |

출력 블록 수 제한은 이 어댑터의 방어 정책이며 AWS 서비스 한도가 아니다.
`max_tokens`·필터링·도구 요청·알 수 없는 종료 사유는 JSON이 유효해 보여도 수용하지 않는다.
보호 필드의 모델 출력은 기존 파서 정책대로 폐기한다. 잘못된 JSON·누락·추가 키·잘못된 타입 등은
원본으로 복귀하지만, 스키마상 유효한 설명의 사실성까지 자동 판별하지는 않는다.

## 3. 클라이언트 수명과 장애 처리

주입한 `bedrock_client`를 그대로 사용한다. 없으면 함수 호출 시 `boto3.client("bedrock-runtime")`를
생성하고 기본 자격증명·리전 제공자 체인을 사용한다. 모듈 import 시 클라이언트를 만들지 않는다.
직접 생성한 클라이언트는 성공·실패·예상 밖 예외 모두 `finally`에서 정리하며 주입 클라이언트는
호출부가 관리한다. 정리 중 SDK 장애는 내용 없는 별도 경고를 남긴다.

기본 [botocore Config](https://docs.aws.amazon.com/botocore/latest/reference/config.html)는
연결 2초·읽기 20초, `retries={"mode":"standard","total_max_attempts":1}`이다.
총 시도 1회는 최초 요청을 포함하므로 SDK 재시도를 추가하지 않는다.
이 설정은 연결·읽기 단계 제한이며 자격증명 조회·DNS·응답 처리까지 포함한 함수 전체의
절대 마감 시간을 보장하지 않는다. 주입 클라이언트의 타임아웃·재시도와 워커 전체 실행 예산은
플랫폼 호출부가 관리해야 한다. 출력 토큰 제한과 낮은 temperature도 사실성이나 지연을 보장하지 않는다.

| 실패 종류 | 결과 |
| --- | --- |
| 클라이언트 생성·호출의 `BotoCoreError`, `ClientError`, `TimeoutError` | 고정 경고와 동일 원본 객체 반환 |
| 자격증명·리전 결함, 연결·읽기 타임아웃, 권한·서비스 오류 | 위 SDK 오류 경계로 동일하게 격리 |
| 잘못된 응답 포장·종료 사유·UTF-8·용량·JSON·보강 필드 | 고정 경고와 동일 원본 객체 반환 |
| 입력 보고서·로그·모델 식별자 오류 | Bedrock 호출 전에 예외 전파 |
| 예상 밖 프로그래밍 오류 | 임의의 `Exception`으로 삼키지 않고 전파 |

경고에는 원문·보고서·모델 응답·IP·사고 ID·AWS 예외 메시지를 넣지 않는다.
이 Fallback은 선택적 LLM 보강의 실패 계약이다. 저장소·차단 엔진·플랫폼 워커의
재시도/DLQ를 위한 예외 전파 정책을 바꾸지 않는다.

## 4. 분산 제약과 검증 범위

| 제약 | 적용 |
| --- | --- |
| 런타임 수명 | 호출 간 공유 상태·캐시 없이 입력 보고서로만 보강 |
| 저장소 상한 | 새 DB·무한 append 없음; 기존 입력 상한과 출력 토큰·바이트·블록 수 제한 |
| 일관성 | 저장 후 조회가 없어 강한 일관성 읽기 대상 없음 |
| 순서 역전 | 사건별 보고서를 재분류하거나 슬라이딩 윈도우를 재집계하지 않음 |
| 장애 격리 | 예상 LLM 장애는 경고·원본 복귀, 입력 및 예상 밖 오류는 전파 |

오프라인 테스트는 클라이언트를 주입하거나 기본 생성 경로를 패치하며 기존 소켓 차단을 유지한다.
실제 Bedrock 호출·과금·IAM 변경·인프라 배포는 수행하지 않는다. 모델 접근 가능 여부,
운영 계정의 리전·추론 프로파일 권한, 실제 지연·비용·정확도는 이번 검증의 증명 범위가 아니다.

## 5. 검증 결과

`powershell .\scripts\check.ps1` 원본 게이트를 우회 없이 실행해
**1280 passed, 4 skipped, 1 warning**으로 통과했다(229.11초, 종료 코드 0).
R&R 3파일 경계 검사, 테스트 경로 검사, Ruff lint 및 152개 Python 파일 format 검사도 통과했다.
skip 4건은 기존 WAF·네트워크 Terraform 환경 조건으로 각각 2건이며,
경고 1건은 기존 소켓 차단 smoke 테스트의 DNS 호출 차단이다. 새 skip은 없다.

`tests/unit/test_llm_analyzer.py`는 기존 84개와 신규 어댑터 46개를 합해 130개를 통과했다.
공식 `botocore.stub.Stubber`로 Converse 요청·응답 규격을 확인하고
원본·보호 필드 보존, 다중 텍스트/UTF-8 용량 경계, 잘못된 포장·중단·JSON,
SDK 생성·호출 장애, 민감 내용 없는 경고, 클라이언트 소유권과 정리,
입력·예상 밖 오류 전파 및 호출 간 상태 분리를 검증했다.
독립 변경 리뷰에서 PR을 막는 신규 결함은 발견하지 않았다.

최신 main `e464539`에서 분리한 작업 공간에서 Python 3.13.15와 lockfile의 개발 의존성을
사용했다. Windows 인코딩 일치를 위해 `PYTHONUTF8=1`, `PYTHONIOENCODING=utf-8`을 설정했고
검증 스크립트·공통 계약·의존성 명세는 변경하지 않았다.
기존 작업 공간의 사용자 문서 수정과 `assets/`는 보존하고 PR에 포함하지 않는다.
