# 상사 보고용 LLM 3단 양식과 인젝션·Fallback 고정 평가

- 담당: 보안 (`@gkacksdnjs22-stack`)
- Issue: [#221](https://github.com/mmmphyun/aleph-project/issues/221)
- Notion Task: [3단 구조화 프롬프트·골든셋 검증](https://notion.so/40504d37c225819cbd4fdff19c338636)
- 브랜치: `feat/security-executive-llm-report-and-eval`
- 기준 main: `c1d149050f2b4df9ee9176d91faeb7721b6efd5e` (클라우드 A PR #218 머지)

## 1. 출력 규격과 검증 경계

`IncidentReport`의 필드·타입·불변성은 유지한다. `summary_ko` 문자열 내부만 다음 양식을 사용한다.
각 제목 다음은 실제 LF 하나이며, 단락 사이는 LF 두 개다. JSON 전송 시에는 해당 LF가
`\n`으로 이스케이프된다. 각 단락은 제목과 내부 LF 포함 400자 이하, 전체는 두 단락 구분자
포함 1,200자 이하다. 따라서 단락 세 개를 모두 400자로 채우면 전체 1,204자로 거부된다.

```text
[1. 침해 개요]
관측된 공격 행위의 개요 한 문장

[2. 관측 로그 근거]
제공된 시각·계정·URI·상태 코드 중 확인 가능한 근거 한 문장

[3. 영향도 및 침해 판정]
관측 사실과 미확인 사실을 구분하고 원본 매퍼 판정을 보존하는 한 문장
```

`recommendations`는 `[즉시 조치] `, `[설정 점검] `, `[재발 방지] ` 순서의 문자열 세 개다.
각 항목은 제목·공백·비어 있지 않은 점검 본문을 포함해 500자 이하다. 한국어·문장 수·근거의
사실성은 프롬프트 지시이며, 파서는 제목·순서·본문 존재·문자 수·UTF-8 유효성을 강제한다.

SSH/Web Few-shot은 기존 매퍼와 각 5개의 합성 로그를 재사용한다. 403 응답을 WAF 집행으로,
200 응답을 정보 유출로 단정하지 않고 성공 인증·격리 집행 등 미확인 항목을 구분한다.

## 2. 호출 호환과 보호 필드

| 진입점 | 기본 동작 | 엄격 모드 적용 |
|---|---|---|
| `build_bedrock_analysis_prompt(report, raw_logs)` | 3단 양식과 기존 전체 JSON 계약을 지시 | 기존 인자·반환형 유지 |
| `parse_bedrock_response_to_incident(raw, base_report)` | 기존 단문 응답 호환; 보고 제목이 등장하면 엄격 검증 | `require_executive_format=True`로 제목 누락까지 거부 |
| `analyze_incident_with_bedrock(...)` | 엄격한 3단 양식을 기본 검증 | 기존 단문 소비자는 키워드 옵션 `False`로 호환 경로 선택 |

엄격 경로는 모델이 제공한 보호 필드가 원본 JSON 값과 다르면 응답 전체를 거부한다.
식별자·IP·타깃·MITRE·위험도·차단 액션은 모델 출력으로 갱신하지 않는다. 기존 파서의 단문
호환 경로도 두 보강 필드만 병합하므로 보호 필드 변조는 허용하지 않는다. 모든 실패는
부분 병합 없이 동일한 원본 객체를 반환한다. 공통 모델의 스키마와 기존 위치 인자는 바꾸지 않았다.

## 3. 상태 텔레메트리

`detection.llm_deep_analyzer`가 INFO 수준의 JSON 메시지를 기록한다.

```json
{"event":"cloudshield.llm_analysis","status":"enhanced","reason":"validated_response","incident_id":"INC-example"}
```

| status | reason | 의미 |
|---|---|---|
| `enhanced` | `validated_response` | 파서 검증과 원본 보호 필드 병합 성공; 실제 모델 정확도·차단 집행 성공의 증거는 아님 |
| `parse_failed` | `response_validation` | JSON·형식·용량·보호 필드 검증 실패, 원본 유지 |
| `parse_failed` | `converse_envelope` | 중단 응답·도구 블록·응답 포장 오류, 원본 유지 |
| `call_failed` | `bedrock_call` | 예상 SDK·권한·타임아웃 장애, 원본 유지 |

원문 로그·응답·IP·요약·권고·SDK 예외 문자열은 기록하지 않는다. 사건 ID가 128자를 넘으면
`incident_id` 대신 UTF-8 SHA-256 `incident_ref`를 기록한다. 기존 고정 경고는 유지한다.
호출부 입력 오류와 예상 밖 프로그래밍 오류는 전파하며 이를 Fallback 성공으로 집계하지 않는다.
상태는 개별 처리 시도 기준이므로 이벤트 중복 수신 시 중복 로그가 생길 수 있다. 사건 단위
지표는 소비자가 사건 ID와 필요한 시도 구분 근거로 집계하고, 로그 건수를 고유 사건 수로 간주하지 않는다.

## 4. 고정 평가셋과 비기능 검증

`tests/unit/test_incident_mapper.py::test_executive_report_golden_set`에 15건을 고정했다.

| 사례 | 수 | 주입 결과와 기대값 |
|---|---:|---|
| SSH 인증 실패 | 5 | 유효한 구조화 응답 수용, 보호 필드 불변 |
| Web 경로 열거 | 5 | 유효한 구조화 응답 수용, 보호 필드 불변 |
| SSH 계정명 인젝션 | 1 | IP·액션 변조 응답 전체 거부 |
| URI 인젝션 | 1 | 추가 지시 키가 있는 응답 거부 |
| User-Agent 인젝션 | 1 | 불완전 JSON 응답 거부 |
| 단락 용량 초과 | 1 | 400자 초과 단락 거부 |
| SDK 타임아웃 | 1 | 내용 없는 경고·상태와 동일 원본 반환 |

평가는 합성 응답을 주입한 오프라인 회귀다. 15건의 보호 필드 불변과 실패 5건의 원본 보존을
검증한다. 실제 Bedrock의 인젝션 저항률·사실성·근거 일치율·지연·비용 측정으로 확대하지 않는다.
표본 10건 수용/5건 격리는 평가셋에 지정된 결과이며 운영 환경의 Fallback 비율이 아니다.

LLM 전용 테스트에는 정확한 400/1,200/500자 경계, 단락 누락·중복·역순·빈 본문, 모든 보호
필드 변조, 호환 경로, 상태별 로그와 비밀 문자열 제외, 과대 사건 ID, 호출 간 상태 분리를 포함한다.
기존 로그 50줄·줄당 4,096자·합계 32KiB, 기본 보고서 16KiB, 프롬프트 256KiB,
응답 32KiB·32블록, 출력 2,048토큰 및 SDK 2/20초·1회 제한을 유지한다.
상한까지 긴 한국어 출력을 한 번에 생성할 수 있다는 보장은 없으며, 중단 응답은 원본으로 복귀한다.
새 DB·시간창·공유 상태·배열 누적·의존성은 추가하지 않는다.

## 5. 클라우드 A/B 연계와 남은 실증

- 클라우드 A의 현재 `llm_worker.execute_bedrock_analysis`는 보안 프롬프트 빌더와 파서를
  직접 호출하고 Bedrock 호출은 자체 처리한다. 새 프롬프트는 반영되지만, 제목을 전혀 출력하지
  않는 모델 응답까지 거부하려면 A 소유 호출부에서 파서에 `require_executive_format=True`를
  전달해야 한다. 또는 기존 보안 `analyze_incident_with_bedrock` 어댑터를 재사용할 수 있다.
- 보안 어댑터에서 추가한 `call_failed`는 현재 A 워커의 자체 SDK 호출 실패에는 실행되지 않는다.
  운영 지표의 누락·이중 집계를 막으려면 A가 보안 어댑터로 호출을 일원화하거나 자체 호출 실패를
  동일 상태 규격으로 기록해야 한다. Lambda의 INFO 로그 활성화도 배포 단계에서 확인한다.
- 클라우드 B의 [멀티 블록 렌더러](https://notion.so/40504d37c22581c38dadfadabb31adca)는
  현재 시작 전이다. 기존 렌더러는 요약을 500자에서 자르므로 보고서 전문 표시는 아직 검증하지
  않았다. B는 같은 제목을 사용하고 Slack escaping 이후에도 블록당 500자 이하로 분할해야 한다.
  원문 400자만으로 escaping 후 500자 이하가 보장되지는 않는다.
- 실인프라 배포·Slack 전문 표시·Grafana 패널과 실제 SSH/Web 사건의 근거 대조는 각 담당자의
  후속 작업 및 P5 실증 범위다. 이 PR은 워커·리포터·계약·인프라를 수정하지 않는다.

## 6. 검증 결과

- 전체 `powershell .\scripts\check.ps1`: **1367 passed, 4 skipped, 1 warning**, 270.85초,
  종료 코드 0. R&R 4파일·테스트 경로·Ruff lint·159개 Python 파일 format 검사를 통과했다.
- skip 4건은 기존 네트워크·WAF Terraform 도구/provider 준비 조건 각 2건이다. 경고는 기존
  소켓 차단 smoke 테스트의 DNS 호출 차단이며 신규 skip은 없다. 추가 회귀는 총 51건이다.
- 보안 LLM·매퍼 집중 테스트도 성공했다. 전체 게이트 후에는 이 검증 결과와 로그 집계 주의점을
  문서에 기록했으며 소스와 테스트는 그대로다. 실인프라 성공을 의미하지 않는다.
- 기존 작업 폴더의 문서 수정과 `assets/`는 보존하고 최신 main의 분리 worktree에서 검증한다.
- 실제 AWS·Bedrock·Slack 호출, 인프라 변경과 Notion 상태 직접 변경은 수행하지 않는다.
