## 1. 작업 개요

- Notion Task: https://app.notion.com/p/A-d5f04d37c22582ad9e7f81acd36191d0?p=40504d37c22581648c87db747dcfea1d&pm=c
- 관련 직무: [ ] 네트워크 / [ ] 클라우드 A / [X] 클라우드 B / [ ] 보안
- 관련 이슈 번호: #238 (사용자의 후속 PR 발행 요청으로 생성)
- 브랜치: `codex/cloud-b-p5-2-grafana-slack`, 기준 `f2b6fc7`.
- 최종 상태: 고정 로그 기반 실환경 통합 실증의 Grafana 화면·쿼리 대조 완료.
  후속 확인은 `2026-10-30-p5-2-panel-verification.md`에 기록했다.
  아래 10월 29일 환경 제약과 운영 로그 재조회 내용은 당시 진행 기록이다.
- 노션 상세는 연결 계정에서 404. 제공된 제목과 머지된 P5-1의 인계 명세를 기준으로 구현했다.

## 2. 핵심 변경 사항

- `src/reporter/grafana_dashboard.py::build_dashboard(region)`:
  기존 `cloudshield-cloudwatch` 데이터소스에 연결하는 2×2 대시보드 생성.
- `docs/roles/cloud-b/grafana/p5-2.json`: Grafana 가져오기용 JSON.
  기존 플랫폼 대시보드와 다른 UID `cloudshield-p5-2`를 사용한다.
- `src/reporter/card_preview.py::build_three_stage_preview(...)`:
  기존 탐지·LLM·복구 카드 빌더를 호출해 동일 사건의 세 카드를 순서대로 생성한다.
  외부 통신이나 실제 복구는 수행하지 않는다.
- `evidence/p5-2-2026-10-29/local-card-preview.json`:
  문서용 IP·가상 인스턴스·합성 사건 ID를 사용한 로컬 렌더링 예시.
  가짜 Slack 게시 시각, Bedrock 응답 또는 운영 성공 증거는 포함하지 않는다.

| 사분면 | 데이터와 해석 |
| --- | --- |
| 좌상단 | SSH Failed password·Nginx HTTP 4xx 로그를 분 단위 집계. 확정 공격 수가 아닌 후보 로그 수 |
| 우상단 | 기존 pipeline_timestamps의 탐지→대응 API 반환 구간(초). 현재 CW 로그 연계가 없어 No data 예상. 전체 10초 SLA는 미평가 |
| 좌하단 | cloudshield.llm_analysis의 enhanced / parse_failed / call_failed. 사건별 마지막 상태를 집계하고 관측된 사건 사이 비중 표시 |
| 우하단 | 두 Lambda의 사건·Slack·복구 로그 최신 200건. ID 없는 로그는 특정 사건과 결합하지 않음 |

현재 `pipeline_timestamps`는 EventBridge detail에만 전달되며 INFO 로그에 출력되지 않는다.
우상단은 이 기존 필드가 JSON 로그에 제공될 때 사용할 준비된 쿼리다.
`remediated_epoch` 자체도 성공 판정을 보장하지 않으므로 이 구간을 물리적 차단 SLA로 쓰지 않는다.
LLM 상태 로그가 없는 임포트·프롬프트 실패나 미호출 사건은 좌하단 분모에서 제외된다.
분석 API 오류율이나 전체 시스템 성공률로 해석하지 않는다.

### 사용 방법과 재현

1. 기존 Grafana에서 Dashboards → New → Import로 `grafana/p5-2.json`을 가져온다.
   데이터소스 UID는 P5-1과 동일하다. 리전 기본값은 `ap-southeast-2`다.
2. 각 패널에서 로그 그룹 이름을 실제 환경과 대조한다. 기본 Lambda 그룹은
   `/aws/lambda/CloudShield-Threat-Orchestrator`, `/aws/lambda/cloudshield-llm-analyzer`다.
   P5-1의 Grafana 11.2.0 공식 쿼리 타입과 대조해 해당 버전이 지원하는
   `logGroupNames` 필드를 사용했다. `logGroups`에는 ARN이 필수이므로 계정 ARN을 추정하지 않는다.
3. 조회 시간 범위는 최근 1시간이며 자동 새로고침은 비활성화했다.
   필요한 시간대로 범위를 줄이고 수동 새로고침한다.
4. 대시보드 생성은 프로젝트 Python 환경에서 다음으로 재현할 수 있다.

```python
import json
from pathlib import Path
from reporter.grafana_dashboard import build_dashboard

Path("docs/roles/cloud-b/grafana/p5-2.json").write_text(
    json.dumps(build_dashboard(), ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
)
```

플랫폼 소유 `infra/grafana/**`는 수정하지 않았다. 따라서 기존 Docker provider가
이 파일을 자동 로드하지는 않는다. 현재 실행 중인 Grafana가 없어 가져오기·화면 표시는
확인하지 못했다. Docker daemon 연결 실패 및 localhost:3000 미응답을 확인했다.
AWS CLI도 `NoCredentials`로 실제 Logs Insights 구문 실행·결과 대조를 수행하지 못했다.

### 실제 3단계 실증의 완료 기준

동일 incident_id의 실제 1차 탐지·2차 분석·3차 복구 카드 원문과 Slack 원본 ts를 확보하고
게시 순서를 대조해야 한다. 복구 성공에는 엔진 결과가 필요하고, 실제 통신 회복에는
별도 통신 관측이 필요하다. 로컬 예시의 설정 복구 표시는 합성 입력을 렌더링한 결과다.

현재 3차 빌더를 자동 호출·전송하는 플랫폼 경로가 없다. 자동 실증을 완성하려면
클라우드 A의 복구 실행·카드 전송 연결 및 CW 시간 필드 로깅이 필요하다.
이는 이번 클라우드 B 변경에 포함하지 않았다. 기존 환경·로그·3단계 카드 증거가
제공되면 B가 단독으로 관제 자료를 대조할 수 있으나, 전체 실증 완료를 현재 주장하지 않는다.

## 3. 기술적 원리 요약 (1, 2, 3 필수 작성)

1. CloudWatch 원시 로그와 기존 LLM JSON 상태를 4개 Grafana 패널에서 조회한다.
2. 기존 IncidentReport와 카드 빌더를 재사용해 같은 사건의 탐지·분석·복구를 순서대로 렌더링한다.
3. 누락된 시간·전송·통신 증거는 미확인으로 남겨 로컬 재현과 운영 실증을 구분한다.

## 4. 로컬 테스트 및 품질 검증 결과

- reporter 테스트 170개 통과. 전문 보존·동일 사건 연계·복구 실패/미확인·길이 상한 검증 포함.
- 대시보드 JSON 재생성 일치, 2×2 배치, 데이터소스·로그 그룹·쿼리 모드 검증.
- `scripts/check.ps1` 전체 품질 게이트 통과(종료 코드 0):
  **1504 passed, 4 skipped, 1 warning**, 175.52초.
  R&R·테스트 경로·Ruff lint/format·계약 및 전체 pytest를 모두 실행했다.
- 실행 명령은 `powershell -NoProfile -ExecutionPolicy RemoteSigned -File .\scripts\check.ps1`.
  로컬 PowerShell 실행 정책은 프로세스 범위에만 적용했다. 검증 우회 옵션은 사용하지 않았다.
  샌드박스 DNS·하위 프로세스 제한 밖에서 실행하고, 기존 셸 하네스의 공백 경로 문제를
  피하도록 TEMP/TMP/PYTEST_DEBUG_TEMPROOT를 공백 없는 허용된 임시 경로에 지정했다.
  소켓 차단 스모크 테스트의 예상 경고 1개와 기존 skipped 4개를 결과에 포함한다.
  전체 로그: 저장소 외부 `../p5-2-check-verified-final.log`.
- 실제 AWS 쿼리 실행, Grafana 화면 렌더링, Slack 게시 및 물리적 차단·복구는 미검증.

## 5. 보안 및 계약 영향도

### 2026-10-30 운영 로그 재조회

기존 `cloudshield-cloud-b` 프로필로 ap-southeast-2의 00:19:40~00:20:05 UTC를
읽기 전용 조회했다. origin/main에서 #233·#235 머지를 확인했으나 로컬 작업 트리는
병합하지 않았다. 다음 내용은 A의 요약과 별도로 실제 CW 응답에서 확인한 값이다.

- Orchestrator RequestId `580c8526-4e94-4564-98c9-ecab249f55ec`:
  INIT_START 00:19:45.137, START 00:19:46.093, END/REPORT 00:19:50.046 UTC.
  Duration 3952.14ms는 A 안내와 일치하지만 INIT_START를 실제 호출 시작으로 사용하면 안 된다.
- Analyzer RequestId `40a363a8-a03a-45fd-8abc-a10e2040dc6c`:
  INIT_START 00:19:50.292, START 00:19:51.226, END/REPORT 00:19:53.326 UTC.
  Duration 2099.30ms. 00:19:52.417에 Bedrock API 호출 또는 파싱 예외·원본 유지 WARNING이 있다.
  2차 카드 도착을 정상 LLM 분석 성공으로 간주할 수 없다.
- 해당 조회 구간에는 `ThreatRemediatedMetric` 및 LLM 상태 INFO 로그가 없다.
  따라서 사건 ID·탐지/대응 시간·조치 성공을 이 CW 응답만으로 확정할 수 없다.
- 두 실행의 X-Ray TraceId는 `1-6ae3e2a0-50667dca237f8a2666faab01`로 일치한다.
  이 사실만으로 Slack 사건 ID까지 검증된 것은 아니다.
- 실제 수집 그룹은 `/cloudshield/target/auth-log`,
  `/cloudshield/target/nginx-access-log`다. A 안내의 `/cloudshield/ec2/target-*`와 다르며
  이번에 만든 대시보드 기본 그룹은 실제 환경과 일치한다.
- Docker daemon은 여전히 미기동이다. Slack 카드 원문·원본 ts·실제 복구 응답은
  A의 요약만 전달됐으며 독립 검증하지 않았다. 실제 환경 변경과 Slack 발송은 하지 않았다.

후속 요청: INFO 정형 로그 출력 설정의 실제 배포 확인, 재실행 사건의 시간·성공 여부
JSON 원문, 동일 사건 Slack 3장 원문·원본 ts, 복구 엔진 원본 결과가 필요하다.
현재 진행 상태는 실환경 검증 진행 중이며 완료가 아니다.

### INFO 핫픽스 후 재검증: INC-1793321673-0089

2026-10-30 00:54:30~00:55:05 UTC의 실제 CloudWatch 로그에서
`ThreatRemediatedMetric`, `remediation_success=true`, 탐지→대응 반환 2.6089초와
`cloudshield.llm_analysis/status=call_failed`를 직접 확인했다.
1·2차 Slack 전송 성공 로그도 확인했다. Slack 게시 원문·원본 ts를 읽은 것은 아니다.

작성한 대시보드 JSON의 쿼리를 그대로 AWS Logs Insights에서 실행한 결과:

- 시간 패널 queryId `29180f5f-4974-4e33-9f65-371f46e0ac9a`:
  Complete, max/p95 모두 2.6089초, 매칭 1건.
- LLM 상태 패널 queryId `fd91c1aa-bafe-4f6e-b497-37f8640923c2`:
  Complete, outcome=call_failed, incidents=1.

따라서 앞서 기록한 시간·LLM INFO 로그 부재는 이 새 사건에서 해소됐다.
2.6089초는 탐지→대응 API 반환 구간이며 전체 공격 시작→물리 차단 SLA로 확장하지 않는다.
LLM 패널은 정상 분석 성공이 아니라 Fallback 1건을 올바르게 집계했다.
새 사건의 3차 복구 카드·엔진 결과와 Grafana 화면은 아직 확인하지 않았다.
운영 코드·인프라·Slack 발송 변경 없이 읽기 전용 검증을 수행했다.

- src/contracts/ 인터페이스 스키마 변경 여부 (클라우드 A 승인 필수): 없음
- AWS 자격증명/토큰 노출 여부: 없음
- 인프라 리소스 영향: 없음
- PR·push·노션 상태 변경·Slack 발송 없음.
- 타 직무 코드 및 infra/ 수정 없음. 대시보드는 클라우드 B 문서 경로의 가져오기 자료다.

쿼리 작성 근거:
[Grafana CloudWatch 로그 쿼리](https://docs.aws.amazon.com/grafana/latest/userguide/CloudWatch-using-the-logs-query-editor.html),
[AWS JSON·시간 함수](https://docs.aws.amazon.com/AmazonCloudWatch/latest/logs/CWL_QuerySyntax-operations-functions.html),
[Grafana CloudWatch 편집기](https://grafana.com/docs/plugins/cloudwatch/latest/query-editor/).
버전별 JSON 형식은
[Grafana 11.2.0 공식 타입](https://github.com/grafana/grafana/blob/v11.2.0/public/app/plugins/datasource/cloudwatch/dataquery.gen.ts)을 대조했다.
