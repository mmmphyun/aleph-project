# CloudWatch Agent 버퍼링 및 수집 지연 검증 보고서

- 작성일: 2026-10-08 (KST)
- 담당: 클라우드 B
- 상태: 로컬 분석 도구 검증 완료, AWS 실측 미수행

## 1. 확인된 오류와 수정

기존 inotify 즉시 감지 설명을 폴링으로 정정했다. AWS 공식 `plugins/inputs/logfile/logfile.go`는 `Poll: true`로 tailer를 구성한다. 배포 버전에 같은 구현이 적용되는지는 해당 버전 소스와 Agent 로그로 확인한다.

`force_flush_interval: 2`는 Agent 메모리 버퍼 설정이다. EC2에서 CloudWatch까지의 전체 지연 상한이 아니므로 기존 2초 상한 및 3초 목표 충족 예상 표현을 정정했다. 두 JSON 설정은 일치하며 변경하지 않았다.

Nginx 기본 설정과 초기화 스크립트의 내장 설정 모두 access_log에 buffer/gzip 옵션이 없다. 커널 페이지 캐시와 Nginx 사용자 공간 버퍼 및 Agent 버퍼를 구분해야 한다. 디스크 영속화 완료가 파일 읽기의 선행 조건은 아니므로 dirty_* 또는 inotify sysctl 변경은 실측 근거 없이 적용하지 않는다.

## 2. 계측 도구 및 재현 절차

`src/collector/collection_latency.py`의 summarize_collection_latency는 단일 로그 그룹의 FilterLogEvents 원본에서 ingestionTime - timestamp를 계산한다. 두 시각은 Unix epoch 밀리초이며 API 조회 완료 시각은 사용하지 않는다. p50/p95는 nearest-rank 방식이다. 순서를 정렬하고 같은 eventId를 중복 제거하되 충돌하는 시각은 오류로 처리한다.

1. 별도 실행 ID를 포함한 요청을 승인된 타깃에 보내고 기대 로그 건수를 기록한다. /health는 access_log off이므로 표본으로 사용하지 않는다. 요청 시작부터의 E2E와 로그 발생부터의 수집 지연을 구분한다.
2. EC2 시계 동기화, OS, Agent 버전, 실제 적용 설정, 로그 그룹/스트림, 실행 구간과 부하를 기록한다. 5초 기본값과 2초 설정을 동일 조건에서 비교한다. 여기서는 설정을 배포하지 않았다.
3. AWS CLI filter-log-events에서 전용 실행 ID와 스트림/시간 범위를 제한하고 자동 페이지 처리를 유지한다. SDK를 쓰면 nextToken을 끝까지 읽고 모든 events를 결합한다. 다른 실행 또는 로그 그룹의 결과를 섞지 않는다.
4. 메시지에는 토큰 등 비밀을 넣지 않는다. 원본은 로컬에 보관하고 필요한 시각과 eventId만 검토용으로 공유한다.
5. 저장한 JSON에 대해 다음 명령을 실행한다 (프로젝트 설치 환경).

```powershell
.\.venv\Scripts\python.exe -m collector.collection_latency events.json --expected-count 100 --budget-ms 3000
```

입력은 32 MiB, 이벤트 배열은 10만 건으로 제한한다. 필수 필드 누락, 음수 지연, 충돌 중복, 기대 건수 초과는 예외로 종료한다. 누락 또는 예산 초과는 통계를 출력하고 종료 코드 1을 반환한다. API 수집 실패를 빈 성공 데이터로 대체하지 않는다.

Nginx timestamp_format은 초 단위이므로 ingestionTime과의 차이에 1초 미만의 양자화 오차가 포함될 수 있다. 이 도구의 값은 기록된 timestamp 기준이며 정확한 파일 쓰기 시각이나 Lambda 인입 시각이 아니다. 정밀 계측은 별도 밀리초 증적을 사용하고 기존 로그 계약을 유지한다. 시계가 과거로 치우친 경우에는 음수 검증만으로 감지할 수 없으므로 동기화 증적이 필수다.

## 3. 검증 결과와 실측 상태

- 로컬 수집기 테스트: 40개 통과 (기존 26개와 새 경계 조건 14개).
- 역순 도착/중복, 기대 건수 누락, 음수 지연, 잘못된 필드 타입, 중복 ID 충돌, 표본 혼입, 용량 상한을 검증했다.
- 합성 표본: 지연 100ms/3100ms, 중복 1건에서 p50=100ms, p95=3100ms, 예산 초과 1건. AWS 실측이 아니다.
- AWS 실측 표본 수: 0. 실제 p50/p95/최댓값 및 3초 목표 달성 여부: 미검증.
- Lambda 전달 및 전체 10초 자동 대응 시간: 이 도구의 측정 범위 밖이며 별도 증적이 필요하다.
- 필수 통합 게이트 결과는 PR 본문에 실제 실행 결과를 기록한다.

## 4. 영향도

공통 계약, 인프라, 로그 형식 및 Agent 설정 변경 없음. 새 영속 저장소/호출 간 상태/외부 API 호출 없음. AWS 자격증명 추가 없음. PR은 분석 도구와 테스트 및 문서 정정만 포함한다.

## 5. 근거

- [AWS logfile 구현](https://github.com/aws/amazon-cloudwatch-agent/blob/main/plugins/inputs/logfile/logfile.go)
- [AWS Agent 설정](https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/CloudWatch-Agent-Configuration-File-Details.html)
- [CloudWatch 이벤트 시각 정의](https://docs.aws.amazon.com/AmazonCloudWatchLogs/latest/APIReference/API_FilteredLogEvent.html)
- [Nginx 로그 버퍼 및 msec](https://nginx.org/en/docs/http/ngx_http_log_module.html)
