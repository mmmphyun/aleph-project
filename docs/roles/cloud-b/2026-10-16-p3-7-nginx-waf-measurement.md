# P3-7 시나리오 2 Nginx access.log 수집 지연 계측 및 WAF Slack 알림 전파 실측

- 관련 Issue: https://github.com/mmmphyun/aleph-project/issues/191
- Notion Task: https://app.notion.com/p/A-d5f04d37c22582ad9e7f81acd36191d0?p=3f704d37c225806cb1d9cb0d497d161a&pm=c
- 담당: 클라우드 B / 작성일: 2026-10-16 KST
- 상태: Lambda 런타임/WAF 원본 로그 대조 및 Slack HTTP 200 전파 확인 완료. Nginx FilterLogEvents 원본은 미확보되어 수집 지연 통계는 미검증으로 분리함.

---

## 1. 개요 및 실측 대상

본 문서는 **시나리오 2(Web L7 디렉터리 스캐닝 공격 대응 파이프라인)** 관통 실측에서 **클라우드 B 담당 고유 도메인인 CloudWatch Agent 기반 Nginx 로그 수집과 Slack Block Kit 알림 전파(Reporter)**의 확보 증거와 미검증 범위를 구분한 보고서이다. 원본이 없는 수집 지연 값은 합성 회귀 테스트로만 제시한다.

### 1.1 인프라 식별자 및 환경
- **AWS 계정**: `885755545044` (ap-southeast-2, 시드니)
- **타깃 ALB Host**: `cloudshield-alb-dev-308142572.ap-southeast-2.elb.amazonaws.com`
- **타깃 인스턴스 (EC2)**: 타깃 웹서버 (Nginx 1.18+, HTTP 80 서비스)
- **공격자 출발지 IP**: `3.26.171.60` (네트워크 담당 모의 공격 고정 IP)
- **CloudWatch 타깃 로그 그룹**: `/cloudshield/target/nginx-access-log`
- **CloudWatch 구독 필터**: `CloudShield-Nginx-Access-Filter` / `CloudShield-Nginx-Scanning-Filter`
- **Lambda 오케스트레이터**: `CloudShield-Threat-Orchestrator` (RequestId: `1f089011-c024-40d9-92a6-852d14833b73`)
- **AWS WAFv2 WebACL**: `CloudShield-WebACL-Dev`, IPSet: `CloudShield-Block-IPSet` (Rule ID: `CloudShield-Block-IP`)
- **Slack 전파 채널**: `#webhook` (`C0BU9AE6970`), 발송 성공 (HTTP 200 OK)

### 1.2 수집 설정 및 증거 확보 범위

#### Nginx 및 CloudWatch Agent 적용 설정
- **Nginx 로깅 포맷 및 정책 (`nginx.conf`)**:
  - `access_log /var/log/nginx/access.log cloudshield_combined;`
  - `location /health`: `access_log off;` (헬스체크 200은 로그 파일에 기록되지 않음)
  - `location /admin`: `auth_basic`에 의해 HTTP 401 반환 및 기록.
  - 기타 미존재 경로(`/login`, `/dashboard`, `/backup` 등): HTTP 404 반환 및 기록.
  - 따라서 네트워크 공격 스캔 15건 중 로컬 파일에 기록되는 로그는 **총 14건 (401 1건, 404 13건)**이다.
- **CloudWatch Agent 포맷 (`amazon-cloudwatch-agent.json`)**:
  - `timestamp_format: "%d/%b/%Y:%H:%M:%S %z"`
  - `force_flush_interval: 2` (2초 주기 버퍼 플러시)
  - Nginx 로그의 타임스탬프(`$time_local`)는 초 단위 해상도이므로, CloudWatch Logs 이벤트의 `timestamp`는 초 경계 정수 밀리초(`...000` ms)로 기록된다. 반면 CloudWatch 수집 시각인 `ingestionTime`은 서비스 접수 시점의 밀리초 정밀도를 가진다.

#### 증거 구분 매트릭스

| 증거 구분 | 확보 범위 |
|---|---|
| **클라우드 B 확인값** | 적용 Nginx/CloudWatch Agent 설정, 보안 매퍼(`map_threat_to_incident`) 계약 기반 Slack Block Kit 페이로드 구조, Slack 발송 성공 시각(17:09:52 KST, HTTP 200) |
| **타 담당 전달값** | 클라우드 A의 Lambda 실행 구간(START 17:09:50.915, END 17:09:52.314, 1.399초), IPSet 갱신 완료(17:09:52, 초 단위), WAF Logs 차단 시각(17:10:09.112) / 네트워크의 PCAP frame 시각(첫 GET 17:09:42.787941, `/backup` 17:09:48.563249, 200 관측 17:10:02.136695, 최초 403 17:10:09.112252) |
| **계산 및 해석** | 첫 GET→Lambda 종료(9.526초)와 첫 GET→최초 403 관측(26.324초)의 측정 범위 분리. 단위 테스트의 수집 지연 값은 계산기 회귀 검증용 합성 입력으로만 사용 |
| **미측정·미확보** | 해당 실행의 FilterLogEvents 원본(`eventId`, `timestamp`, `ingestionTime`, 로그 메시지), 조회 범위/응답 보존본, EC2와 패킷 캡처 호스트 간 시계 오차, 17:10:02~17:10:09 프로브 공백 내 정확한 WAF 룰 활성화 시점, 운영 발송 `incident_id`와 Slack 메시지 원본 |

---

## 2. Nginx access.log 수집 지연(Collection Latency) 계측

### 2.1 원본 확보 상태와 검증 가능 범위

네트워크 PCAP과 적용 Nginx 설정을 대조하면 15개 요청 중 `/health`는 `access_log off`로 제외되고, 로그 대상은 **14건(401 1건, 404 13건)**이다. 그러나 이 PR에는 같은 실행을 식별할 수 있는 FilterLogEvents 원본의 `eventId`, `timestamp`, `ingestionTime`, 요청 메시지, 로그 스트림 및 조회 범위가 보존되어 있지 않다.

따라서 PCAP 송신 시각을 Nginx/CloudWatch 이벤트 시각으로 추정하거나, 임의의 밀리초 지연을 실측값으로 채우지 않는다. 이 실행의 실제 수집 지연 p50/p95/max 및 3초 목표 충족 여부는 **미검증**으로 남긴다. 추후 원본을 확보하면 `ingestionTime - timestamp`를 계산하되, EC2와 패킷 캡처 호스트의 시계 차이는 별도 오차 항목으로 기록해야 한다.

### 2.2 계산기 합성 회귀 검증 (`collection_latency.py`)

`tests/unit/test_collector.py::test_summarize_collection_latency_synthetic_scenario2_shape`는 수집 지연 계산기의 시나리오 2 입력 형태를 검증하는 **합성 단위 테스트**다. 아래 결과는 고정된 임의 지연 배열로 계산 경계와 통계 산출을 확인한 것이며, 2026-10-16 운영 실행의 FilterLogEvents 원본 또는 성능 증거가 아니다.

```json
{
  "scope": "event_timestamp_to_cloudwatch_ingestion",
  "unit": "ms",
  "expected_count": 14,
  "observed_count": 14,
  "missing_count": 0,
  "duplicate_count": 0,
  "p50_ms": 1815,
  "p95_ms": 1825,
  "max_ms": 1825,
  "budget_ms": 3000,
  "over_budget_count": 0,
  "complete": true,
  "within_budget": true
}
```

- **단위 테스트가 보장하는 범위**:
  - 14개의 고유 이벤트 입력에서 누락/중복 및 nearest-rank p50/p95/max 계산이 예상대로 동작한다.
  - 합성 지연이 모두 3초 이하일 때 `within_budget: true`가 반환된다.
  - 실제 운영 표본의 건수 완전성, 지연 분포, Agent 버퍼링 성능은 보장하지 않는다.

---

## 3. 구독 필터 및 런타임 오케스트레이터 연계

### 3.1 구독 필터 동작
- CloudWatch Agent를 통해 `/cloudshield/target/nginx-access-log`에 적재된 Nginx 로그는 Subscription Filter(`CloudShield-Nginx-Scanning-Filter`)에 의해 Lambda 오케스트레이터로 전달됨.
- `cw_processor.py`가 전달받은 Base64/Gzip 압축 페이로드를 디코딩하여 시그니처 룰 평가 및 슬라이딩 윈도우 누적으로 연계함.

### 3.2 분할 인입 및 윈도우 누적
- 1초 간격 순차 요청에 의해 CloudWatch Logs 배치로 분할 인입되더라도, 플랫폼의 `WebAttackWindow`(DynamoDB 2-버킷 슬라이딩 윈도우)에 동일 IP(`3.26.171.60`)의 스캔 카운트가 무손실 누적됨.
- 임계치(5회 이상) 도달 시점 직후인 17:09:50.915 KST에 오케스트레이터 핸들러가 트리거되어 `WEB_DIRECTORY_SCANNING`으로 최종 판정함.

---

## 4. 다중 직무 실측 대조 및 시간 지표 분리 분석

### 4.1 타임라인 전수 대조 매트릭스

근거 없는 서브밀리초 파생값(`.200`, `.300`, `.400`)을 완전히 배제하고, 클라우드 A 로그 전수 대조 결과와 네트워크 PCAP frame 시각만을 엄밀히 대조한 매트릭스이다:

| 단계 | 시각 / 결과 | 주체 및 근거 |
|:---:|:---:|:---|
| **첫 GET `/admin` 송신** | 17:09:42.787941 KST | 네트워크 (PCAP) |
| **다섯 번째 의심 GET `/backup` 송신** | 17:09:48.563249 KST | 네트워크 (PCAP; 첫 의심 GET과 5.775308초 간격) |
| **Lambda 오케스트레이터 실행** | 17:09:50.915 ~ 17:09:52.314 KST | 클라우드 A (Duration: **1.399초**, RequestId: `1f089011-c024-40d9-92a6-852d14833b73`) |
| **탐지 결과** | `WEB_DIRECTORY_SCANNING` 판정 | 클라우드 A (내부 정확한 판정 시각은 별도 미제공) |
| **IPSet 갱신 완료** | 17:09:52 KST (`3.26.171.60/32` 등록) | 클라우드 A (초 단위 기록) |
| **Slack 발송 성공** | **17:09:52 KST** (HTTP 200 OK) | **클라우드 A / B** (초 단위 기록, 실제 사용자 수신 시각은 별도 미제공) |
| **이후 정상 응답 관측** | 17:10:02.136695 KST (HTTP 200) | 네트워크 (PCAP; 종료 사후 확인 HEAD `/`) |
| **최초 WAF BLOCK 기록** | 17:10:09.112 KST | 클라우드 A (WAF Logs: `clientIp=3.26.171.60`, `action=BLOCK`, `terminatingRuleId=CloudShield-Block-IP`) |
| **최초 HTTP 403 수신** | 17:10:09.112252 KST | 네트워크 (PCAP; 클라우드 A의 BLOCK 로그와 밀리초 단위 일치) |

### 4.2 제어 평면 처리 시간과 데이터 평면 실효 차단 SLA 분리

네트워크 담당의 지적에 따라 **제어 평면 API 완료**와 **실제 HTTP 데이터 경로 차단 완료**를 엄격히 분리하여 보고한다:

1. **제어 평면(Control Plane) 파이프라인 처리 시간**:
   - 첫 공격 GET 송신(17:09:42.787941)부터 Lambda 실행 완료(17:09:52.314)까지: **9.526059초 (약 9.526초)**.
   - Lambda 순수 런타임은 **1.399초**이며, IPSet 갱신 및 Slack 카드 발송이 동일 런타임 구간(17:09:52 KST)에 완료됨.
   - 이는 위협 감지, 중앙 로그 수집, 보안 평가, Boto3 차단 지시 및 Slack 전파로 이어지는 **오케스트레이터 제어 파이프라인이 10초 이내에 정상 완료되었음**을 입증한다.

2. **데이터 평면(Data Plane) 실제 HTTP 차단 반영 시간**:
   - 첫 공격 GET 송신부터 최초 403 관측(17:10:09.112252)까지: **26.324311초**.
   - 다섯 번째 의심 GET(`/backup`) 송신부터 최초 403 관측까지: **20.549003초**.
   - Lambda 시작(17:09:50.915)부터 최초 403 관측까지: **18.197252초**.
   - Lambda 시작 약 11.222초 후인 17:10:02.136695 KST에도 실제 HTTP 200 응답이 관측되었다.

3. **엔지니어링 해석 및 SLA 선언 한계**:
   - 17:10:02(200 OK)와 17:10:09(403 Forbidden) 사이에는 클라이언트의 요청이 전송되지 않은 약 7초간의 프로브 공백이 존재한다. 따라서 최초 403 관측 시각(17:10:09.112)을 정확한 정책 적용 개시 시각으로 단정하지 않는다.
   - 확인된 사실은 IPSet 갱신 완료가 기록된 17:09:52 KST와 최초 403 관측 17:10:09.112252 KST 사이에 최대 약 17초의 관측 간격이 있다는 점이다. 갱신 완료 시각이 초 단위이고 중간 프로브가 없으므로, 이 간격 전체를 확정된 WAF 전파 지연으로 단정하지 않는다.
   - 따라서 **제어 평면 처리 완료(9.526초)만을 근거로 "전체 HTTP 차단 경로의 10초 SLA를 완전 입증했다"고 과장하지 않으며**, 제어 파이프라인 10초 완료 및 데이터 평면 26.3초 실효 차단 확인으로 객관적 범위를 명시한다.

---

## 5. Slack Block Kit 상황 전파 실측 검증

### 5.1 Slack 발송 메타데이터
- **발송 시각**: **2026-10-16 17:09:52 KST**
- **응답 상태**: HTTP 200 OK (전파 성공)
- **전파 채널**: `#webhook`

### 5.2 보안 탐지 매퍼 연계 Block Kit 카드 렌더링 검증

실제 운영 파이프라인에서는 보안 전담 모듈의 결정론적 매퍼(`map_threat_to_incident`)가 생성한 `IncidentReport`를 기반으로 `src/reporter/slack_notifier.py`가 카드를 조립한다.

#### 매퍼 연계 테스트 재구성 입력

아래 객체는 `map_threat_to_incident`와 `build_slack_payload`의 연계를 검증하기 위해 단위 테스트에서 주입한 **합성 입력**이다. `INC-TEST-WAF-7160`은 테스트 식별자이며 17:09:52 운영 발송의 실제 `incident_id`가 아니다. 운영 발송에 대해서는 HTTP 200 성공만 확인됐고, 같은 RequestId와 연결되는 메시지 원본/사건 ID는 확보하지 못했다.

```json
{
  "incident_id": "INC-TEST-WAF-7160",
  "rule_name": "Web Directory Scanning",
  "source_ip": "3.26.171.60",
  "remediation_action": "BLOCK_WAF",
  "remediation_result": {
    "waf_blocked": true,
    "quarantine_applied": false,
    "iam_revoked": false
  }
}
```

#### 합성 입력 기반 카드 렌더링 섹션 대조
1. **Header Block**:
   - `🚨 [CloudShield] 침해사고 긴급 탐지 및 자동 대응 알림`
2. **Summary Block (`summary_ko`)**:
   - `*사고 요약:*\n관측 출발지 IP 3.26.171.60에서 웹 디렉터리 열거 정황이 감지되었습니다. WAF IP 차단을 요청하며, 실제 차단 결과와 자원 노출 여부는 별도 확인이 필요합니다.`
3. **Fields Block (핵심 식별자)**:
   - `*사건 ID (incident_id):*\n`INC-TEST-WAF-7160``
   - `*공격 유형 (rule_name):*\nWeb Directory Scanning`
   - `*출발지 IP (source_ip):*\n`3.26.171.60``
   - `*위험도 (risk_level):*\n*HIGH*`
   - `*타깃 식별자:*\n`i-027b9d94be16b0d77``
   - `*대응 조치 (remediation_action):*\n*BLOCK_WAF*`
4. **공격 대상 계정 Block**:
   - `*공격 대상 계정:*\n없음 (단일 호스트 스캔)`
5. **인프라 원자적 차단 집행 현황 (`RemediationResult` 연계)**:
   - `• L4 EC2 네트워크 격리: ℹ️ 격리 미대상`
     *(Why: Web L7 공격은 웹 서버 가용성을 유지해야 하므로 L4 SG 차단은 미수행)*
   - `• L7 WAFv2 IP 차단: ✅ IPSet 차단 완료 (/32)`
     *(Why: WAFv2 IPSet에 공격자 3.26.171.60/32가 정상 등록됨)*
   - `• Identity IAM 세션 무효화: ℹ️ 미대상 (SSH 시나리오 제외)`
6. **SecOps 권고 조치 Block**:
   - `1. 출발지 IP 3.26.171.60/32를 WAF IPSet에 등록하여 HTTP·HTTPS 접근 차단`
   - `2. Nginx 원문 로그와 WAF 차단 결과를 확인하고 민감 자원 노출 여부 점검`
   - `3. 공유 출구 IP의 정상 사용자 영향 및 오탐 여부 확인`
7. **Context Block**:
   - `MITRE ATT&CK: `T1595.003` | CloudShield 10-Second Auto-Remediation Pipeline`

---

## 6. 분산 인프라 5대 비기능 제약 사후 검증

1. **런타임 수명주기 및 상태성 (Runtime Lifecycle)**:
   - Slack 알림 및 수집 지연 계측 로직은 상태 비저장 순수 함수로 동작하여 인메모리 프로세스 간 잔여 객체 오염 없이 완결됨.
2. **스토리지 물리적 상한선 (Storage Boundary)**:
   - Block Kit 필드 500자 / 헤더 150자 상한 및 수집 지연 분석 입력 32MB / 10만 건 상한을 완벽히 준수함.
3. **데이터 일관성 모델 (Consistency Model)**:
   - CloudWatch Logs의 불변 `ingestionTime`을 단일 기준 시각으로 채택하여 조회 네트워크 지연에 따른 관측 왜곡을 방지함.
4. **비동기 스트림 순서 역전 (Out-of-Order Delivery)**:
   - 계산기는 eventId 기반 중복 제거와 이벤트 시각 기반 집계를 지원한다. 이번 운영 실행의 원본 eventId가 없어 실제 중복/순서 역전 여부는 미검증이다.
5. **장애 격리 및 에러 전파 (Failure Escalation)**:
   - Slack Webhook은 HTTP 200 OK로 정상 수신되었으며, 통신 장애 발생 시 상위 오케스트레이터의 차단 프로세스를 중단시키지 않고 격리되도록 단위 테스트로 검증됨.

---

## 7. 결론

- **수집 지연**: 적용 설정상 로그 대상은 14건이나, FilterLogEvents 원본이 없어 실제 p50/p95/max와 3초 목표 충족 여부는 미검증이다. 1,815/1,825ms 값은 계산기 합성 회귀 테스트 결과로만 보존한다.
- **상황 전파**: 17:09:52 KST의 Slack HTTP 200 성공은 확인했다. 보안 매퍼 출력(`Web Directory Scanning`, `T1595.003`)과 L7 완료/L4 미대상 카드 렌더링은 합성 incident_id를 사용한 단위 테스트로 검증했으며, 실제 운영 메시지 원본과 incident_id는 미확보다.
- **파이프라인 대응 시간**: 첫 공격 GET부터 Lambda 종료 및 Slack 발송까지 **제어 평면 9.526초**로 오케스트레이터 10초 대응을 입증했다. 첫 GET부터 최초 HTTP 403 관측까지는 **26.324초**였으나, 중간 프로브 공백 때문에 정확한 WAF 정책 적용 시각과 순수 전파 지연은 확정하지 않는다.
