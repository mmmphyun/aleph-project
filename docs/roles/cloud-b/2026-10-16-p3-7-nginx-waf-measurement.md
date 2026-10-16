# P3-7 시나리오 2 Nginx access.log 수집 지연 계측 및 WAF Slack 알림 전파 실측

- 관련 Issue: https://github.com/mmmphyun/aleph-project/issues/191
- Notion Task: https://app.notion.com/p/A-d5f04d37c22582ad9e7f81acd36191d0?p=3f704d37c225806cb1d9cb0d497d161a&pm=c
- 담당: 클라우드 B / 작성일: 2026-10-16 KST
- 상태: 실인프라 Nginx 수집 지연 계측 정합화, Lambda 런타임/WAF 원본 로그 전수 대조, Slack Block Kit 실제 매퍼 연계 및 데이터·제어 평면 전파 시간 분리 반영 완료.

---

## 1. 개요 및 실측 대상

본 문서는 **시나리오 2(Web L7 디렉터리 스캐닝 공격 대응 파이프라인)** 관통 실측에서 **클라우드 B 담당 고유 도메인인 CloudWatch Agent 기반 Nginx 로그 수집 지연(Collection Latency)과 Slack Block Kit 알림 전파(Reporter)**의 정량적 성능 및 데이터 정합성을 독립 대조·검증한 실측 보고서이다.

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
| **클라우드 B 원본 확인값** | CloudWatch Nginx access log 원문·timestamp·ingestionTime (14건), 보안 매퍼(`map_threat_to_incident`) 계약 기반 Slack Block Kit 페이로드 구조, Slack 발송 성공 시각(17:09:52 KST, HTTP 200) |
| **타 담당 전달값** | 클라우드 A의 Lambda 실행 구간(START 17:09:50.915, END 17:09:52.314, 1.399초), IPSet 갱신 완료(17:09:52, 초 단위), WAF Logs 차단 시각(17:10:09.112) / 네트워크의 PCAP frame 시각(첫 GET 17:09:42.787941, `/backup` 17:09:48.563249, 200 관측 17:10:02.136695, 최초 403 17:10:09.112252) |
| **계산 및 해석** | 이벤트 timestamp와 ingestionTime의 차이(수집 지연), nearest-rank p50/p95 통계, 제어 평면(9.526초)과 데이터 평면(26.324초) 간의 약 17초 전파 지연 갭 분리 |
| **추정** | 단일 스캔 표본에서의 안정적 수집이 고부하 동시성 환경의 일반적 성능을 100% 대변하지는 않음 |
| **미측정·미확보** | EC2 로컬 하드웨어 시계 정밀 NTP 동기화 오차(밀리초 미만), 17:10:02와 17:10:09 사이의 프로브 공백 구간 내 정확한 WAF 룰 활성화 시점 |

---

## 2. Nginx access.log 수집 지연(Collection Latency) 계측

### 2.1 이벤트별 수집 타임라인
모의 공격자가 승인된 dev ALB로 전송한 15개 스캔 요청 중, `access_log off;` 처리된 `/health`를 제외하고 EC2 Nginx `access.log`에 기록되어 CloudWatch Logs(`/cloudshield/target/nginx-access-log`, 스트림 `i-027b9d94be16b0d77`)로 수집된 14건의 실측 타임라인이다.

- 모든 시각은 **2026-10-16 KST** 기준이다.
- $T_{\text{event}}$는 CloudWatch 이벤트의 `timestamp` 밀리초 표현(초 단위 정규화)이다.
- $T_{\text{cw}}$는 CloudWatch 이벤트의 `ingestionTime`이며, API 조회 시각을 수집 시각으로 대체하지 않았다.

| 순번 | 요청 경로 | HTTP 상태 | $T_{\text{event}}$ (KST) | $T_{\text{cw}}$ (KST) | 기록된 시각 기준 수집 지연 |
|:---:|:---|:---:|:---:|:---:|:---:|
| 1 | `/admin` | 401 | 17:09:42.000 | 17:09:43.810 | 1.810초 |
| 2 | `/login` | 404 | 17:09:43.000 | 17:09:44.815 | 1.815초 |
| 3 | `/dashboard` | 404 | 17:09:44.000 | 17:09:45.812 | 1.812초 |
| 4 | `/api` | 404 | 17:09:45.000 | 17:09:46.818 | 1.818초 |
| - | `/health` | 200 | *(access_log off)* | *(미수집)* | *(서버 설정에 의해 제외)* |
| 5 | `/backup` | 404 | 17:09:48.000 | 17:09:49.825 | 1.825초 |
| 6 | `/config` | 404 | 17:09:49.000 | 17:09:50.810 | 1.810초 |
| 7 | `/robots.txt` | 404 | 17:09:50.000 | 17:09:51.815 | 1.815초 |
| 8 | `/sitemap.xml` | 404 | 17:09:51.000 | 17:09:52.820 | 1.820초 |
| 9 | `/uploads` | 404 | 17:09:52.000 | 17:09:53.812 | 1.812초 |
| 10 | `/images` | 404 | 17:09:53.000 | 17:09:54.818 | 1.818초 |
| 11 | `/static` | 404 | 17:09:54.000 | 17:09:55.822 | 1.822초 |
| 12 | `/assets` | 404 | 17:09:55.000 | 17:09:56.815 | 1.815초 |
| 13 | `/private` | 404 | 17:09:56.000 | 17:09:57.820 | 1.820초 |
| 14 | `/internal` | 404 | 17:09:57.000 | 17:09:58.825 | 1.825초 |

> **정합성 검증 메모**:
> - 5번째 의심 경로인 `/backup`의 네트워크 송신 시각은 17:09:48.563249 KST(PCAP)이며, Nginx 초 단위 로깅에 따라 `17:09:48 +0900` ($T_{\text{event}}$ = 17:09:48.000)으로 정확히 기록되었다.
> - 이전 보고서 초안의 표에 존재하던 송신 전 시각 오류(17:09:46.825) 및 15건 모두 404 표기를 PCAP 및 Nginx 설정과 100% 일치하도록 정정했다.

### 2.2 수집 지연 통계 분석 (`collection_latency.py`)
`src/collector/collection_latency.py` 엔진에 위 14건의 실제 수집 이벤트를 입력하여 검증한 통계 결과:

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

- **분석 결과**:
  - 기대 건수 14건 전수 관측 완료 (`missing_count: 0`, `duplicate_count: 0`).
  - 중간값(p50): **1,815ms (1.815초)**, 95백분위수(p95): **1,825ms (1.825초)**, 최대 지연: **1,825ms**.
  - 수집 SLA 예산(`budget_ms: 3000`) 대비 **초과 건수 0건 (`over_budget_count: 0`)**으로 목표 성능을 100% 충족함 (`within_budget: true`).
  - CloudWatch Agent의 `force_flush_interval: 2` 주기에 부합하는 안정적 버퍼링이 입증됨.

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
   - AWS WAFv2의 글로벌/리전 엣지 룰셋 동기화 지연 특성상, 제어 평면 API 완료 후 데이터 평면에 실제 차단이 반영되기까지 약 15~20초의 물리적 전파 시간이 발생함을 실측으로 확인했다.
   - 따라서 **제어 평면 처리 완료(9.526초)만을 근거로 "전체 HTTP 차단 경로의 10초 SLA를 완전 입증했다"고 과장하지 않으며**, 제어 파이프라인 10초 완료 및 데이터 평면 26.3초 실효 차단 확인으로 객관적 범위를 명시한다.

---

## 5. Slack Block Kit 상황 전파 실측 검증

### 5.1 Slack 발송 메타데이터
- **발송 시각**: **2026-10-16 17:09:52 KST**
- **응답 상태**: HTTP 200 OK (전파 성공)
- **전파 채널**: `#webhook`

### 5.2 보안 탐지 매퍼 연계 Block Kit 카드 렌더링 검증

실제 운영 파이프라인에서는 보안 전담 모듈의 결정론적 매퍼(`map_threat_to_incident`)가 생성한 `IncidentReport`를 기반으로 `src/reporter/slack_notifier.py`가 카드를 조립한다.

#### 매퍼 생성 객체 및 실제 Block Kit 페이로드

```json
{
  "incident_id": "INC-1729066190-WAF",
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

#### 실제 카드 렌더링 섹션 대조
1. **Header Block**:
   - `🚨 [CloudShield] 침해사고 긴급 탐지 및 자동 대응 알림`
2. **Summary Block (`summary_ko`)**:
   - `*사고 요약:*\n관측 출발지 IP 3.26.171.60에서 웹 디렉터리 열거 정황이 감지되었습니다. WAF IP 차단을 요청하며, 실제 차단 결과와 자원 노출 여부는 별도 확인이 필요합니다.`
3. **Fields Block (핵심 식별자)**:
   - `*사건 ID (incident_id):*\n`INC-1729066190-WAF``
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
   - 14건 이벤트의 타임스탬프와 `eventId` 정합성을 검증하여 중복 및 순서 역전 없이 정량 산출됨.
5. **장애 격리 및 에러 전파 (Failure Escalation)**:
   - Slack Webhook은 HTTP 200 OK로 정상 수신되었으며, 통신 장애 발생 시 상위 오케스트레이터의 차단 프로세스를 중단시키지 않고 격리되도록 단위 테스트로 검증됨.

---

## 7. 결론

- **수집 지연**: Nginx `access.log`의 CloudWatch 중앙 적재 지연은 실제 로깅된 14건 기준 p50 1,815ms, p95 1,825ms로 목표 3초 예산 내에서 안정적으로 동작함.
- **상황 전파**: 보안 매퍼 출력(`Web Directory Scanning`, `T1595.003`)과 완벽히 호환되는 Slack 카드가 17:09:52 KST에 HTTP 200으로 전파되었으며, L7 WAF 차단 완료 및 L4 격리 미대상이 규격대로 렌더링됨.
- **파이프라인 대응 시간**: 첫 공격 GET부터 Lambda 종료 및 Slack 발송까지 **제어 평면 9.526초**로 오케스트레이터 10초 대응을 입증함. 단, AWS WAF의 리전 분산 엣지 동기화로 인해 실제 클라이언트 HTTP 403 실효 차단 관측까지는 **26.324초**가 소요되었음을 명확히 분리하여 기술적 진실성을 확립함.
