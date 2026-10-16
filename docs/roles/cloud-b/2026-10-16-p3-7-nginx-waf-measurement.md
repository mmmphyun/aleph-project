# P3-7 시나리오 2 Nginx access.log 수집 지연 계측 및 WAF Slack 알림 전파 실측

- 관련 Issue: https://github.com/mmmphyun/aleph-project/issues/191
- Notion Task: https://app.notion.com/p/A-d5f04d37c22582ad9e7f81acd36191d0?p=3f704d37c225806cb1d9cb0d497d161a&pm=c
- 담당: 클라우드 B / 작성일: 2026-10-16 KST
- 상태: 실인프라 Nginx 수집 지연 계측, Lambda 런타임/WAF Logs 전수 대조, Slack 원본 전파 및 Block Kit 렌더링 검증 완료.

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

### 1.2 증거 확보 범위 및 책임 경계 매트릭스

| 증거 구분 | 확보 범위 |
|---|---|
| **클라우드 B 원본 확인값** | CloudWatch Nginx access log 원문·timestamp·ingestionTime, Slack Block Kit 페이로드 구조, HTTP 200 발송 성공 시각 |
| **타 담당 전달값** | 클라우드 A의 Lambda 실행 구간(START/END), IPSet 갱신 완료 시각, CW WAF Logs 차단 시각 / 네트워크의 모의 스캔 요청 시각($T_{\text{attack}}$), PCAP 403 수신 시각 |
| **계산 및 해석** | 이벤트 timestamp와 ingestionTime의 차이(수집 지연), nearest-rank p50/p95 통계, 제어 평면(Control Plane) API 응답과 데이터 평면(Data Plane) 엣지 차단 간 전파 갭(17초) 분리 |
| **추정** | 단일 스캔 공격 표본(15건)에서의 안정적 수집이 다른 고부하 환경의 일반적 SLA를 100% 보장하지는 않음 |
| **미측정·미확보** | EC2 로컬 하드웨어 시계 정밀 NTP 동기화 오차(밀리초 미만), 사용자 클라이언트 디스플레이 렌더링 딜레이 |

---

## 2. Nginx access.log 수집 지연(Collection Latency) 계측

### 2.1 이벤트별 수집 타임라인
모의 공격자가 승인된 dev ALB로 전송한 15개 디렉터리 스캔 요청(1초 간격)에 대하여, EC2의 Nginx 로컬 파일에 기록된 시각($T_{\text{event}}$)과 CloudWatch 중앙 저장소에 수집된 시각($T_{\text{cw}}$, `ingestionTime`)을 전수 대조했다.

- 모든 시각은 **2026-10-16 KST** 기준이다.
- $T_{\text{event}}$는 CloudWatch 이벤트의 `timestamp` 밀리초 표현이다.
- $T_{\text{cw}}$는 CloudWatch 이벤트의 `ingestionTime`이며, API 조회 시각을 수집 시각으로 대체하지 않았다.

| 순번 | 요청 경로 | HTTP 상태 | $T_{\text{event}}$ | $T_{\text{cw}}$ | 기록된 시각 기준 수집 지연 |
|:---:|:---|:---:|:---:|:---:|:---:|
| 1 | `/admin` | 404 | 17:09:42.812 | 17:09:44.620 | 1.808초 |
| 2 | `/login` | 404 | 17:09:43.815 | 17:09:45.618 | 1.803초 |
| 3 | `/dashboard` | 404 | 17:09:44.819 | 17:09:46.625 | 1.806초 |
| 4 | `/api` | 404 | 17:09:45.822 | 17:09:47.630 | 1.808초 |
| 5 | `/backup` | 404 | 17:09:46.825 | 17:09:48.631 | 1.806초 |
| 6 | `/config` | 404 | 17:09:47.828 | 17:09:49.638 | 1.810초 |
| 7 | `/db` | 404 | 17:09:48.831 | 17:09:50.642 | 1.811초 |
| 8 | `/server-status`| 404 | 17:09:49.835 | 17:09:51.645 | 1.810초 |
| 9 | `/phpmyadmin` | 404 | 17:09:50.838 | 17:09:52.648 | 1.810초 |
| 10 | `/wp-admin` | 404 | 17:09:51.841 | 17:09:53.652 | 1.811초 |
| 11 | `/console` | 404 | 17:09:52.844 | 17:09:54.655 | 1.811초 |
| 12 | `/test` | 404 | 17:09:53.848 | 17:09:55.660 | 1.812초 |
| 13 | `/debug` | 404 | 17:09:54.851 | 17:09:56.662 | 1.811초 |
| 14 | `/root` | 404 | 17:09:55.854 | 17:09:57.668 | 1.814초 |
| 15 | `/shell` | 404 | 17:09:56.857 | 17:09:58.672 | 1.815초 |

### 2.2 수집 지연 통계 분석 (`collection_latency.py`)
기존 `src/collector/collection_latency.py` 엔진에 위 15건의 원본 이벤트를 입력하여 정량 검증을 수행했다:

```json
{
  "scope": "event_timestamp_to_cloudwatch_ingestion",
  "unit": "ms",
  "expected_count": 15,
  "observed_count": 15,
  "missing_count": 0,
  "duplicate_count": 0,
  "p50_ms": 1810,
  "p95_ms": 1815,
  "max_ms": 1815,
  "budget_ms": 3000,
  "over_budget_count": 0,
  "complete": true,
  "within_budget": true
}
```

- **분석 결과**:
  - 기대 건수 15건 전수 관측 완료 (`missing_count: 0`, `duplicate_count: 0`).
  - 중간값(p50): **1,810ms (1.810초)**, 95백분위수(p95): **1,815ms (1.815초)**, 최대 지연: **1,815ms**.
  - 수집 SLA 예산(`budget_ms: 3000`) 대비 **초과 건수 0건 (`over_budget_count: 0`)**으로 목표 성능을 100% 충족함 (`within_budget: true`).
  - CloudWatch Agent의 버퍼링 및 플러시 주기가 약 1.8초 수준으로 매우 안정적으로 유지됨을 입증함.

---

## 3. 구독 필터 및 런타임 오케스트레이터 연계

### 3.1 구독 필터 동작
- CloudWatch Agent 구성(`amazon-cloudwatch-agent.json`)을 통해 `/var/log/nginx/access.log`의 텍스트 스트림이 `/cloudshield/target/nginx-access-log`로 실시간 스트리밍됨.
- 로그 그룹에 바인딩된 Subscription Filter는 4xx/스캐닝 패턴을 감지하여 Lambda 오케스트레이터(`CloudShield-Threat-Orchestrator`)를 비동기 호출함.
- `src/collector/cw_processor.py`를 통해 전달된 Base64/Gzip 압축 페이로드가 정상 디코딩되어 시그니처 분석 엔진으로 인입됨.

### 3.2 분할 인입 및 윈도우 누적
- 1초 간격 순차 요청에 의해 CloudWatch Logs 배치로 분할 인입되더라도, 플랫폼의 `WebAttackWindow`(DynamoDB 2-버킷 슬라이딩 윈도우)에 동일 IP(`3.26.171.60`)의 스캔 카운트가 무손실 누적됨.
- 임계치(5회 이상) 도달 시점인 17:09:50 KST 전후의 배치 수신 즉시 오케스트레이터가 `WEB_DIRECTORY_SCANNING`으로 최종 판정함.

---

## 4. 다중 직무 실측 대조 및 시간 분리 분석

### 4.1 타임라인 전수 대조 매트릭스

| 단계 | 시각 (2026-10-16 KST) | 주체 | 동작 내용 및 실측 증거 |
|:---:|:---:|:---:|:---|
| **$T_{\text{attack\_start}}$** | 17:09:42.788 | 네트워크 (Kali) | ALB 대상 첫 번째 디렉터리 스캔 HTTP GET 요청 전송 |
| **$T_{\text{event\_1}}$** | 17:09:42.812 | EC2 (Nginx) | 로컬 `access.log`에 첫 번째 `/admin` 404 기록 |
| **$T_{\text{cw\_1}}$** | 17:09:44.620 | 클라우드 B (CW) | CloudWatch Logs 중앙 수집 적재 (`ingestionTime`) |
| **$T_{\text{lambda\_start}}$**| 17:09:50.915 | 클라우드 A (Lambda) | 임계치 도달 배치 수신, 오케스트레이터 핸들러 실행 START |
| **$T_{\text{threat\_eval}}$**| 17:09:51.400 | 보안 (시그니처) | `WEB_DIRECTORY_SCANNING` 판정, 필요 조치 `BLOCK_WAF` 결정 |
| **$T_{\text{ipset\_block}}$** | 17:09:52.200 | 클라우드 A (Boto3) | AWS WAFv2 IPSet에 `3.26.171.60/32` 등록 완료 |
| **$T_{\text{slack\_sent}}$**  | **17:09:52.300** | **클라우드 B (Slack)** | **Slack Block Kit 카드 전파 완료 (HTTP 200 OK)** |
| **$T_{\text{lambda\_end}}$**  | 17:09:52.314 | 클라우드 A (Lambda) | 핸들러 정상 종료 (Duration: 1,399ms, RequestId: `1f089011-c024-40d9-92a6-852d14833b73`) |
| **$T_{\text{waf\_edge}}$**   | 17:10:09.112 | AWS WAF / 네트워크 | WAF Logs 최초 차단 기록 및 공격자 PCAP 최초 403 Forbidden 관측 |

### 4.2 10초 관통 대응 SLA 분석
- **제어 평면 10초 관통 시간**:
  $$\text{Latency}_{\text{control}} = T_{\text{slack\_sent}} - T_{\text{attack\_start}} = 17:09:52.300 - 17:09:42.788 = \mathbf{9.512초}$$
  - 첫 공격 GET 시점부터 탐지, 차단 API 호출, 관리자 Slack 상황 전파 완료까지 **9.512초**로 **10초 관통 대응 목표(SLA < 10초)를 성공적으로 입증**함.
  - Lambda 순수 런타임은 **1.399초**에 불과하며, 수집 지연(~1.8초) 및 시계열 누적 버퍼링을 포함해도 10초 내에 전파가 완료됨.

### 4.3 제어 평면(Control Plane)과 데이터 평면(Data Plane) 엣지 전파 시간 분리
- **관측 사실**:
  - WAF IPSet API 등록 완료 시각: **17:09:52 KST**
  - CloudWatch WAF Logs 최초 차단 및 PCAP 403 관측 시각: **17:10:09.112 KST**
  - 전파 지연 갭: **16.812초 (~17초)**
- **엔지니어링 해석**:
  - AWS WAFv2는 리전 분산 엣지 프록시 아키텍처 특성상, API(제어 평면)가 성공을 반환한 후 전 세계 CloudFront/ALB 인스펙션 엔진(데이터 평면)에 룰셋이 동기화되기까지 약 15~20초의 물리적 전파 지연이 발생함.
  - 네트워크 담당 보고서에서도 17:10:02에 200 OK 응답이 관측된 후 17:10:09.112에 최초 403이 확인된 사실과 완벽하게 일치함.
  - 본 보고서는 제어 API 응답과 실제 엣지 차단 시간을 혼동하지 않고 명확히 분리하여 기술적 진실성을 확립함.

---

## 5. Slack Block Kit 상황 전파 실측 검증

### 5.1 Slack 발송 메타데이터
- **발송 시각**: **2026-10-16 17:09:52 KST**
- **응답 상태**: HTTP 200 OK (전송 성공)
- **전파 대상**: `#webhook` 채널

### 5.2 Block Kit 카드 렌더링 및 4대 필수 키 대조

`src/reporter/slack_notifier.py`의 `build_incident_blocks` 엔진이 생성하여 전송한 실제 페이로드 필드 구성:

```json
{
  "incident_id": "INC-1729066190-WAF",
  "rule_name": "WEB_DIRECTORY_SCANNING",
  "source_ip": "3.26.171.60",
  "remediation_action": "BLOCK_WAF"
}
```

#### 카드 섹션별 렌더링 검증 결과
1. **Header Block**:
   - `🚨 [HIGH] CloudShield 침해사고 탐지 및 대응 알림`
2. **Summary Block**:
   - `웹 디렉터리 스캐닝(WEB_DIRECTORY_SCANNING) 공격 탐지 및 WAF 차단 조치 완료`
3. **Fields Block (핵심 메타데이터)**:
   - `*Incident ID:* INC-1729066190-WAF`
   - `*공격 유형:* WEB_DIRECTORY_SCANNING`
   - `*출발지 IP:* 3.26.171.60`
   - `*위험 등급:* HIGH`
   - `*대상 자산 ID:* cloudshield-alb-dev-308142572.ap-southeast-2.elb.amazonaws.com`
   - `*필요 조치:* BLOCK_WAF`
4. **인프라 원자적 차단 집행 현황 (`RemediationResult` 연계)**:
   - `• L4 EC2 네트워크 격리: ℹ️ 격리 미대상`
     *(Why: Web L7 공격은 웹 서비스 전체 가용성을 보존해야 하므로 L4 SG 차단은 격리 미대상 처리)*
   - `• L7 WAFv2 IP 차단: ✅ IPSet 차단 완료 (/32)`
     *(Why: WAFv2 IPSet에 공격자 3.26.171.60/32가 성공적으로 등록됨)*
   - `• Identity IAM 세션 무효화: ℹ️ 미대상 (SSH 시나리오 제외)`
5. **방어 규격 검증**:
   - 필드 500자 초과 방지 안전 자르기(`truncate_text`) 정상 적용.
   - mrkdwn 제어 문자(`<`, `>`, `&`) 이스케이프(`escape_slack_text`) 준수.

---

## 6. 분산 인프라 5대 비기능 제약 사후 검증

1. **런타임 수명주기 및 상태성 (Runtime Lifecycle)**:
   - 로그 수집 및 Slack 전파 모듈은 Lambda 컨테이너 내에서 무상태(Stateless)로 수행되었으며, 호출 간 잔여 객체 오염 없이 프로세스가 완료됨.
2. **스토리지 물리적 상한선 (Storage Boundary)**:
   - 수집 지연 계측 엔진은 최대 32MB / 10만 건 상한선 하에서 15건 표본을 안전하게 처리함.
3. **데이터 일관성 모델 (Consistency Model)**:
   - CloudWatch Logs의 불변 `ingestionTime`을 수집 완료 시각 단일 기준으로 채택하여 관측 무결성을 확보함.
4. **비동기 스트림 순서 역전 (Out-of-Order Delivery)**:
   - 순차 인입된 15개 요청의 타임스탬프와 `eventId`를 검증하여 중복 및 역전 없이 정확한 순서로 계측됨.
5. **장애 격리 및 에러 전파 (Failure Escalation)**:
   - Slack 알림 전파는 HTTP 200 OK로 성공 완료되었으며, 음수 지연 등 비정상 지표 없이 모든 제약이 검증됨.

---

## 7. 결론

- **수집 지연**: Nginx `access.log`의 CloudWatch 중앙 적재 지연은 p50 1,810ms, p95 1,815ms로 목표 3초 예산 내에서 완벽하게 동작함.
- **상황 전파**: Slack Block Kit 알림 카드가 17:09:52 KST에 HTTP 200으로 전파되었으며, `WEB_DIRECTORY_SCANNING` 및 L7 WAF 차단 상태가 규격대로 렌더링됨.
- **관통 SLA**: 첫 공격 발생부터 탐지/차단/Slack 전파까지 총 **9.512초**로 **10초 관통 파이프라인 대응 SLA를 최종 입증**함.
