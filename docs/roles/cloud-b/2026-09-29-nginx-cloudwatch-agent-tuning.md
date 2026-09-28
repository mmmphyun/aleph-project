# [클라우드 B] Nginx access.log CloudWatch Agent 수집 경로 및 버퍼링 튜닝 명세서

- **작성일**: 2026-09-29
- **작성자**: 클라우드 B 담당 (`@wkdtlgns99-cell`)
- **연계 티켓**: [#82 Nginx access.log CloudWatch Agent 수집 경로 및 버퍼링 튜닝 명세 작성](https://github.com/mmmphyun/aleph-project/issues/82)
- **1차 리뷰어**: 네트워크 담당 (`@RockCandy444`)

---

## 1. 개요 및 10초 관통 파이프라인 수집 SLA (Why)

CloudShield의 프로젝트 핵심 목표는 **"단일 10초 관통 자동 대응 파이프라인"**을 증빙하는 것입니다.
`공격 발생(Hydra/Nmap/Curl) -> 타깃 서버(EC2) -> CW Agent 중앙 수집 -> Lambda 오케스트레이터(탐지/차단) -> 다중 계층 원자적 차단(L4 SG / L7 WAF) -> Slack 전파`의 전체 E2E 타임라인에서 수집 단계(Log Collection)에 할당된 시간 예산(Time Budget)은 **최대 3초 이내**입니다.

기존 CloudWatch Agent 기본 설정(로그 버퍼링 플러시 간격 5초)을 그대로 사용할 경우, 공격 로그가 인스턴스 로컬 디스크에 기록된 후 중앙 CloudWatch Logs로 스트리밍되기까지 최대 5초 이상의 수집 지연이 발생하여 10초 관통 SLA를 위협할 수 있습니다.

본 명세는 다음을 달성하기 위한 구체적인 인프라 및 전처리 튜닝 엔지니어링을 정의합니다:
1. **CloudWatch Agent 버퍼링 튜닝 (`force_flush_interval: 2`)**: 메모리 버퍼 플러시 주기를 2초로 강제하여 수집 지연 3초 이내 SLA 엄격 보장.
2. **Nginx access.log 다중 스트림 격리 수집**: 기존 SSH 인증 로그(`/var/log/auth.log`)와 더불어 L7 웹 공격 로그(`/var/log/nginx/access.log`)를 독립 수집 파이프라인으로 분리.
3. **타임스탬프 파싱 정합성**: Nginx `$time_local` 포맷과 CloudWatch Agent `%d/%b/%Y:%H:%M:%S %z` 디렉티브를 정합화하여 로그 순서 역전(Out-of-order) 방지.
4. **멀티 스트림 라우터 및 At-least-once 멱등성 보장**: Lambda 수신 페이로드를 logGroup에 따라 자동 분기하고, 재시도로 인한 중복 이벤트 인입을 차단.
5. **L7 WAF 차단 전용 Slack Block Kit 카드 구현**: L7 Web 공격 탐지 및 WAF IPSet 차단 집행 결과를 관제 센터에 즉각 시각화.

---

## 2. CloudWatch Agent 버퍼링 튜닝 및 수집 경로 (`amazon-cloudwatch-agent.json`)

### 2.1 JSON 구성 명세
```json
{
  "agent": {
    "metrics_collection_interval": 60,
    "run_as_user": "root"
  },
  "logs": {
    "logs_collected": {
      "files": {
        "collect_list": [
          {
            "file_path": "/var/log/auth.log",
            "log_group_name": "/cloudshield/target/auth-log",
            "log_stream_name": "{instance_id}",
            "timestamp_format": "%Y-%m-%dT%H:%M:%S.%f%z"
          },
          {
            "file_path": "/var/log/nginx/access.log",
            "log_group_name": "/cloudshield/target/nginx-access-log",
            "log_stream_name": "{instance_id}",
            "timestamp_format": "%d/%b/%Y:%H:%M:%S %z"
          }
        ]
      }
    },
    "force_flush_interval": 2
  }
}
```

### 2.2 핵심 파라미터 설계 근거 (Why & Constraints)
1. **`force_flush_interval: 2`**:
   - CloudWatch Agent는 디스크 I/O 최적화를 위해 이벤트를 메모리 버퍼에 보관했다가 배치 전송합니다.
   - 기본값은 5초이나, 본 프로젝트에서는 `force_flush_interval`을 **2초**로 설정하여 로그 라인 발생 후 최대 2초 이내에 AWS CloudWatch Logs API(`PutLogEvents`) 호출을 강제합니다.
   - 단, 버퍼 크기가 1MB에 도달하면 `force_flush_interval` 만료 전이라도 즉시 전송됩니다.
2. **OS 커널 inotify 이벤트 감시**:
   - Linux 환경에서 CloudWatch Agent는 파일 수정 이벤트를 실시간 감지하기 위해 Linux 커널의 `inotify` 서브시스템을 활용합니다.
   - 로그 파일 끝에 새 라인이 추가(append)되는 즉시 Agent 버퍼로 읽어 들이므로, 폴링 방식의 디스크 오버헤드가 없으며 밀리초 단위로 버퍼에 적재됩니다.
3. **`timestamp_format: "%d/%b/%Y:%H:%M:%S %z"`**:
   - Nginx의 기본 `cloudshield_combined` 포맷에 포함된 `$time_local` 필드(`[28/Sep/2026:11:52:38 +0000]`)를 파싱합니다.
   - Agent Go 파서의 `%z` 디렉티브는 콜론 없는 시간대 오프셋(`+0000`, `-0500`)과 100% 호환되므로 CloudWatch Logs 타임스탬프 색인이 정확하게 생성됩니다.

---

## 3. 멀티 스트림 라우터 및 At-least-once 멱등성 보장 (`cw_processor.py`)

### 3.1 다중 스트림 분기 라우팅 (`route_cw_logs`)
Lambda 위협 분석 오케스트레이터가 단일 진입점으로 CloudWatch Logs 구독 필터 이벤트를 수신할 때, `logGroup` 메타데이터를 기반으로 수신 스트림의 종류를 판별합니다:

```text
[CloudWatch Logs Subscription Filter]
               │
               ▼ (Base64 + Gzip Payload)
    [cw_processor.route_cw_logs]
               │
    ┌──────────┴──────────┐
    ▼                     ▼
logGroup: /auth-log   logGroup: /nginx-access-log
(stream_type: "auth") (stream_type: "nginx")
    │                     │
    ▼                     ▼
[SyslogAuthEvent]     [Nginx L7 / WAF 규칙 엔진]
```

### 3.2 At-least-once 전달 환경 대비 멱등성(Idempotency) 보장
CloudWatch Logs Subscription Filter는 분산 네트워크 환경에서 최소 1회(At-least-once) 전달을 보장하므로, 네트워크 재전송 또는 Lambda 타임아웃 재시도 시 동일한 로그 이벤트 배치가 재인입될 수 있습니다.

- **이벤트 ID 기반 중복 제거 (`deduplicate_log_events`)**:
  각 CloudWatchLogEvent에 부여된 고유 식별자(`id`)를 세션 또는 메모리 세트(`seen_event_ids`)에 기록하고, 중복 인입된 이벤트는 분석 윈도우 진입 전에 선제적으로 드롭(`dropped_duplicates`)합니다.
- 이를 통해 DynamoDB 인증 실패 윈도우 카운터의 비정상 중복 합산 및 오탐에 의한 과잉 차단을 원천 방지합니다.

---

## 4. L7 WAF 차단 전용 Slack Block Kit 카드 (`build_waf_slack_payload`)

### 4.1 UI 레이아웃 및 4대 필수 키 준수
L7 Web 공격 탐지 및 AWS WAFv2 IPSet /32 차단 집행 결과를 관제 센터 채널에 보고하는 전용 카드 레이아웃입니다:

1. **헤더**: `🛡️ [CloudShield] L7 WAF 웹 침해사고 탐지 및 차단 알림`
2. **사고 요약**: `*L7 웹 위협 요약:*` (500자 이내 안전 자르기)
3. **4대 필수 식별자 섹션 (`fields`)**:
   - `incident_id`: 사고 고유 식별자
   - `rule_name`: 공격 유형 (Web L7 Brute Force / Scanning 등)
   - `source_ip`: 차단된 공격자 IPv4 주소
   - `remediation_action`: 집행된 조치 (`BLOCK_WAF`)
   - `risk_level`: 위험도 (`HIGH`, `MEDIUM`, `LOW`)
   - `target_identifier`: 타깃 EC2 인스턴스 ID
4. **WAF 방어 계층 상세 섹션**:
   - WAF IPSet 명세 및 `/32` 차단 집행 결과(성공: ✅, 실패: ❌, 대기: ⏳) 가시화.
5. **공격 대상 엔드포인트 및 권고 조치**: 타깃 URL/엔드포인트 및 웹 보안 강화 권고사항 안내.
6. **컨텍스트 푸터**: MITRE ATT&CK 기법 번호 및 CloudShield 10초 관통 파이프라인 식별자.

---

## 5. 결론 및 1:1 짝꿍 리뷰 검증 포인트

- **네트워크 담당자 (`@RockCandy444`) 검증 포인트**:
  1. Nginx `access.log` 수집 경로 및 CloudWatch Logs 그룹명(`/cloudshield/target/nginx-access-log`)이 네트워크 모의 L7 스캐닝/스프레잉 공격 트래픽의 수용 경로와 일치하는가?
  2. `force_flush_interval: 2` 설정이 10초 관통 대응 시나리오에서 3초 이내 수집 SLA를 충족하는가?
