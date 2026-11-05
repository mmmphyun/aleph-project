# 로깅 및 SRE 관제 기술 포트폴리오 (클라우드 B)

<div align="center">

**CloudWatch Agent 수집 파이프라인, 이종 로그 스트림 라우터, Slack 2단계 알림 및 Grafana 4사분면 관제**

**담당 엔지니어: 시훈 ([@wkdtlgns99-cell](https://github.com/wkdtlgns99-cell))**  
*역할: 클라우드 시스템 및 SRE 관제 엔지니어*

</div>

---

## 1. 담당 도메인 개요 및 관제 R&R

클라우드 B는 CloudShield 파이프라인의 **타깃 서버 로깅 환경 구성, CloudWatch Agent 중앙 수집 버퍼 최적화, 이종 로그 스트림 역직렬화 및 라우팅 어댑터, 운영자 혼선 방지 Slack Block Kit 2단계 알림, Grafana 4사분면 SecOps 관제 대시보드 구축**을 전담했습니다.

공격 트래픽이 인입되었을 때 2초 이내에 오케스트레이터로 전달되도록 버퍼 레이턴시를 튜닝하고 차단 결과와 심층 분석 결과를 명확히 분리하여 운영자의 관제 가시성을 극대화했습니다.

---

## 2. 핵심 엔지니어링 딥다이브 (수집 파이프라인 & 가시성 아키텍처)

### 2.1 CloudWatch Agent 중앙 수집 튜닝 및 2초 버퍼 플러시 최적화
* **배경 및 지연 난제**:
  - CloudWatch Agent의 기본 설정은 비용 및 네트워크 최적화를 위해 로그를 수 분간 메모리에 버퍼링한 후 일괄 전송합니다.
  - 이로 인해 타깃 서버에 침해 공격이 발생해도 로그 전송이 지연되어 10초 이내 자동 차단 파이프라인이 즉시 가동되지 못하는 병목이 발생했습니다.
* **수집 주기 정밀 튜닝 및 TCO 고려**:
  - 타깃 인스턴스(/var/log/auth.log, /var/log/nginx/access.log)의 에이전트 설정(mazon-cloudwatch-agent.json)에서 플러시 대기 시간을 **2초**로 정밀 튜닝하여 파이프라인의 **이론적 최소 지연 한계**를 실측했습니다.
  - 로그 파일 회전 및 권한을 안정화하여 실인프라 공격 인입 시 수초 이내에 CloudWatch Subscription Filter를 통해 Lambda로 전달되도록 보장하되, 대규모 프로덕션 확장 시 PutLogEvents API 비용 및 스로틀링을 완화하기 위한 Fluent Bit 스트리밍 버퍼링 또는 Kinesis Data Firehose 배치가 보완 아키텍처로 요구됨을 함께 도출했습니다.

### 2.2 이종 로그 스트림 역직렬화 어댑터 및 인메모리 중복 제거
* **다중 로그 스트림 정형화**:
  - 단일 Lambda 오케스트레이터가 SSH 인증 로그(`SyslogAuthEvent`)와 Nginx 웹 접근 로그(`NginxAccessLogEvent`)를 모두 처리할 수 있도록 Base64 디코딩 및 Gzip 압축 해제 팩토리를 구현했습니다.
  - 로그 그룹 식별자에 따라 이벤트를 분기 라우팅하고 비정상 로그 라인 및 미등록 로그 그룹을 사전 필터링하는 방어적 어댑터(`cw_processor.py`)를 구축했습니다.
* **배치 내 중복 로그 필터링**:
  - CloudWatch Logs 전송 특성상 네트워크 재시도로 인한 동일 로그 중복 인입 가능성에 대비하여, 이벤트 ID 해시 집합을 기반으로 배치 내 인메모리 중복 제거를 수행했습니다.

### 2.3 지시 조치와 엔진 반환값을 분리한 Slack Block Kit 2단계 알림
* **운영자 혼선 방지 상태 모델**:
  - 기존 관제 알림이 단순히 "차단 요청됨"만을 보여주어 실제 인프라 적용 실패를 감지하지 못하는 결함을 개선했습니다.
  - 카드 UI에서 **'지시된 대응 조치'**와 Boto3 엔진이 반환한 **'실제 인프라 집행 상태(성공·실패·미완료·미대상)'**를 엄격히 분리 표기했습니다.
* **2단계 알림 및 SaaS 장애 격리**:
  - 1차 실시간 대응 카드: 탐지 사실과 L4 SG 격리 / L7 WAF 차단 성공 여부를 즉시 전파했습니다.
  - 2차 사후 분석 카드: EventBridge 백그라운드 분석 완료 시 동일한 `incident_id`로 상사 보고용 3단 분석 및 권고를 전달했습니다.
  - 제어 문자 이스케이프를 적용해 공격 문자열에 의한 의도치 않은 채널 멘션(@here, @channel) 공격을 방어하고 SaaS 네트워크 타임아웃 예외를 격리하여 핵심 차단 로직에 영향이 없도록 설계했습니다.

### 2.4 Grafana 4사분면 CloudWatch Logs Insights 관제 대시보드
* **SecOps 핵심 메트릭 시각화**:
  - **1사분면 (공격 인입)**: SSH 인증 실패 및 Nginx 4xx/5xx 인입 추이를 시각화했습니다.
  - **2사분면 (대응 소요 시간)**: 오케스트레이터 탐지 $\rightarrow$ 대응 반환 시간(max/p95: **2.7042s**)을 추적했습니다.
  - **3사분면 (LLM 분석 상태)**: Bedrock 분석의 enhanced 성공률 및 fallback 비율을 시각화했습니다.
  - **4사분면 (사건 처리 타임라인)**: 침해 인입부터 격리, 1차 알림, EventBridge, Bedrock 분석, 2차 알림까지 8단계 전 과정을 추적했습니다.

---

## 3. 핵심 정량 실측 성과 요약

<div align="center">

| 검증 항목 | 달성 지표 | 환경 및 측정 조건 | 단일 신뢰점 원본 |
| :--- | :---: | :--- | :---: |
| **수집 플러시 주기** | `2.0s` | CloudWatch Agent 버퍼 플러시 주기 정밀 튜닝 | [수집 레이턴시 보고서](2026-10-08-cloudwatch-collection-latency-report.md) |
| **관제 SLA 반환 시간** | `2.7042s` | Logs Insights 대응 소요 시간 max/p95 계측 | [P5-2 패널 검증서](2026-10-30-p5-2-panel-verification.md) |
| **사건 타임라인 추적** | `8단계 완결` | 단일 사건 ID 기준 차단-알림-분석 전 과정 추적 | [P5-2 패널 검증서](2026-10-30-p5-2-panel-verification.md) |
| **작업 카드 분담률** | `23%` | 노션 프로젝트 일정 DB 100개 카드 중 23개 전담 | [공식 노션 페이지](https://app.notion.com/p/A-d5f04d37c22582ad9e7f81acd36191d0) |

</div>

---

## 4. 로깅 및 관제 기술 보고서 목록 (총 17편 전수 링크)

1. [2026-09-09: 타깃 인스턴스(Ubuntu/Nginx) 환경 구성 및 초기화](2026-09-09-target-server-init.md)
2. [2026-09-14: CloudWatch Logs Subscription Filter 명세서](2026-09-14-subscription-filter-spec.md)
3. [2026-09-23: Slack 오케스트레이터 페이로드 규격 설계](2026-09-23-slack-orchestrator-payload-spec.md)
4. [2026-09-29: Nginx CloudWatch Agent 수집 튜닝 명세](2026-09-29-nginx-cloudwatch-agent-tuning.md)
5. [2026-09-29: Nginx 페이로드 디코더 및 다중 스트림 라우터 구축](2026-09-29-nginx-payload-decoder-and-multistream-router.md)
6. [2026-09-30: L7 WAF Slack 알림 카드 템플릿 설계](2026-09-30-l7-waf-slack-card-template.md)
7. [2026-10-08: CloudWatch 수집 레이턴시 측정 및 지연 보고서](2026-10-08-cloudwatch-collection-latency-report.md)
8. [2026-10-08: EC2 에이전트 배포 및 실환경 로깅 검증](2026-10-08-ec2-agent-deployment.md)
9. [2026-10-13: [P3-3a] SSH Lab 실습 계정 환경 구성](2026-10-13-p3-3a-ssh-lab-account.md)
10. [2026-10-14: [P3-4] 침해사고 수집 레이턴시 실측 결과](2026-10-14-p3-4-incident-measurement.md)
11. [2026-10-16: [P3-7] Nginx WAF 차단 이벤트 수집 실측](2026-10-16-p3-7-nginx-waf-measurement.md)
12. [2026-10-19: LLM 2차 사후 분석 Slack 카드 서식 명세](2026-10-19-llm-secondary-slack-card.md)
13. [2026-10-22: LLM 2차 Slack 카드 비동기 발송 모듈 구현](2026-10-22-llm-secondary-slack-sender.md)
14. [2026-10-23: [P4-2] Slack 2단계 순차 알림 실환경 계측 보고서](2026-10-23-p4-2-slack-sequential-measurement.md)
15. [2026-10-28: LLM 멀티블록 복구 카드 렌더러 설계](2026-10-28-llm-multiblock-recovery-card.md)
16. [2026-10-29: [P5-2] Grafana 관제 대시보드 및 Slack 실증](2026-10-29-p5-2-grafana-slack.md)
17. [2026-10-30: [P5-2] 실인프라 Grafana 패널 쿼리 검증 결과](2026-10-30-p5-2-panel-verification.md)
