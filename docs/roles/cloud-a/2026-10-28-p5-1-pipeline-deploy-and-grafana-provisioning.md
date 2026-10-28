# [P5-1] 보고서·복구 파이프라인 실인프라 배포 및 Grafana 컨테이너 프로비저닝 보고서

- **작성 일시**: 2026-10-28 KST
- **작성자**: 클라우드 A (플랫폼 전담 @mmmphyun)
- **관련 티켓**: [P5-1] [클라우드 A] 보고서·복구 파이프라인 실인프라 배포 및 Grafana 컨테이너 프로비저닝 구축 (https://notion.so/40504d37c22581bbbc3be47152a63e23)
- **관련 Issue / PR**: Issue #225
- **배포 리전**: `ap-southeast-2` (시드니)

---

## 1. 개요 및 배경

Track 1(PR #218, #220, #223, #224)에서 완성된 4대 직무의 코어 산출물(3단 상사 보고서 LLM 프롬프트·파서, Slack Block Kit 멀티블록 렌더러 및 복구 결과 카드, L4/L7 원자적 롤백 복구 엔진, 정밀 구간 지연 계측기)을 단일 AWS Lambda 런타임 아티팩트(`orchestrator.zip`)로 통합 패키징하고, CloudWatch Logs/Metrics ReadOnly 권한 기반의 코드형 Grafana(`grafana/grafana-oss`) 무상태 프로비저닝 환경을 구축하였습니다.

수동 UI 조작에 의존하던 기존 관제 환경을 탈피하여 데이터소스(`cloudwatch.yaml`), 대시보드 프로바이더(`dashboards.yaml`), 도커 컴포즈(`docker-compose.yml`)를 코드로 버전 관리함으로써, 어느 호스트에서나 `docker compose up -d` 명령어 하나로 동일한 SecOps 관제 환경을 100% 재현할 수 있도록 표준화하였습니다.

---

## 2. 배포 및 프로비저닝 산출물 명세

| 계층 | 파일 / 리소스 경로 | 유형 및 스펙 | 비고 |
| :--- | :--- | :--- | :--- |
| **Lambda Bundle** | `infra/terraform/modules/lambda/build/orchestrator.zip` | 2,737,982 bytes (Linux x86_64 ELF) | 1차 오케스트레이터 및 2차 LLM 분석 워커 공통 번들 |
| **Worker Enhancement** | `src/remediation/llm_worker.py` | `require_executive_format` 지원, `_log_analysis_status` 연동 | PR #224 상태 로깅 및 PR #223 멀티블록 알림 연계 |
| **IAM Policy** | `infra/terraform/main.tf` (`aws_iam_policy.grafana_cloudwatch_readonly`) | `CloudShield-Grafana-CloudWatch-ReadOnly-dev` | Logs/Metrics ReadOnly 최소 권한 정책 |
| **Grafana Container** | `infra/grafana/docker-compose.yml` | `grafana/grafana-oss:11.2.0` (포트 3000) | 무상태 볼륨 마운트 및 호스트 AWS 자격증명 연동 |
| **Data Source as Code** | `infra/grafana/provisioning/datasources/cloudwatch.yaml` | `uid: cloudshield-cloudwatch` (CloudWatch) | ap-southeast-2 리전 기본 바인딩 |
| **Dashboard Provider** | `infra/grafana/provisioning/dashboards/dashboards.yaml` | Provider Name: `CloudShield Dashboards` | `/var/lib/grafana/dashboards` 자동 로드 |
| **Dashboard Skeleton** | `infra/grafana/dashboards/cloudshield-secops-overview.json` | `uid: cloudshield-overview` | SecOps 기본 정보 및 후속 4사분면 패널 확장 스켈레톤 |

---

## 3. 핵심 아키텍처 및 보안 설계 원리

### 3.1 Grafana as Code (무상태 프로비저닝)
- **Zero Click 관제 배포**: Grafana 웹 UI에 접속하여 데이터소스를 등록하거나 대시보드를 임포트하는 수동 작업을 완전히 배제하고, 컨테이너 기동 시 설정 파일(`cloudwatch.yaml`, `dashboards.yaml`)이 자동 주입되도록 구성하였습니다.
- **불변 UID 바인딩**: CloudWatch 데이터소스 UID를 `cloudshield-cloudwatch`로 고정 선언하여, 클라우드 B(`[P5-2]`)가 작성할 대시보드 JSON 패널들이 환경에 구애받지 않고 일관되게 동일 데이터소스를 바라보도록 설계하였습니다.

### 3.2 최소 권한 분리 (Least Privilege)
- Grafana 컨테이너가 사용할 IAM Policy(`CloudShield-Grafana-CloudWatch-ReadOnly`)는 오직 CloudWatch 로그 검색(`logs:FilterLogEvents`, `logs:StartQuery`, `logs:GetQueryResults`)과 메트릭 조회(`cloudwatch:GetMetricData`) 및 리전 조회(`ec2:DescribeRegions`)만을 허용합니다.
- 인프라 변경, 삭제, 보안 그룹 수정, WAF 변경 등의 쓰기/수정 권한을 전면 차단하여 관제 계정 및 컨테이너 침해 시의 횡적이동 및 권한 상승을 원천 방지하였습니다.

### 3.3 관제 상태 로깅 및 멀티블록 알림 정합성 결합
- `llm_worker.py`의 `execute_bedrock_analysis`에서 Bedrock 호출 장애 시 `_log_analysis_status(report, "call_failed", "bedrock_call")`를 명시적으로 기록하도록 결합하여, 클라우드 B의 3사분면 Grafana 쿼리 패널에서 Bedrock 성공/Fallback 전환율이 누락 없이 집계되도록 보완하였습니다.
- `send_deep_analysis_slack_alert`가 클라우드 B의 세마포어(동시성 상한 2) 및 데드라인 보호 기반 멀티블록 렌더러(`send_llm_slack_alert`)를 소비하도록 연결하여 긴 3단 상사 보고서 원문이 자림 없이 안전하게 전파되도록 구성하였습니다.

---

## 4. 정적 보안 및 테스트 검증 결과

1. **Lambda 번들 무결성 검증 (`tests/unit/test_lambda_package.py`)**:
   - 10개 전 테스트 통과 (Linux ELF .so 바이너리 탑재, Windows .pyd 부재, pydantic/typing_inspection 의존성 포함).
2. **Terraform IaC 구문 및 모듈 검증 (`terraform validate`)**:
   - `Success! The configuration is valid.` 100% 통과.
3. **Grafana 프로비저닝 및 단위 검증 (`tests/unit/test_remediation.py`)**:
   - `docker-compose.yml`, `cloudwatch.yaml`, `dashboards.yaml`, `cloudshield-secops-overview.json` 규격 및 Terraform 최소 권한 IAM 정책 정합성 테스트 통과.
4. **로컬 통합 품질 게이트 (`powershell .\scripts\check.ps1`)**:
   - R&R 스코프 가드, Ruff Lint, Ruff Format, Pytest 100% 검증 예정.

---

## 5. 후속 직무(클라우드 B `[P5-2]`, 보안 `[P5-3]`, 네트워크 `[P5-4]`) 연계 가이드

1. **클라우드 B (`[P5-2]` Grafana 4사분면 CloudWatch Logs Insights 쿼리 패널 구성)**:
   - 로컬 또는 관제 서버에서 `docker compose -f infra/grafana/docker-compose.yml up -d`를 실행하여 Grafana(`http://localhost:3000`, `admin / cloudshield`)를 기동하십시오.
   - `cloudshield-cloudwatch` 데이터소스가 이미 등록되어 있으므로, `infra/grafana/dashboards/` 내의 대시보드 파일에 4사분면 CloudWatch Logs Insights 쿼리(공격 인입 건수, 10초 차단 SLA 소요 시간, LLM 정상/Fallback 전환율, 사건 처리 타임라인) 패널을 추가하여 JSON을 고정하십시오.
2. **보안 (`[P5-3]` 실인프라 2차 LLM 상사 보고서 품질 및 정량 지표 검수)**:
   - 본 배포로 Bedrock 장애 및 성공 상태가 `cloudshield.llm_analysis` 규격으로 CloudWatch Logs에 기록됩니다.
   - 실인프라 공격 인입 시 2차 LLM 상사 보고서의 3단 구조화 양식(`[1. 침해 개요]`, `[2. 관측 로그 근거]`, `[3. 영향도 및 침해 판정]`) 및 보호 필드 불변성을 검수하십시오.
3. **네트워크 (`[P5-4]` SSH·Web 왕복 차단·복구 패킷 캡처 및 타임라인 대조)**:
   - Grafana 관제 대시보드와 `network/roundtrip_timeline.py` 계측기를 활용하여 공격 노드의 PCAP 타임라인과 서버 측 Grafana/CloudWatch 차단·복구 시각을 `incident_id` 기반으로 양측 대조하십시오.
