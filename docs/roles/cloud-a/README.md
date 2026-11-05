# 플랫폼 엔지니어링 및 거버넌스 기술 포트폴리오 (클라우드 A)

<div align="center">

**CloudShield 플랫폼 아키텍처, 분산 상태 관리 및 DevSecOps 거버넌스 하네스**

**담당 엔지니어: 승윤 ([@mmmphyun](https://github.com/mmmphyun))**  
*역할: 테크 리드 & 플랫폼 엔지니어 (Platform / DevSecOps)*

</div>

---

## 1. 담당 도메인 개요 및 플랫폼 R&R

클라우드 A는 CloudShield 파이프라인의 기반이 되는 **선언적 클라우드 인프라(IaC), 분산 상태 슬라이딩 윈도우 엔진, L4/L7 원자적 차단·복구 오케스트레이터, 무상태 Grafana 관제 프로비저닝, 4개 직무 병렬 개발을 지탱하는 개발 하네스**를 전담했습니다.

도메인 엔지니어(네트워크, 보안, 클라우드 B)가 인프라 배관의 복잡도와 클라우드 과금 및 자격증명 유출 우려 없이 고유 연구 영역에 집중할 수 있도록 플랫폼 엔지니어링 선행 투자 모델을 구축했습니다.

---

## 2. 핵심 엔지니어링 딥다이브 (CS 메커니즘 & 아키텍처)

### 2.1 무상태 Lambda 환경의 분산 슬라이딩 윈도우 알고리즘 진화
* **배경 및 난제**:
  - AWS Lambda는 무상태(Stateless) 컨테이너이므로 호출 간 공격 인증 실패 횟수를 인메모리에 유지할 수 없습니다.
  - 초기 단일 고정 윈도우(Fixed Window) 도입 시, 분 경계면(예: 11:59 vs 12:01)에 걸쳐 인입되는 공격 로그가 버킷별로 분할되어 5회 임계치를 미달해 탐지를 누락하는 결함이 발생했습니다.
* **알고리즘 트레이드오프 분석 및 한계 극복**:
  - 대규모 트래픽에서 균등 분포를 가정하는 Cloudflare 가중 2-버킷 알고리즘을 검토했으나, 저트래픽 및 간헐적 버스트 공격 환경에서는 오차율이 증가하여 테스트베드 검증에 실패했습니다.
  - 분 단위 버킷에 타임스탬프를 부여하고 기준 시각 기준 직전-현재-직후 3개 분을 병렬 조회하는 **'타임스탬프 3-버킷 슬라이딩 윈도우'**를 자체 설계·적용하여 경계면 누락을 방어했습니다.
* **분산 데이터 일관성(Consistency Model) 보장**:
  - 분산 저장소 DynamoDB는 기본적으로 최종 일관성(Eventual Consistency)을 제공하므로, 쓰기 직후 후속 람다 호출이 직전 카운트를 즉시 조회하지 못해 임계치 판정이 지연되는 경쟁 상태(Race Condition)가 발생했습니다.
  - 쿼리 호출부에 **`ConsistentRead=True`(Strongly Consistent Read)**를 강제 적용하여 분산 복제 지연에 따른 카운트 누락을 차단했습니다.

### 2.2 Boto3 기반 L4/L7 다중 계층 원자적 차단 및 단일 명령 롤백 엔진
* **원자성(Atomicity) 및 멱등성(Idempotency)**:
  - L4 계층: EC2 인스턴스의 보안 그룹을 인바운드가 통제된 격리 보안 그룹(`quarantine_sg`)으로 단일 API(`modify_instance_attribute`) 호출을 통해 원자적으로 교체했습니다.
  - L7 계층: ALB 전면 AWS WAF IPSet에 공격자 IP를 `/32` 단위로 업데이트하여 인바운드 트래픽을 즉시 드롭했습니다.
  - 중복 호출 및 재시도 상황에서도 리소스 상태 왜곡이 없도록 Boto3 ClientError 정밀 핸들링 및 멱등성을 보장했습니다.
* **원자적 인프라 롤백 복구 모듈**:
  - 실측 검증 후 테스트베드를 즉시 정상 운영 상태로 환원하기 위해 `restore_baseline_sg.py` 및 `unblock_waf_ip.py`를 단일 롤백 파이프라인으로 연동했습니다.

### 2.3 Pydantic V2 불변 계약 및 컴파일 타임 5대 교차 계약 하드가드
* **데이터 드리프트 사전 방어**:
  - 직무 간 인터페이스 불일치로 인한 런타임 붕괴를 막기 위해 `src/contracts/`에 Pydantic V2 기반 불변(`frozen=True`, `extra="forbid"`) 데이터 모델을 정의했습니다.
  - 4개 직무의 모의 데이터셋과 인터페이스 규격이 어긋나면 컴파일 타임에 즉시 빌드를 차단하는 [5대 교차 계약 하드가드](../../../tests/test_contracts.py)를 구축했습니다.
  - 이를 통해 **137건의 PR이 머지되는 동안 브랜치 병합 충돌 제로**를 달성했습니다.

### 2.4 Grafana as Code (Zero-Click 관제 프로비저닝)
* **코드형 대시보드 및 데이터소스 자동화**:
  - 웹 콘솔 수동 설정을 배제하고 Docker Compose 기동 시 `cloudwatch.yaml` 및 `dashboards.yaml`을 주입하여 동일 관제 환경을 일관되게 재현하도록 표준화했습니다.
  - 불변 UID(`cloudshield-cloudwatch`)를 바인딩하여 클라우드 B가 작성한 대시보드 JSON 패널들이 환경에 구애받지 않고 연동되도록 설계했습니다.
  - Logs/Metrics ReadOnly 최소 권한 IAM 정책(`CloudShield-Grafana-CloudWatch-ReadOnly`)을 적용하여 관제 인프라 침해 시의 측면 이동 위험을 최소화했습니다.

---

## 3. 핵심 정량 실측 성과 요약

<div align="center">

| 검증 항목 | 달성 지표 | 환경 및 측정 조건 | 단일 신뢰점 원본 |
| :--- | :---: | :--- | :---: |
| **분산 윈도우 판정** | `0 누락` | 분 경계면 분할 인입 시 3-버킷 병렬 쿼리 무결성 | [윈도우 아키텍처](2026-09-21-auth-failure-window-architecture.md) |
| **차단 API 소요 시간** | `0.44s` | Boto3 EC2 SG 교체 및 WAF IPSet 업데이트 호출 | [P5-1 배포 보고서](2026-10-28-p5-1-pipeline-deploy-and-grafana-provisioning.md) |
| **Lambda 번들 용량** | `2.73MB` | Linux x86_64 ELF 바이너리 최적화 패키징 | [P5-1 배포 보고서](2026-10-28-p5-1-pipeline-deploy-and-grafana-provisioning.md) |
| **협업 거버넌스 안정성** | `137 PRs` | 사전 하네스 검증을 통한 137건 PR 머지 무충돌 유지 | [GitHub PR 목록](https://github.com/mmmphyun/aleph-project/pulls?q=is%3Apr+is%3Amerged) |
| **작업 카드 분담률** | `30%` | 노션 프로젝트 일정 DB 100개 카드 중 30개 전담 | [공식 노션 페이지](https://app.notion.com/p/A-d5f04d37c22582ad9e7f81acd36191d0) |

</div>

---

## 4. 플랫폼 엔지니어링 기술 보고서 목록 (총 16편 전수 링크)

1. [2026-09-04: 로컬 에이전트 거버넌스 하네스 및 개발 환경 구축](2026-09-04-agent-governance-harness.md)
2. [2026-09-10: L4 EC2 격리 보안 그룹 교체 아키텍처 설계](2026-09-10-l4-ec2-quarantine-architecture.md)
3. [2026-09-15: L7 WAFv2 IPSet /32 원자적 차단 아키텍처](2026-09-15-l7-wafv2-ipset-architecture.md)
4. [2026-09-17: R&R 도메인 경계선 하드가드 및 런타임 단일화](2026-09-17-rnr-scope-guard-and-runtime-unification.md)
5. [2026-09-21: DynamoDB 인증 실패 슬라이딩 윈도우 아키텍처](2026-09-21-auth-failure-window-architecture.md)
6. [2026-09-23: 분산 윈도우 동시성 및 Strongly Consistent Read 벤치마크](2026-09-23-auth-window-concurrency-benchmark.md)
7. [2026-09-23: 대용량 볼륨 vs 저트래픽 은닉 공격 아키텍처 트레이드오프 분석](2026-09-23-secops-architecture-tradeoff-volumetric-vs-stealth.md)
8. [2026-09-28: 오케스트레이터-Slack 파이프라인 결함 격리 설계](2026-09-28-orchestrator-slack-pipeline-fault-isolation.md)
9. [2026-10-02: SecOps 하네스 진화 및 포스트모텀 회고](2026-10-02-secops-harness-evolution-and-postmortem.md)
10. [2026-10-07: L7 분산 위협 탐지 및 데이터 계약 심층 분석](2026-10-07-l7-distributed-threat-detection-deepdive.md)
11. [2026-10-08: 로컬 사전 비행 검증 및 Moto 가상 인프라 리포트](2026-10-08-local-preflight-verification-report.md)
12. [2026-10-13: [P3-2] AWS 인프라 프로비저닝 및 리소스 배포 보고서](2026-10-13-p3-2-aws-infrastructure-provisioning-report.md)
13. [2026-10-14: [P3-3b] 기준 보안 그룹 인바운드 롤백 엔진 검증](2026-10-14-p3-3b-baseline-sg-ingress-rollback-report.md)
14. [2026-10-21: 오케스트레이터 PutEvents 비동기 워커 파이프라인](2026-10-21-orchestrator-putevents-worker.md)
15. [2026-10-23: [P4-1] EventBridge-Bedrock LLM 배포 및 2단계 분리 보고서](2026-10-23-p4-1-eventbridge-llm-deployment-report.md)
16. [2026-10-28: [P5-1] 실인프라 배포 및 무상태 Grafana 프로비저닝 보고서](2026-10-28-p5-1-pipeline-deploy-and-grafana-provisioning.md)
