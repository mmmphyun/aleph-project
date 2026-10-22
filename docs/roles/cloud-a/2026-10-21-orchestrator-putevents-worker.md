# 기술 문서: EventBridge PutEvents 발행 및 비동기 LLM 분석 워커 결합
작성자: 클라우드 A (플랫폼 전담)
날짜: 2026-10-21
관련 티켓: https://notion.so/3fe04d37c225806a81c2de3d8be324fe
관련 이슈: #207

## 1. 구현 개요
10초 SLA를 갖는 실시간 긴급 차단(L4 SG / L7 WAF)과 수십 초가 소요되는 사후 LLM 심층 분석을 아키텍처 레벨에서 비동기 분리(Asynchronous Decoupling)하기 위해:
1. src/remediation/orchestrator.py: 차단 성공 시 EventBridge로 ThreatRemediated 이벤트를 발행하는 emit_threat_resolved_event 구현 및 통합 결합.
2. src/remediation/llm_worker.py: EventBridge 이벤트를 비동기 수신하여 Bedrock 심층 분석(nalyze_incident_with_bedrock) 및 2차 Slack 전파(send_deep_analysis_slack_alert)를 실행하는 워커 핸들러 결합.
3. 	ests/unit/test_remediation.py: EventBridge 발행 스키마, 통신 실패 격리(Fault Isolation), 워커 결합 파이프라인 단위 테스트 구축.

## 2. 분산 제약 및 안정성 설계
- **비대칭 트랜잭션 결함 격리**: EventBridge 통신 실패(ClientError, FailedEntryCount > 0) 시에도 이미 적용된 L4/L7 차단 상태를 절대 롤백하지 않고 안전 격리.
- **스키마 규격 준수**: Source=cloudshield.security, DetailType=ThreatRemediated, Detail=IncidentReport 표준 직렬화.
- **의존성 지연 바인딩**: 순수 격리 환경(python -S) 및 번들 로딩 무결성을 보장하기 위해 지연 임포트 패턴 적용.
