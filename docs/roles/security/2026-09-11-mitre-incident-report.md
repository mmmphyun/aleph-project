# MITRE T1110.001 IncidentReport 연동 구현 보고서

## 1. 작업 개요

- 작업 일자: 2026-09-11
- 담당 직무: 보안
- 커밋: `f66ab06 feat(security): MITRE T1110.001 IncidentReport 연동`
- 작업 범위: `src/detection/llm_analyzer.py`, `tests/unit/test_llm_analyzer.py`
- 목적: SSH 인증 실패 로그를 탐지 룰 결과와 MITRE ATT&CK 기법으로 매핑하고, 공통 `IncidentReport` 계약 객체로 변환

## 1.1 전체 보안 작업 이력

이번 보고서는 최근 IncidentReport 연동만이 아니라, 본인이 수행한 보안 탐지 계층의 누적 변경을 함께 정리한다.

| 커밋 | 작업 내용 |
|---|---|
| `6d3bb86` | SSH 단일 계정 무차별 대입 1차 탐지 룰 구현 |
| `3f04014` | 탐지 룰 오탐 및 우선순위 수정 |
| `3ff7855` | 탐지 룰과 단위 테스트 보완 |
| `a5f4703` | 탐지 룰 코드 포맷 정리 |
| `b1ba138` | 리뷰 지적 회귀 검증 및 배치 경계 명시 |
| `97dc234` | 윤일 날짜의 Syslog 인증 실패 누락 수정 |
| `538550e` | 노이즈 로그 오탐 방어 회귀 테스트 추가 |
| `e15ba0c` | 노이즈 로그 정상 샘플 판별 명확화 |
| `c81fb89` | SSH 실패 로그 공격자 식별자 추출 정규식 추가 |
| `f66ab06` | MITRE 매핑 및 IncidentReport 연동 |

누적 결과로 SSH 인증 실패 로그를 정규식·임계치 기반으로 탐지하고, 공격자 식별·오탐 방어·날짜 경계 처리·공통 사고 계약 변환까지 보안 담당 영역의 탐지 파이프라인을 완성했다.

## 2. 구현 내용

### 2.1 탐지 결과의 IncidentReport 승격

`analyze_incident(raw_logs)`가 원문 로그를 줄 단위로 파싱하여 `SyslogAuthEvent` 목록을 만들고, `evaluate_rules`를 통해 공격 여부와 룰 이름을 결정하도록 구현했다. 탐지되지 않은 로그는 임의의 사고 보고서로 만들지 않고 `ValueError`를 발생시켜 호출부가 후속 정책을 명시적으로 선택하도록 했다.

### 2.2 MITRE ATT&CK 매핑

| 탐지 룰 | MITRE 기법 | 위험도 | 대응 수준 |
|---|---|---|---|
| `SSH_BRUTE_FORCE` | `T1110.001` Password Guessing | `HIGH` | `BLOCK_AND_QUARANTINE` |
| `SSH_PASSWORD_SPRAYING` | `T1110.003` Password Spraying | `MEDIUM` | `BLOCK_IP_ONLY` |

### 2.3 사고 필드 생성

- 공격자 IP: 실패 이벤트가 가장 많이 발생한 출발지 IP를 대표 공격자로 선택
- 대상 계정: 중복을 제거한 순서 보존 튜플로 생성
- 대상 식별자: 로그의 EC2 인스턴스 ID를 우선 사용하고, 미포함 시 테스트베드 표준 ID 사용
- 요약 및 권고안: MITRE 기법별 한국어 상황 설명과 WAF IPSet 등록, SSH 키 인증 강제, 필요 시 EC2 격리 권고 생성

외부 LLM API를 호출하지 않는 결정론적 Fallback 구조를 적용해 10초 데모 파이프라인에서 재현성과 단위 테스트 가능성을 확보했다.

## 3. 테스트 내용

`tests/unit/test_llm_analyzer.py`에 다음 검증을 반영했다.

1. 다중 계정 인증 실패 로그가 `T1110.003` 및 `BLOCK_IP_ONLY`로 변환되는지 검증
2. 동일 계정 반복 실패 로그가 `T1110.001`, `HIGH`, `BLOCK_AND_QUARANTINE`으로 변환되는지 검증
3. 정상 로그인 로그가 사고 보고서로 오인되지 않고 `ValueError`를 반환하는지 검증
4. 반환값이 `IncidentReport` 타입이며 EC2 ID, 공격자 IP, 대상 계정 계약을 만족하는지 검증

## 4. 검증 결과

- 실행 명령: `powershell -ExecutionPolicy Bypass -File .\\scripts\\check.ps1`
- 결과: 자동 검증 완료 전 중단
- 원인: `scripts/check.ps1`의 테스트 파일 경로 검사 단계에서 `.pytest_cache` 접근 권한 오류 발생
- 추가 확인: 현재 셸에서 `pytest` 명령을 찾지 못함
- 판정: 환경 권한 및 실행 도구 문제로 전체 게이트 통과 여부는 확인하지 못함

## 5. 영향 및 후속 연계

이번 변경은 보안 탐지 계층 내부에서 `IncidentReport`를 생성하는 단계까지 담당한다. 생성된 보고서는 이후 클라우드 A의 차단 오케스트레이터와 클라우드 B의 Slack 알림 모듈이 소비할 수 있으며, 이번 변경에서는 해당 직무 영역의 파일을 수정하지 않았다.

후속 환경에서 `.pytest_cache` 접근 권한을 정리하고 프로젝트 테스트 실행 환경을 활성화한 뒤 `scripts/check.ps1`를 재실행해야 한다.

## 6. 결론

SSH Brute Force 및 Password Spraying 탐지 결과를 MITRE ATT&CK ID, 위험도, 대응 수준이 포함된 표준 `IncidentReport`로 변환하는 보안 모듈 구현을 완료했다. 비탐지 로그 거부와 결정론적 처리로 오탐 전파 및 외부 API 의존성을 줄였으며, 주요 정탐·비탐지 시나리오에 대한 단위 테스트를 추가했다.
