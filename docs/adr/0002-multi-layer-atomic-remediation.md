# ADR 0002: 다중 계층(L4 SG / L7 WAF / IAM) 원자적 복합 차단 엔진 아키텍처

- **상태**: 승인됨 (Accepted)
- **결정자**: 클라우드 A (테크 리드 @mmmphyun)
- **일자**: 2026-09-04
- **소유 직무**: 클라우드 A (차단 엔진/오케스트레이터)

---

## 1. 배경 및 문제 제기 (Context)

- 단일 차단 기법(예: WAF 단독 또는 SG 단독)만 사용할 경우 프로토콜 계층 불일치 모순이 발생함:
  - L4 SSH 무차별 대입 공격은 L7 AWS WAF로 차단할 수 없음.
  - 웹 기반 웹쉘/SQLi 공격 발생 시 L4 SG만 차단하면 정상 웹 서비스 포트(80/443)가 전체 마비됨.
  - 탈취된 IAM Access Key나 세션을 통한 내부 침해 시 네트워크 레벨 차단만으로는 API 호출을 막을 수 없음.
- 따라서 침해 위협의 유형과 심각도에 따라 L4(네트워크 격리), L7(IP 인바운드 차단), Identity(자격증명 무효화)를 트랜잭션 수준으로 원자적(Atomic) 실행하는 복합 대응 엔진이 필요함.

---

## 2. 대안 검토 및 트레이드오프 분석 (Considered Options)

| 구분 | 방안 1: 단일 계층 차단 (SG 교체 전용) | 방안 2: 다중 계층 원자적 복합 차단 엔진 (채택) |
| :--- | :--- | :--- |
| **방어 범위** | L4 네트워크 격리만 가능 | L4(SG) + L7(WAF IPSet) + Identity(IAM Session) 통합 제어 |
| **복합 공격 대응** | SSH 공격 후 웹쉘 업로드 및 IAM 탈취 연계 시 무력화 | 공격 벡터별 맞춤형/동시 복합 차단 가능 |
| **장애 격리성** | 단일 API 호출로 단순함 | 개별 Boto3 API 실패 시 나머지 계층 독립 격리 실행 및 멱등성 보장 필요 |
| **결과 인터페이스** | 단순 성공/실패 불리언 | `RemediationResult` TypedDict를 통한 명확한 계층별 결과 반환 |

---

## 3. 아키텍처 결정 (Decision)

- **`IncidentReport.action_required` 지시어 기반 다중 계층 원자적 복합 대응 엔진 구현**:
  1. **L4 차단**: 침해 타깃 EC2의 인바운드/아웃바운드를 전면 차단하는 Quarantine Security Group으로 교체 (`ec2.modify_instance_attribute`).
  2. **L7 차단**: 공격자 출발지 IPv4를 `/32` CIDR로 변환하여 AWS WAF IPSet에 추가 (`wafv2.update_ip_set`).
  3. **Identity 차단**: 탈취 의심 IAM Role의 임시 보안 자격증명 세션 강제 무효화 (`iam.put_role_policy` 인라인 폐기 정책 적용).
- **견고성 원칙**:
  - 개별 계층 조치 실패가 타 계층 차단을 중단시키지 않도록 독립 `try-except` 격리 실행.
  - 중복 호출 시에도 오류가 발생하지 않도록 멱등성(Idempotency) 보장.

---

## 4. 기대 효과 및 결과 (Consequences)

- **긍정적 영향**:
  - 단일 10초 관통 파이프라인에서 L4/L7/IAM 복합 침해에 대한 엔터프라이즈급 대응 시나리오 입증.
  - 클라우드 B(Slack 알림 카드)에 세부 조치 결과(`waf_blocked`, `quarantine_applied`, `iam_revoked`)를 정밀 전달 가능.
- **관리 대상 한계점**:
  - Boto3 Client 호출 시 IAM 최소 권한(Least Privilege) 정책 설계 필요.
  - Moto 기반 가상 AWS 테스트베드에서 3대 계층에 대한 단위/통합 테스트 유지보수 필요.
