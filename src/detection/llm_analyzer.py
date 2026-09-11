# CloudShield 탐지 엔진: LLM 심층 분석기
# 소유자: 보안 담당
"""LLM Structured Output 기반 침해사고 심층 분석기.

Why:
    1차 룰에서 탐지된 공격 원문 로그와 정황을 LLM(Gemini / OpenAI)에 전달하여
    MITRE ATT&CK TTP 매핑, 공격 기법 분석, 한글 상황 요약문 및 관리자 권고 조치를
    엄격한 Pydantic IncidentReport 스키마 형태로 구조화 추출함.

Constraints:
    - LLM 응답은 IncidentReport 스키마와 100% 필드 호환되어야 함.
    - Pydantic V2 model_validate_json 또는 구조화 출력(Structured Outputs) 연동 필수.
"""

from __future__ import annotations

from contracts.events import SyslogAuthEvent
from contracts.incident import IncidentReport
from detection.rules import evaluate_rules

_DEFAULT_TARGET_IDENTIFIER = "i-0abcd1234ef567890"

_RULE_METADATA = {
    "SSH_BRUTE_FORCE": {
        "attack_type": "SSH Brute Force",
        "mitre_id": "T1110.001",
        "risk_level": "HIGH",
        "action_required": "BLOCK_AND_QUARANTINE",
    },
    "SSH_PASSWORD_SPRAYING": {
        "attack_type": "SSH Password Spraying",
        "mitre_id": "T1110.003",
        "risk_level": "MEDIUM",
        "action_required": "BLOCK_IP_ONLY",
    },
}


def analyze_incident(raw_logs: str) -> IncidentReport:
    """원문 로그 텍스트를 LLM에 전달하여 정형화된 IncidentReport 객체로 변환.

    Why:
        비정형 텍스트 로그에서 공격자 IP, 타깃 인스턴스, 대상 계정 목록을 추출하고
        SecOps 대응 지침(action_required)과 권고안을 정형 데이터 계약으로 도출함.

    Constraints:
        - raw_logs: 최소 1줄 이상의 인증 실패 또는 시스템 이상 징후 로그 문자열.
        - 반환값: IncidentReport 불변(frozen) 모델 인스턴스.

    Side-effects / Edge-cases:
        - 현재 구현은 로컬 시그니처 룰 결과를 IncidentReport로 승격하는 결정론적 Fallback이다.
          외부 LLM API를 호출하지 않아 단위 테스트와 10초 데모 파이프라인에서 재현성이 보장된다.
        - raw_logs에 탐지 가능한 SSH 실패 로그가 없거나 지원하지 않는 룰이면 ValueError를 발생시켜
          호출부가 ALERT_ONLY 또는 조기 종료 정책을 명시적으로 선택하게 한다.
    """
    events = [
        event
        for line in raw_logs.splitlines()
        if (event := SyslogAuthEvent.parse_line(line)) is not None
    ]
    is_detected, rule_name = evaluate_rules(events)
    if not is_detected or rule_name is None:
        raise ValueError("탐지 가능한 SSH 인증 실패 공격 패턴이 없습니다.")

    metadata = _RULE_METADATA.get(rule_name)
    if metadata is None:
        raise ValueError(f"지원하지 않는 탐지 룰입니다: {rule_name}")

    source_ip = _select_primary_source_ip(events)
    target_accounts = tuple(dict.fromkeys(event.username for event in events))
    target_identifier = _extract_target_identifier(events)

    return IncidentReport(
        incident_id="INC-SIG-SSH-AUTH-001",
        attack_type=metadata["attack_type"],
        mitre_id=metadata["mitre_id"],
        risk_level=metadata["risk_level"],
        source_ip=source_ip,
        target_identifier=target_identifier,
        target_accounts=target_accounts,
        summary_ko=_build_summary(metadata["mitre_id"], source_ip, target_accounts),
        action_required=metadata["action_required"],
        recommendations=_build_recommendations(
            metadata["mitre_id"],
            source_ip,
            target_identifier,
        ),
    )


def _select_primary_source_ip(events: list[SyslogAuthEvent]) -> str:
    """가장 많은 실패 이벤트를 만든 출발지 IP를 사고 대표 공격자로 선택한다."""
    counts: dict[str, int] = {}
    for event in events:
        counts[event.source_ip] = counts.get(event.source_ip, 0) + 1
    return max(counts, key=counts.__getitem__)


def _extract_target_identifier(events: list[SyslogAuthEvent]) -> str:
    """로그 안의 EC2 인스턴스 ID를 우선 사용하고, 없으면 데모 표준 타깃 ID를 사용한다.

    Why:
        auth.log의 hostname은 보통 target-ec2처럼 사람이 읽는 이름이라 IncidentReport의
        EC2 ID 계약을 직접 만족하지 못한다. CloudWatch logStream 연동 전까지는 테스트베드
        표준 ID를 사용해 보안 모듈과 공통 계약의 결합을 먼저 고정한다.
    """
    for event in events:
        if event.hostname.startswith("i-"):
            return event.hostname
    return _DEFAULT_TARGET_IDENTIFIER


def _build_summary(mitre_id: str, source_ip: str, target_accounts: tuple[str, ...]) -> str:
    account_text = ", ".join(target_accounts)
    if mitre_id == "T1110.001":
        return (
            f"출발지 IP {source_ip}에서 단일 계정 대상 SSH 비밀번호 추측 공격이 감지되었습니다. "
            f"대상 계정은 {account_text}이며 MITRE ATT&CK {mitre_id}로 분류됩니다."
        )
    return (
        f"출발지 IP {source_ip}에서 여러 계정 대상 SSH 패스워드 스프레잉이 감지되었습니다. "
        f"대상 계정은 {account_text}이며 MITRE ATT&CK {mitre_id}로 분류됩니다."
    )


def _build_recommendations(
    mitre_id: str,
    source_ip: str,
    target_identifier: str,
) -> tuple[str, ...]:
    common = (
        f"AWS WAF IPSet에 {source_ip}/32를 등록해 반복 접근을 차단",
        "비밀번호 기반 SSH 접속 비활성화 및 키 기반 인증 강제",
    )
    if mitre_id == "T1110.001":
        return (
            *common,
            f"타깃 EC2 인스턴스({target_identifier})를 Quarantine 보안 그룹으로 격리",
        )
    return common
