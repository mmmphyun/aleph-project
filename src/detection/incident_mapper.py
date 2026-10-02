# CloudShield 탐지 엔진: 결정론적 침해사고 매퍼
# 소유자: 보안 담당
"""결정론적 룰 기반 침해사고 변환기.

Why:
    1차 시그니처 룰에서 탐지된 공격 원문 로그와 정황을 분석하여
    MITRE ATT&CK TTP 매핑, 공격 기법 분석, 한글 상황 요약문 및 관리자 권고 조치를
    엄격한 Pydantic IncidentReport 스키마 형태로 구조화 승격함.

Constraints:
    - 생성되는 객체는 IncidentReport 스키마와 100% 필드 호환되어야 함.
    - 10초 실시간 대응 SLA 보장을 위해 외부 LLM 호출 없이 결정론적 매핑을 수행함.
"""

from __future__ import annotations

from collections.abc import Sequence

from contracts.events import SyslogAuthEvent
from contracts.incident import IncidentReport
from detection.rules import evaluate_rules

_DEFAULT_TARGET_IDENTIFIER = "i-0abcd1234ef567890"
_DEFAULT_INCIDENT_ID = "INC-SIG-SSH-AUTH-001"

_RULE_METADATA = {
    "PATH_TRAVERSAL": {
        "attack_type": "Web Path Traversal",
        "mitre_id": "T1595.002",
        "risk_level": "HIGH",
        "action_required": "BLOCK_WAF",
    },
    "SENSITIVE_FILE_PROBING": {
        "attack_type": "Web Sensitive File Probing",
        "mitre_id": "T1595.003",
        "risk_level": "HIGH",
        "action_required": "BLOCK_WAF",
    },
    "WEB_DIRECTORY_SCANNING": {
        "attack_type": "Web Directory Scanning",
        "mitre_id": "T1595.003",
        "risk_level": "HIGH",
        "action_required": "BLOCK_WAF",
    },
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
    """원문 로그 텍스트를 정형화된 IncidentReport 객체로 변환.

    Why:
        비정형 텍스트 로그에서 공격자 IP, 타깃 인스턴스, 대상 계정 목록을 추출하고
        SecOps 대응 지침(action_required)과 권고안을 정형 데이터 계약으로 도출함.

    Constraints:
        - raw_logs: 최소 1줄 이상의 인증 실패 또는 시스템 이상 징후 로그 문자열.
        - 반환값: IncidentReport 불변(frozen) 모델 인스턴스.

    Side-effects / Edge-cases:
        - 로컬 시그니처 룰 결과를 IncidentReport로 승격하는 결정론적 매퍼 구조이다.
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

    source_ip = _select_primary_source_ip(events)
    target_accounts = tuple(dict.fromkeys(event.username for event in events))
    target_identifier = _extract_target_identifier(events)

    return map_threat_to_incident(
        is_threat=is_detected,
        rule_name=rule_name,
        source_ip=source_ip,
        target_accounts=target_accounts,
        target_identifier=target_identifier,
    )


def map_threat_to_incident(
    *,
    is_threat: bool,
    rule_name: str | None,
    source_ip: str,
    target_accounts: Sequence[str] = (),
    target_identifier: str = _DEFAULT_TARGET_IDENTIFIER,
    incident_id: str | None = None,
) -> IncidentReport:
    """누적 윈도우 또는 로컬 룰의 위협 판정을 표준 IncidentReport로 변환한다.

    Why:
        ``auth_window``와 ``evaluate_rules``는 동일한 룰명을 반환하지만 각 호출부가
        MITRE ATT&CK·위험도·대응 정책을 다시 정의하면 메타데이터가 불일치할 수 있다.
        판정 경로와 무관하게 이 함수만 IncidentReport 생성 책임을 갖는다.

    Constraints:
        - ``rule_name``은 기존 SSH 2종 또는 Web L7 3종 시그니처 룰이어야 한다.
        - ``target_accounts``는 SSH에서는 필수이며 Web에서는 빈 시퀀스를 허용한다.
          URI를 계정으로 대체하지 않으며 계정 문자열의 입력 순서를 보존한다.
          문자열 자체는 계정 목록이 아니므로 거부한다. 누적 목록 수집은 호출부가 담당한다.
        - Password Spraying은 MEDIUM / BLOCK_IP_ONLY이며 EC2 격리를 요청하지 않는다.
        - IP와 EC2 식별자의 최종 형식 검증은 보호된 IncidentReport 계약에 위임한다.
        - 기본 사고 ID와 타깃 ID는 데모용이며 운영 호출부는 고유 사고 ID와 실제 EC2 ID를 제공한다.

    Side-effects / Edge-cases:
        - 외부 API를 호출하지 않으며 입력이 같으면 동일한 보고서를 반환한다.
        - 비위협 판정과 지원하지 않는 룰은 보고서로 승격하지 않고 ValueError를 발생시킨다.
    """
    if not is_threat or rule_name is None:
        raise ValueError("탐지 가능한 SSH 인증 실패 공격 패턴이 없습니다.")

    metadata = _RULE_METADATA.get(rule_name)
    if metadata is None:
        raise ValueError(f"지원하지 않는 탐지 룰입니다: {rule_name}")
    if not target_accounts and metadata["action_required"] != "BLOCK_WAF":
        raise ValueError("위협 보고서에는 최소 한 개의 대상 계정이 필요합니다.")
    if isinstance(target_accounts, (str, bytes)) or any(
        not isinstance(account, str) or not account.strip() for account in target_accounts
    ):
        # 계정 문자열을 문자 단위 목록으로 오인하거나 빈 계정을 증거로 승격하는 것을 방지한다.
        # 식별자 변형으로 증거가 달라지지 않도록 유효 계정은 정규화 없이 보존한다.
        raise ValueError("대상 계정은 비어 있지 않은 문자열 목록이어야 합니다.")

    unique_target_accounts = tuple(dict.fromkeys(target_accounts))

    return IncidentReport(
        incident_id=(
            incident_id
            if incident_id is not None
            else (
                "INC-SIG-WEB-L7-001"
                if metadata["action_required"] == "BLOCK_WAF"
                else _DEFAULT_INCIDENT_ID
            )
        ),
        attack_type=metadata["attack_type"],
        mitre_id=metadata["mitre_id"],
        risk_level=metadata["risk_level"],
        source_ip=source_ip,
        target_identifier=target_identifier,
        target_accounts=unique_target_accounts,
        summary_ko=(
            _build_web_summary(rule_name, source_ip)
            if metadata["action_required"] == "BLOCK_WAF"
            else _build_summary(metadata["mitre_id"], source_ip, unique_target_accounts)
        ),
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
    if mitre_id in ("T1595.002", "T1595.003"):
        # Web 탐색 정황만으로 침해 성공을 단정하지 않고 HTTP 차단과 증거 확인을 권고한다.
        # WAF IPSet 변경은 플랫폼 계층이 집행하며 이 매퍼는 외부 API를 호출하지 않는다.
        return (
            f"출발지 IP {source_ip}/32를 WAF IPSet에 등록하여 HTTP·HTTPS 접근 차단",
            "Nginx 원문 로그와 WAF 차단 결과를 확인하고 민감 자원 노출 여부 점검",
            "공유 출구 IP의 정상 사용자 영향 및 오탐 여부 확인",
        )
    common = (
        # SSH는 WAF의 HTTP 검사 대상이 아니므로 권고를 L4 차단 요구로 표현한다.
        # 실제 차단 엔진의 BLOCK_IP_ONLY 집행 방식은 플랫폼 담당이 정합화해야 한다.
        f"출발지 IP {source_ip}/32의 SSH 접근을 차단하는 네트워크 정책 적용",
        "비밀번호 기반 SSH 접속 비활성화 및 키 기반 인증 강제",
    )
    if mitre_id == "T1110.001":
        return (
            *common,
            f"타깃 EC2 인스턴스({target_identifier})를 Quarantine 보안 그룹으로 격리",
        )
    return common


def _build_web_summary(rule_name: str, source_ip: str) -> str:
    """탐색 시그니처를 침해 성공으로 오인하지 않도록 Web 정황과 조치 요청을 요약한다."""
    descriptions = {
        "PATH_TRAVERSAL": "경로 탈출 시도",
        "SENSITIVE_FILE_PROBING": "민감 파일 탐색",
        "WEB_DIRECTORY_SCANNING": "웹 디렉터리 열거",
    }
    return (
        f"관측 출발지 IP {source_ip}에서 {descriptions[rule_name]} 정황이 감지되었습니다. "
        "WAF IP 차단을 요청하며, 실제 차단 결과와 자원 노출 여부는 별도 확인이 필요합니다."
    )
