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

from contracts.incident import IncidentReport


def analyze_incident(raw_logs: str) -> IncidentReport:
    """원문 로그 텍스트를 LLM에 전달하여 정형화된 IncidentReport 객체로 변환.

    Why:
        비정형 텍스트 로그에서 공격자 IP, 타깃 인스턴스, 대상 계정 목록을 추출하고
        SecOps 대응 지침(action_required)과 권고안을 정형 데이터 계약으로 도출함.

    Constraints:
        - raw_logs: 최소 1줄 이상의 인증 실패 또는 시스템 이상 징후 로그 문자열.
        - 반환값: IncidentReport 불변(frozen) 모델 인스턴스.

    Side-effects / Edge-cases:
        - LLM API 호출 레이턴시 발생(보통 1~3초). 네트워크 타임아웃 및 재시도 고려 필요.
        - LLM 출력 JSON이 IncidentReport 검증 규칙(IPv4 형식, EC2 인스턴스 ID 형식)을
          위반할 경우 ValidationError가 발생하므로 Fallback 처리 또는 프롬프트 보정이 요구됨.
    """
    raise NotImplementedError(
        "보안 담당자 구현 영역: LLM Structured Output 기반 침해사고 심층 분석기"
    )
