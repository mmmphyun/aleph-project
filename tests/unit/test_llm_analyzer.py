# CloudShield 단위 테스트: LLM 심층 분석기
# 소유자: 보안 담당
"""LLM 심층 분석기(llm_analyzer.py) 단위 테스트."""

from __future__ import annotations

import pytest

from contracts.incident import IncidentReport
from detection.llm_analyzer import analyze_incident


def test_analyze_incident_interface(sample_auth_log_lines: list[str]) -> None:
    """analyze_incident 함수 시그니처 및 스켈레톤 인터페이스 스모크 검증.

    Why:
        보안 담당 에이전트가 llm_analyzer.py 구현 착수 전 모듈 import 경로와
        함수 시그니처(원문 문자열 수락 여부)를 즉각 검증함.
    """
    raw_logs = "\n".join(sample_auth_log_lines)
    with pytest.raises(NotImplementedError, match="보안 담당자 구현 영역"):
        analyze_incident(raw_logs)


@pytest.mark.skip(reason="보안 담당 구현 대기")
def test_llm_analyzer_structured_output(sample_auth_log_lines: list[str]) -> None:
    """LLM 분석 결과가 IncidentReport 스키마와 100% 호환되는지 검증."""
    raw_logs = "\n".join(sample_auth_log_lines)
    report = analyze_incident(raw_logs)

    assert isinstance(report, IncidentReport)
    assert report.source_ip == "198.51.100.50"
    assert report.risk_level in ["HIGH", "MEDIUM", "LOW"]
