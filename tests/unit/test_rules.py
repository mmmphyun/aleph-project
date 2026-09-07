# CloudShield 단위 테스트: 보안 탐지 룰 엔진
# 소유자: 보안 담당
"""시그니처 1차 룰 엔진(rules.py) 단위 테스트."""

from __future__ import annotations

import pytest

from contracts.events import SyslogAuthEvent
from detection.rules import evaluate_rules


def test_evaluate_rules_interface(sample_auth_log_lines: list[str]) -> None:
    """evaluate_rules 함수 시그니처 및 스켈레톤 인터페이스 스모크 검증.

    Why:
        보안 담당 에이전트가 rules.py 구현 착수 전 모듈 import 경로와
        함수 시그니처(SyslogAuthEvent 리스트 수락 여부)를 즉각 검증함.
    """
    events = [
        SyslogAuthEvent.parse_line(line)
        for line in sample_auth_log_lines
        if SyslogAuthEvent.parse_line(line) is not None
    ]
    assert len(events) >= 1

    with pytest.raises(NotImplementedError, match="보안 담당자 구현 영역"):
        evaluate_rules(events)


@pytest.mark.skip(reason="보안 담당 구현 대기")
def test_brute_force_detection_success(sample_auth_log_lines: list[str]) -> None:
    """단일 IP 5회 이상 실패 시 SSH Brute Force 탐지 성공 검증."""
    events = [
        SyslogAuthEvent.parse_line(line)
        for line in sample_auth_log_lines
        if SyslogAuthEvent.parse_line(line) is not None
    ]
    is_detected, rule_name = evaluate_rules(events)
    assert is_detected is True
    assert rule_name == "SSH_BRUTE_FORCE"
