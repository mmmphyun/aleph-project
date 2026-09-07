# CloudShield 단위 테스트: CloudWatch Logs 프로세서
# 소유자: 클라우드 B 담당
"""CloudWatch Logs 압축 해제기(cw_processor.py) 단위 테스트."""

from __future__ import annotations

from typing import Any

import pytest

from collector.cw_processor import decode_cw_logs


def test_decode_cw_logs_interface(sample_cw_event: dict[str, Any]) -> None:
    """decode_cw_logs 함수 시그니처 및 스켈레톤 인터페이스 스모크 검증.

    Why:
        클라우드 B 담당 에이전트가 cw_processor.py 구현 착수 전 모듈 import 경로와
        함수 시그니처(Lambda 이벤트 딕셔너리 수락 여부)를 즉각 검증함.
    """
    with pytest.raises(NotImplementedError, match="클라우드 B 담당자 구현 영역"):
        decode_cw_logs(sample_cw_event)


@pytest.mark.skip(reason="클라우드 B 구현 대기")
def test_decode_cw_logs_success(sample_cw_event: dict[str, Any]) -> None:
    """CloudWatch Logs 페이로드 Gzip 압축 해제 및 로그 문자열 추출 검증."""
    lines = decode_cw_logs(sample_cw_event)
    assert isinstance(lines, list)
    assert len(lines) >= 1
    assert "Failed password" in lines[0]
