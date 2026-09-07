import urllib.request
from importlib.metadata import version

import pytest
from pytest_socket import SocketBlockedError


def test_package_version() -> None:
    assert version("cloudshield") == "0.1.0"


def test_network_socket_is_blocked_by_default() -> None:
    """단위 테스트 중 실제 외부 네트워크(AWS, Slack 등) 호출 누출이 원천 차단되는지 검증."""
    with pytest.raises(SocketBlockedError):
        urllib.request.urlopen("https://example.com")
