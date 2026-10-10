import pytest

from core.exceptions import InvalidTargetError
from core.target import Target


def test_localhost_is_valid():
    target = Target(base_url="http://localhost:8080")
    assert target.host == "localhost"
    assert target.port == 8080
    assert target.protocol == "http"


def test_loopback_ip_is_valid():
    target = Target(base_url="http://127.0.0.1:8080")
    assert target.host == "127.0.0.1"


def test_external_host_is_rejected():
    with pytest.raises(InvalidTargetError):
        Target(base_url="http://example.com")


def test_invalid_scheme_is_rejected():
    with pytest.raises(InvalidTargetError):
        Target(base_url="ftp://localhost:8080")
