"""
03_BACKEND/tests/test_ssrf_hardening.py
Comprehensive test suite verifying SSRF defenses, IP representation normalization,
DNS resolution validation, route interception, and RBAC on the sandbox screenshot feature (F4).
"""
import ipaddress
import pytest
from unittest.mock import patch
from fastapi import HTTPException
from app.models import UserRole
from app.api.v1.routes_sandbox import (
    _validate_safe_sandbox_url,
    parse_ip_literal,
    is_prohibited_ip,
)
from tests.conftest import auth_headers, _make_user


def test_ip_representation_parsing():
    """Verifies that normal, decimal, octal, hex, and mapped IPs parse accurately."""
    # Standard dotted
    assert str(parse_ip_literal("127.0.0.1")) == "127.0.0.1"
    # Short dotted quad (127.1 -> 127.0.0.1)
    assert str(parse_ip_literal("127.1")) == "127.0.0.1"
    # Decimal integer
    assert str(parse_ip_literal("2130706433")) == "127.0.0.1"
    # Octal dotted
    assert str(parse_ip_literal("0177.0.0.1")) == "127.0.0.1"
    # Hex dotted
    assert str(parse_ip_literal("0x7f.0.0.1")) == "127.0.0.1"
    # IPv6 loopback
    assert str(parse_ip_literal("[::1]")) == "::1"
    # IPv4-mapped IPv6
    assert parse_ip_literal("[::ffff:127.0.0.1]") == ipaddress.ip_address("::ffff:127.0.0.1")
    # Regular domain name returns None
    assert parse_ip_literal("example.com") is None



def test_prohibited_ip_rejection():
    """All private, loopback, link-local, metadata, and mapped IPs are rejected."""
    blocked_ips = [
        "127.0.0.1",
        "127.0.0.2",
        "10.0.0.1",
        "10.254.0.1",
        "172.16.0.1",
        "172.31.255.255",
        "192.168.1.1",
        "169.254.169.254",
        "169.254.1.1",
        "0.0.0.0",
        "::1",
        "::",
        "::ffff:127.0.0.1",
        "::ffff:10.0.0.1",
        "::ffff:192.168.0.1",
        "fc00::1",
        "fd00::1",
    ]
    for ip_str in blocked_ips:
        ip = parse_ip_literal(ip_str)
        assert ip is not None, f"Failed to parse {ip_str}"
        blocked, reason = is_prohibited_ip(ip)
        assert blocked is True, f"Expected {ip_str} to be blocked, but passed!"


def test_ssrf_url_validation_denies_all_evasion_forms():
    """Verifies that _validate_safe_sandbox_url blocks all SSRF evasion variants."""
    evasion_urls = [
        "file:///etc/passwd",
        "ftp://internal.ftp/secret",
        "data:text/html,<html>alert(1)</html>",
        "gopher://127.0.0.1:70/",
        "http://localhost",
        "http://localhost:8000",
        "http://sub.localhost:8080",
        "http://server.local",
        "http://metadata.google.internal",
        "http://127.0.0.1",
        "http://127.1",
        "http://127.0.1",
        "http://2130706433",
        "http://0177.0.0.1",
        "http://0x7f.0.0.1",
        "http://[::1]",
        "http://[::ffff:127.0.0.1]",
        "http://169.254.169.254/latest/meta-data/",
        "http://10.0.0.1/status",
        "http://172.16.0.1/secret",
        "http://192.168.1.1/admin",
    ]
    for url in evasion_urls:
        with pytest.raises(HTTPException) as exc_info:
            _validate_safe_sandbox_url(url)
        assert exc_info.value.status_code == 400


def test_dns_resolution_private_ip_rejection():
    """A domain name that resolves to a private IP is blocked at DNS resolution."""
    with patch("socket.getaddrinfo") as mock_dns:
        # Mock DNS returning a private RFC 1918 address
        mock_dns.return_value = [
            (2, 1, 6, "", ("10.20.30.40", 80)),
        ]
        with pytest.raises(HTTPException) as exc_info:
            _validate_safe_sandbox_url("http://attacker-controlled-rebinding.test")
        assert exc_info.value.status_code == 400
        assert "Prohibited target" in exc_info.value.detail


def test_public_url_allowed():
    """Standard public domains pass validation."""
    with patch("socket.getaddrinfo") as mock_dns:
        mock_dns.return_value = [
            (2, 1, 6, "", ("93.184.216.34", 80)),
        ]
        safe = _validate_safe_sandbox_url("https://example.com/login")
        assert safe == "https://example.com/login"


def test_sandbox_screenshot_rbac_user_forbidden(client, db_session, org):
    """Regular USER role is rejected with 403 Forbidden."""
    regular_user = _make_user(db_session, org, "user_regular@acme.test", role=UserRole.USER)
    resp = client.get(
        "/api/v1/sandbox/screenshot?url=https://example.com",
        headers=auth_headers(regular_user),
    )
    assert resp.status_code == 403
    assert "restricted to ANALYST and ADMIN" in resp.json()["message"]


def test_sandbox_screenshot_disabled_by_default(client, user, monkeypatch):
    """When SANDBOX_SCREENSHOT_ENABLED is false, returns 403 Forbidden."""
    from app.config import get_settings
    settings = get_settings()
    monkeypatch.setattr(settings, "sandbox_screenshot_enabled", False)

    with patch("socket.getaddrinfo") as mock_dns:
        mock_dns.return_value = [(2, 1, 6, "", ("93.184.216.34", 80))]
        resp = client.get(
            "/api/v1/sandbox/screenshot?url=https://example.com",
            headers=auth_headers(user),
        )
        assert resp.status_code == 403
        assert "feature is disabled" in resp.json()["message"]
