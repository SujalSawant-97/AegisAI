import pytest

from core.endpoint import Endpoint, Parameter, ParameterLocation
from core.finding import Finding, Severity
from core.scan_context import AuthContext, ScanConfig, ScanContext
from core.target import Target


def test_scan_context_initialization_defaults():
    target = Target(base_url="http://localhost:8080")
    context = ScanContext(target=target)

    assert context.target == target
    assert context.endpoints == []
    assert context.http_client is None
    assert context.findings == []
    assert context.completed_scanners == []
    assert context.scanner_errors == []
    assert context.scanned_endpoints == set()
    assert context.scan_id.startswith("SCAN-")


def test_scan_context_add_endpoint_deduplication():
    target = Target(base_url="http://localhost:8080")
    context = ScanContext(target=target)

    ep1 = Endpoint(method="GET", path="/api/users")
    ep2 = Endpoint(method="GET", path="/api/users")
    ep3 = Endpoint(method="POST", path="/api/users")

    context.add_endpoint(ep1)
    context.add_endpoint(ep2)  # Duplicate method + path
    context.add_endpoint(ep3)

    assert len(context.endpoints) == 2
    assert {e.identifier() for e in context.endpoints} == {"GET /api/users", "POST /api/users"}


def test_scan_context_add_endpoints_batch():
    target = Target(base_url="http://localhost:8080")
    context = ScanContext(target=target)

    eps = [
        Endpoint(method="GET", path="/a"),
        Endpoint(method="GET", path="/b"),
        Endpoint(method="GET", path="/a"),
    ]
    context.add_endpoints(eps)
    assert len(context.endpoints) == 2


def test_scan_context_add_findings_and_scanned_endpoints():
    target = Target(base_url="http://localhost:8080")
    context = ScanContext(target=target)

    finding1 = Finding(
        scanner="sqli",
        vulnerability_type="SQL_INJECTION_ERROR_BASED",
        severity=Severity.CRITICAL,
        confidence=0.95,
        title="SQLi in /search",
        description="Error-based SQLi detected",
        endpoint="/search",
        parameter="q",
    )
    finding2 = Finding(
        scanner="xss",
        vulnerability_type="REFLECTED_XSS",
        severity=Severity.HIGH,
        confidence=0.9,
        title="XSS in /search",
        description="Reflected XSS detected",
        endpoint="/search",
        parameter="q",
    )

    context.add_findings("sqli", [finding1])
    assert context.completed_scanners == ["sqli"]
    assert len(context.findings) == 1
    assert "/search" in context.scanned_endpoints

    context.add_findings("xss", [finding2])
    assert context.completed_scanners == ["sqli", "xss"]
    assert len(context.findings) == 2


def test_scan_context_add_error():
    target = Target(base_url="http://localhost:8080")
    context = ScanContext(target=target)

    context.add_error("cors", "Connection refused")
    assert len(context.scanner_errors) == 1
    assert context.scanner_errors[0].scanner == "cors"
    assert context.scanner_errors[0].error == "Connection refused"


def test_scan_context_filters_and_summary():
    target = Target(base_url="http://localhost:8080")
    context = ScanContext(target=target)

    f_crit = Finding(
        scanner="sqli",
        vulnerability_type="SQL_INJECTION_ERROR_BASED",
        severity=Severity.CRITICAL,
        confidence=0.95,
        title="Critical SQLi",
        description="Critical test",
    )
    f_med = Finding(
        scanner="security_headers",
        vulnerability_type="MISSING_SECURITY_HEADER",
        severity=Severity.MEDIUM,
        confidence=0.8,
        title="Missing CSP",
        description="Medium test",
    )

    context.add_findings("sqli", [f_crit])
    context.add_findings("security_headers", [f_med])

    assert context.get_findings_by_severity(Severity.CRITICAL) == [f_crit]
    assert context.get_findings_by_severity("medium") == [f_med]
    assert context.get_findings_by_scanner("sqli") == [f_crit]

    summary = context.get_summary()
    assert summary["total_findings"] == 2
    assert summary["findings_by_severity"]["CRITICAL"] == 1
    assert summary["findings_by_severity"]["MEDIUM"] == 1
    assert summary["findings_by_severity"]["LOW"] == 0
    assert summary["completed_scanners"] == ["sqli", "security_headers"]

    as_dict = context.to_dict()
    assert as_dict["scan_id"] == context.scan_id
    assert "summary" in as_dict
    assert len(as_dict["findings"]) == 2
