from payloads.sqli import SqliPayloadProvider, detect_sql_error
from payloads.xss import XssPayloadProvider, is_reflected_unescaped


def test_sqli_payload_provider_returns_payloads():
    provider = SqliPayloadProvider()
    payloads = provider.get_payloads()
    assert len(payloads) > 0
    assert any(p.value == "'" for p in payloads)

    pairs = provider.get_boolean_pairs()
    assert len(pairs) > 0
    assert any(pair.true_payload == "' OR '1'='1" for pair in pairs)


def test_sqli_error_detection():
    # SQLite error detection
    match = detect_sql_error("sqlite3.OperationalError: near syntax error")
    assert match is not None
    engine, pattern = match
    assert engine == "sqlite"

    # MySQL error detection
    match_mysql = detect_sql_error("You have an error in your SQL syntax near '1'")
    assert match_mysql is not None
    assert match_mysql[0] == "mysql"

    # Postgres error detection
    match_pg = detect_sql_error("ERROR: parser: parse error at or near 'SELECT'")
    assert match_pg is not None
    assert match_pg[0] == "postgresql"

    # Normal text produces no match
    assert detect_sql_error("User alice logged in successfully.") is None


def test_xss_payload_provider_returns_probes():
    provider = XssPayloadProvider()
    probes = provider.generate_probes()
    assert len(probes) > 0
    for probe in probes:
        assert probe.canary in probe.rendered_payload
        assert "<xss_" in probe.rendered_payload

    payloads = provider.get_payloads()
    assert len(payloads) > 0


def test_xss_reflection_detection():
    canary = "test1234"

    # Unescaped reflection
    body_unescaped = f"<html><body><div><xss_{canary}></div></body></html>"
    assert is_reflected_unescaped(canary, body_unescaped) is True

    # Escaped reflection
    body_escaped = f"<html><body><div>&lt;xss_{canary}&gt;</div></body></html>"
    assert is_reflected_unescaped(canary, body_escaped) is False

    # Canary not present
    assert is_reflected_unescaped(canary, "<html><body>Hello</body></html>") is False
