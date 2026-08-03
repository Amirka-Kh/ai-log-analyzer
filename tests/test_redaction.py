from __future__ import annotations

from ai_ops_agent.core.redaction import Redactor


def test_jwt_redacted():
    r = Redactor()
    text = (
        "auth header eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0"
        ".dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"
    )
    out = r.redact(text)
    assert "eyJ" not in out
    assert "[REDACTED:jwt]" in out


def test_password_kv_redacted():
    r = Redactor()
    out = r.redact("db connect password=SuperSecret123 host=db1")
    assert "SuperSecret123" not in out


def test_aws_key_redacted():
    r = Redactor()
    out = r.redact("using key AKIAIOSFODNN7EXAMPLE for s3")
    assert "AKIAIOSFODNN7EXAMPLE" not in out


def test_bearer_redacted():
    r = Redactor()
    out = r.redact("Authorization: Bearer abcdef123456789tok")
    assert "abcdef123456789tok" not in out


def test_conn_string_redacted():
    r = Redactor()
    out = r.redact("dsn postgres://app:hunter2@db.internal:5432/prod")
    assert "hunter2" not in out


def test_email_redacted():
    r = Redactor()
    out = r.redact("user alice@example.com logged in")
    assert "alice@example.com" not in out


def test_private_key_block_redacted():
    r = Redactor()
    text = "-----BEGIN RSA PRIVATE KEY-----\nMIIEow\nsecretbits\n-----END RSA PRIVATE KEY-----"
    out = r.redact(text)
    assert "secretbits" not in out


def test_ip_optional():
    assert "10.0.0.5" in Redactor(redact_ips=False).redact("from 10.0.0.5")
    assert "10.0.0.5" not in Redactor(redact_ips=True).redact("from 10.0.0.5")


def test_disabled_passthrough():
    r = Redactor(enabled=False)
    text = "password=SuperSecret123"
    assert r.redact(text) == text


def test_hit_counter():
    r = Redactor()
    r.redact("password=a token=b alice@example.com")
    assert r.hits >= 3
