"""Unit tests: Redactor — determinism, stability, and field coverage."""

from __future__ import annotations

from ca_radar.utils.redaction import Redactor


def test_redact_upn_is_stable() -> None:
    r = Redactor(salt=b"test-salt-" + b"\x00" * 22)
    token1 = r.redact_upn("alice@contoso.com")
    token2 = r.redact_upn("alice@contoso.com")
    assert token1 == token2
    assert token1.startswith("upn:")


def test_redact_upn_case_insensitive() -> None:
    r = Redactor(salt=b"x" * 32)
    assert r.redact_upn("Alice@contoso.com") == r.redact_upn("alice@contoso.com")


def test_different_upns_produce_different_tokens() -> None:
    r = Redactor(salt=b"y" * 32)
    assert r.redact_upn("alice@contoso.com") != r.redact_upn("bob@contoso.com")


def test_different_salts_produce_different_tokens() -> None:
    r1 = Redactor(salt=b"a" * 32)
    r2 = Redactor(salt=b"b" * 32)
    assert r1.redact_upn("alice@contoso.com") != r2.redact_upn("alice@contoso.com")


def test_redact_dict_replaces_upn_fields() -> None:
    r = Redactor(salt=b"z" * 32)
    obj = {
        "id": "user-001",
        "userPrincipalName": "alice@contoso.com",
        "displayName": "Alice Smith",
        "accountEnabled": True,
    }
    result = r.redact_dict(obj)

    assert result["id"] == "user-001"
    assert result["accountEnabled"] is True
    assert result["userPrincipalName"].startswith("upn:")
    assert result["userPrincipalName"] != "alice@contoso.com"
    assert result["displayName"].startswith("name:")


def test_redact_dict_nested() -> None:
    r = Redactor(salt=b"n" * 32)
    obj = {
        "users": [
            {"id": "u1", "userPrincipalName": "alice@contoso.com"},
            {"id": "u2", "userPrincipalName": "bob@contoso.com"},
        ]
    }
    result = r.redact_dict(obj)
    assert result["users"][0]["userPrincipalName"].startswith("upn:")
    assert result["users"][1]["userPrincipalName"].startswith("upn:")
    assert result["users"][0]["userPrincipalName"] != result["users"][1]["userPrincipalName"]


def test_redact_dict_none_values_preserved() -> None:
    r = Redactor(salt=b"m" * 32)
    obj = {"userPrincipalName": None, "id": "u1"}
    result = r.redact_dict(obj)
    assert result["userPrincipalName"] is None


def test_salt_hint_is_set() -> None:
    salt = bytes.fromhex("deadbeef") + b"\x00" * 28
    r = Redactor(salt=salt)
    assert r.salt_hint == "deadbeef"


def test_generate_produces_random_salts() -> None:
    r1 = Redactor.generate()
    r2 = Redactor.generate()
    assert r1._salt != r2._salt


def test_redact_proxy_addresses_list() -> None:
    r = Redactor(salt=b"p" * 32)
    obj = {"proxyAddresses": ["SMTP:alice@contoso.com", "smtp:alice@contoso.onmicrosoft.com"]}
    result = r.redact_dict(obj)
    for addr in result["proxyAddresses"]:
        assert addr.startswith("upn:")
