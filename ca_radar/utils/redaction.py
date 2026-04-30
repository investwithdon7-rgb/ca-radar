"""Redaction helpers for PII-safe reports and snapshots.

UPNs are replaced with deterministic HMAC-SHA256 hashes so that:
- The same UPN always maps to the same token within a snapshot (findings remain linkable).
- Different snapshots use different salts, so tokens cannot be cross-correlated.
- The original UPN cannot be recovered from the token without the salt.

Usage:
    redactor = Redactor.generate()          # random salt, typical for new snapshots
    redactor = Redactor(salt=known_bytes)   # reproducible, e.g. for test fixtures

    safe_upn = redactor.redact_upn("alice@contoso.com")
    # -> "upn:3a7f2b..." (first 16 hex chars of HMAC)

    safe_report = redactor.redact_dict(graph_user_object)
"""

from __future__ import annotations

import hashlib
import hmac
import os
from typing import Any

_UPN_FIELDS = frozenset(
    {
        "userPrincipalName",
        "user_principal_name",
        "upn",
        "mail",
        "email",
        "onPremisesUserPrincipalName",
        "on_premises_user_principal_name",
        "proxyAddresses",
        "proxy_addresses",
    }
)

_DISPLAY_NAME_FIELDS = frozenset(
    {
        "displayName",
        "display_name",
        "userDisplayName",
        "user_display_name",
        "givenName",
        "given_name",
        "surname",
    }
)


class Redactor:
    """Stateful redactor bound to a per-snapshot salt."""

    def __init__(self, salt: bytes) -> None:
        self._salt = salt
        self.salt_hint = salt[:4].hex()  # first 8 hex chars — safe to store in manifest

    @classmethod
    def generate(cls) -> Redactor:
        """Create a redactor with a cryptographically random 32-byte salt."""
        return cls(salt=os.urandom(32))

    @classmethod
    def from_hint(cls, hint: str) -> Redactor:
        """Reconstruct a redactor from a stored hint (used in tests only).

        The hint is the first 4 bytes as hex; the rest is zeroed.  This is NOT
        secure and is only used to produce predictable fixture output.
        """
        prefix = bytes.fromhex(hint)
        salt = prefix + bytes(32 - len(prefix))
        return cls(salt=salt)

    # ------------------------------------------------------------------

    def redact_upn(self, upn: str) -> str:
        """Replace a UPN with a short, stable, non-reversible token."""
        digest = hmac.new(self._salt, upn.lower().encode(), hashlib.sha256).hexdigest()
        return f"upn:{digest[:16]}"

    def redact_display_name(self, name: str) -> str:
        digest = hmac.new(self._salt, name.encode(), hashlib.sha256).hexdigest()
        return f"name:{digest[:8]}"

    def redact_dict(self, obj: Any) -> Any:
        """Recursively redact a dict/list structure in place (returns new structure)."""
        return self._walk(obj)

    def _walk(self, obj: Any) -> Any:
        if isinstance(obj, dict):
            return {k: self._redact_value(k, v) for k, v in obj.items()}
        if isinstance(obj, list):
            return [self._walk(i) for i in obj]
        return obj

    def _redact_value(self, key: str, value: Any) -> Any:
        if value is None:
            return None
        if key in _UPN_FIELDS:
            if isinstance(value, str):
                return self.redact_upn(value)
            if isinstance(value, list):
                return [self.redact_upn(v) if isinstance(v, str) else v for v in value]
        if key in _DISPLAY_NAME_FIELDS and isinstance(value, str):
            return self.redact_display_name(value)
        return self._walk(value)
