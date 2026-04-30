"""Persistent user configuration for ca-radar.

Configuration is stored at ``~/.ca-radar/config.yaml`` and provides
defaults for every ``ca-radar scan`` invocation.  Command-line flags and
environment variables always override saved values.

Typical config file::

    tenant: patientadvocacy.eu
    client_id: 00000000-0000-0000-0000-000000000000
    auth_mode: delegated
    out: ./snapshot
    redact: true
    concurrency: 5
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

# Default location for the config file
_CONFIG_DIR = Path.home() / ".ca-radar"
_CONFIG_FILE = _CONFIG_DIR / "config.yaml"


def config_path() -> Path:
    """Return the path to the user config file (``~/.ca-radar/config.yaml``)."""
    return _CONFIG_FILE


@dataclass
class RadarConfig:
    """Persisted configuration for ca-radar.

    All fields are optional — a freshly installed tool has no config.
    """

    tenant: str = ""
    client_id: str = ""
    auth_mode: str = "delegated"
    cert_path: str = ""
    client_secret: str = ""
    out: str = "./snapshot"
    redact: bool = True
    concurrency: int = 5
    # Stored extras (forward compat) — not surfaced in the wizard
    _extra: dict[str, Any] = field(default_factory=dict, repr=False, compare=False)

    # ------------------------------------------------------------------ #
    # Persistence
    # ------------------------------------------------------------------ #

    @classmethod
    def load(cls, path: Path | None = None) -> RadarConfig:
        """Load config from *path* (defaults to ``~/.ca-radar/config.yaml``).

        Returns an empty ``RadarConfig`` if the file does not exist.
        """
        p = path or _CONFIG_FILE
        if not p.exists():
            return cls()
        try:
            raw: dict[str, Any] = yaml.safe_load(p.read_text(encoding="utf-8")) or {}
        except yaml.YAMLError:
            return cls()

        # Pull known fields; stash the rest in _extra for round-trip safety
        known = {
            "tenant",
            "client_id",
            "auth_mode",
            "cert_path",
            "client_secret",
            "out",
            "redact",
            "concurrency",
        }
        kwargs: dict[str, Any] = {}
        extra: dict[str, Any] = {}
        for k, v in raw.items():
            if k in known:
                kwargs[k] = v
            else:
                extra[k] = v

        obj = cls(**kwargs)
        obj._extra = extra
        return obj

    def save(self, path: Path | None = None) -> Path:
        """Write config to *path* (defaults to ``~/.ca-radar/config.yaml``).

        Creates parent directories if needed.  Returns the file path.
        """
        p = path or _CONFIG_FILE
        p.parent.mkdir(parents=True, exist_ok=True)

        data: dict[str, Any] = {**self._extra}
        # Write known fields — skip empty strings / falsy-but-meaningful values
        if self.tenant:
            data["tenant"] = self.tenant
        if self.client_id:
            data["client_id"] = self.client_id
        data["auth_mode"] = self.auth_mode
        if self.cert_path:
            data["cert_path"] = self.cert_path
        if self.client_secret:
            data["client_secret"] = self.client_secret
        data["out"] = self.out
        data["redact"] = self.redact
        data["concurrency"] = self.concurrency

        p.write_text(
            yaml.safe_dump(data, default_flow_style=False, allow_unicode=True),
            encoding="utf-8",
        )
        return p

    # ------------------------------------------------------------------ #
    # Merge helpers
    # ------------------------------------------------------------------ #

    def merge_cli(
        self,
        *,
        tenant: str = "",
        client_id: str = "",
        auth_mode: str = "",
        cert_path: str = "",
        client_secret: str = "",
        out: str = "",
        redact: bool | None = None,
        concurrency: int | None = None,
    ) -> RadarConfig:
        """Return a *new* RadarConfig with CLI overrides applied.

        Only non-empty / non-None CLI values override the saved config.
        """
        from copy import copy

        merged = copy(self)
        if tenant:
            merged.tenant = tenant
        if client_id:
            merged.client_id = client_id
        if auth_mode:
            merged.auth_mode = auth_mode
        if cert_path:
            merged.cert_path = cert_path
        if client_secret:
            merged.client_secret = client_secret
        if out:
            merged.out = out
        if redact is not None:
            merged.redact = redact
        if concurrency is not None:
            merged.concurrency = concurrency
        return merged
