"""Tenant configuration models for MSP portfolio mode.

Consumed by ``ca-radar scan-all --tenants tenants.yaml``.

YAML format
-----------
::

    tenants:
      - id: contoso.onmicrosoft.com
        name: Contoso Ltd          # optional display name
        auth_mode: delegated       # delegated (default) | app
        client_id: ""              # required for app auth; optional for delegated
        cert_path: ""              # path to PEM cert (app auth)
        client_secret: ""          # client secret (app auth, less secure)

      - id: fabrikam.onmicrosoft.com
        name: Fabrikam Inc
        auth_mode: app
        client_id: "11111111-0000-0000-0000-000000000000"
        cert_path: "/path/to/cert.pem"
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

import yaml


@dataclass
class TenantConfig:
    """Configuration for a single tenant scan."""

    id: str
    name: str = ""  # human-readable display name; falls back to `id`
    auth_mode: str = "delegated"
    client_id: str = ""
    cert_path: str = ""
    client_secret: str = ""

    @property
    def display_name(self) -> str:
        return self.name or self.id


@dataclass
class TenantsFile:
    """Parsed tenants YAML file."""

    tenants: list[TenantConfig] = field(default_factory=list)

    @classmethod
    def from_yaml(cls, path: str | Path) -> TenantsFile:
        """Load and parse a tenants YAML file.

        Args:
            path: Path to the YAML file.

        Returns:
            :class:`TenantsFile` with the parsed tenants list.

        Raises:
            FileNotFoundError: If the file does not exist.
            ValueError:        If the YAML is missing the ``tenants`` key
                               or any tenant is missing an ``id``.
        """
        p = Path(path)
        if not p.exists():
            raise FileNotFoundError(f"Tenants file not found: {p}")

        with p.open(encoding="utf-8") as fh:
            raw = yaml.safe_load(fh)

        if not isinstance(raw, dict) or "tenants" not in raw:
            raise ValueError(f"Tenants file {p} must contain a top-level 'tenants' list.")

        tenants: list[TenantConfig] = []
        for i, entry in enumerate(raw["tenants"] or []):
            if "id" not in entry:
                raise ValueError(
                    f"Tenant entry #{i + 1} in {p} is missing the required 'id' field."
                )
            tenants.append(
                TenantConfig(
                    id=str(entry["id"]),
                    name=str(entry.get("name") or ""),
                    auth_mode=str(entry.get("auth_mode") or "delegated"),
                    client_id=str(entry.get("client_id") or ""),
                    cert_path=str(entry.get("cert_path") or ""),
                    client_secret=str(entry.get("client_secret") or ""),
                )
            )

        return cls(tenants=tenants)
