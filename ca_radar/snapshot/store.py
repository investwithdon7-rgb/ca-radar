"""Snapshot store — reads and writes point-in-time tenant state to disk.

Layout on disk:
    snapshot/<tenantId>/<utcTimestamp>/manifest.json
    snapshot/<tenantId>/<utcTimestamp>/conditional_access_policies.json
    snapshot/<tenantId>/<utcTimestamp>/named_locations.json
    ...

The store is the boundary between live Graph access and analysis.
Analysers always run against a store, never directly against Graph.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, TypeVar, cast

from pydantic import BaseModel

from ca_radar.snapshot.models import SNAPSHOT_SCHEMA_VERSION, SnapshotManifest

T = TypeVar("T", bound=BaseModel)

# Timestamp format used in directory names — sortable, filesystem-safe.
_TS_FMT = "%Y%m%dT%H%M%SZ"

# Canonical resource file names (without .json).
RESOURCE_NAMES = [
    "conditional_access_policies",
    "named_locations",
    "authentication_strength_policies",
    "authentication_methods_policy",
    "users",
    "groups",
    "directory_roles",
    "role_assignments",
    "pim_eligible_role_assignments",
    "service_principals",
    "applications",
    "device_compliance_policies",
    "identity_protection_summary",
    "risky_users",
    "sign_in_logs",
]


class SnapshotStore:
    """Read/write access to snapshots stored on disk."""

    def __init__(self, base_dir: str | Path = "snapshot") -> None:
        self.base_dir = Path(base_dir)

    # ------------------------------------------------------------------
    # Writing
    # ------------------------------------------------------------------

    def new_snapshot_path(self, tenant_id: str, captured_at: datetime | None = None) -> Path:
        """Return a fresh (not-yet-created) path for a new snapshot."""
        ts = (captured_at or datetime.now(UTC)).strftime(_TS_FMT)
        return self.base_dir / _sanitise(tenant_id) / ts

    def write_resource(
        self,
        snapshot_path: Path,
        resource_name: str,
        data: list[Any] | dict[str, Any],
    ) -> None:
        """Serialise *data* to ``<snapshot_path>/<resource_name>.json``."""
        snapshot_path.mkdir(parents=True, exist_ok=True)
        dest = snapshot_path / f"{resource_name}.json"
        dest.write_text(
            json.dumps(_serialisable(data), indent=2, ensure_ascii=False),
            encoding="utf-8",
        )

    def write_manifest(self, snapshot_path: Path, manifest: SnapshotManifest) -> None:
        snapshot_path.mkdir(parents=True, exist_ok=True)
        dest = snapshot_path / "manifest.json"
        dest.write_text(
            manifest.model_dump_json(indent=2, by_alias=True),
            encoding="utf-8",
        )

    # ------------------------------------------------------------------
    # Reading
    # ------------------------------------------------------------------

    def latest_snapshot_path(self, tenant_id: str) -> Path | None:
        """Return the most-recent snapshot path for *tenant_id*, or None."""
        tenant_dir = self.base_dir / _sanitise(tenant_id)
        if not tenant_dir.exists():
            return None
        snapshots = sorted(tenant_dir.iterdir(), reverse=True)
        return snapshots[0] if snapshots else None

    def read_manifest(self, snapshot_path: Path) -> SnapshotManifest:
        data = _load_json(snapshot_path / "manifest.json")
        manifest = SnapshotManifest.model_validate(data)
        if manifest.schema_version != SNAPSHOT_SCHEMA_VERSION:
            raise SnapshotVersionError(
                f"Snapshot schema version {manifest.schema_version!r} is not supported "
                f"(expected {SNAPSHOT_SCHEMA_VERSION!r}). "
                "Re-collect the snapshot with the current version of ca-radar."
            )
        return manifest

    def read_resource_raw(
        self, snapshot_path: Path, resource_name: str
    ) -> list[Any] | dict[str, Any]:
        """Return the raw parsed JSON for a resource file."""
        path = snapshot_path / f"{resource_name}.json"
        if not path.exists():
            raise ResourceNotFoundError(f"{resource_name} not found in snapshot at {snapshot_path}")
        return cast("list[Any] | dict[str, Any]", _load_json(path))

    def read_resource_list(
        self,
        snapshot_path: Path,
        resource_name: str,
        model: type[T],
    ) -> list[T]:
        """Read a resource file that contains a JSON array and parse each item as *model*."""
        raw = self.read_resource_raw(snapshot_path, resource_name)
        if not isinstance(raw, list):
            raise ValueError(f"{resource_name} is not a JSON array")
        return [model.model_validate(item) for item in raw]

    def read_resource_single(
        self,
        snapshot_path: Path,
        resource_name: str,
        model: type[T],
    ) -> T:
        """Read a resource file that contains a single JSON object."""
        raw = self.read_resource_raw(snapshot_path, resource_name)
        if not isinstance(raw, dict):
            raise ValueError(f"{resource_name} is not a JSON object")
        return model.model_validate(raw)

    def list_tenants(self) -> list[str]:
        """Return tenant IDs that have at least one snapshot."""
        if not self.base_dir.exists():
            return []
        return [d.name for d in self.base_dir.iterdir() if d.is_dir()]

    def list_snapshots(self, tenant_id: str) -> list[Path]:
        """Return all snapshot paths for *tenant_id*, newest first."""
        tenant_dir = self.base_dir / _sanitise(tenant_id)
        if not tenant_dir.exists():
            return []
        return sorted(tenant_dir.iterdir(), reverse=True)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _sanitise(tenant_id: str) -> str:
    """Make tenant ID safe for use as a directory name."""
    return tenant_id.replace("/", "_").replace("\\", "_").replace(":", "_")


def _load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def _serialisable(obj: Any) -> Any:
    """Recursively convert Pydantic models and datetimes to JSON-safe types."""
    if isinstance(obj, BaseModel):
        return json.loads(obj.model_dump_json(by_alias=True))
    if isinstance(obj, datetime):
        return obj.isoformat()
    if isinstance(obj, list):
        return [_serialisable(i) for i in obj]
    if isinstance(obj, dict):
        return {k: _serialisable(v) for k, v in obj.items()}
    return obj


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------


class SnapshotVersionError(Exception):
    """Raised when a snapshot was created by an incompatible schema version."""


class ResourceNotFoundError(Exception):
    """Raised when a requested resource file is missing from a snapshot."""
