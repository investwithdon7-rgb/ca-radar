"""Unit tests: SnapshotStore read/write round-trips."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

import pytest

from ca_radar.snapshot.models import ConditionalAccessPolicy, PolicyState, SnapshotManifest
from ca_radar.snapshot.store import (
    ResourceNotFoundError,
    SnapshotStore,
    SnapshotVersionError,
)


def _make_manifest(tenant_id: str = "contoso.onmicrosoft.com") -> SnapshotManifest:
    return SnapshotManifest(
        tenant_id=tenant_id,
        captured_at=datetime(2024, 6, 1, 12, 0, 0, tzinfo=UTC),
        tool_version="0.1.0",
        resources_captured=["conditional_access_policies"],
    )


def _make_policy() -> dict:
    return {
        "id": "policy-001",
        "displayName": "Require MFA",
        "state": "enabled",
        "conditions": {
            "users": {
                "includeUsers": ["All"],
                "excludeUsers": [],
                "includeGroups": [],
                "excludeGroups": [],
                "includeRoles": [],
                "excludeRoles": [],
            },
            "applications": {
                "includeApplications": ["All"],
                "excludeApplications": [],
                "includeUserActions": [],
                "includeAuthenticationContextClassReferences": [],
            },
        },
        "grantControls": {
            "operator": "OR",
            "builtInControls": ["mfa"],
            "customAuthenticationFactors": [],
            "termsOfUse": [],
        },
    }


def test_write_and_read_resource_list(tmp_path: Path) -> None:
    store = SnapshotStore(base_dir=tmp_path)
    snap = store.new_snapshot_path("contoso.onmicrosoft.com")

    policies = [_make_policy()]
    store.write_resource(snap, "conditional_access_policies", policies)

    result = store.read_resource_list(snap, "conditional_access_policies", ConditionalAccessPolicy)
    assert len(result) == 1
    assert result[0].id == "policy-001"
    assert result[0].state == PolicyState.enabled


def test_write_and_read_manifest(tmp_path: Path) -> None:
    store = SnapshotStore(base_dir=tmp_path)
    snap = store.new_snapshot_path("contoso.onmicrosoft.com")
    manifest = _make_manifest()

    store.write_manifest(snap, manifest)
    loaded = store.read_manifest(snap)

    assert loaded.tenant_id == "contoso.onmicrosoft.com"
    assert loaded.schema_version == "1"
    assert "conditional_access_policies" in loaded.resources_captured


def test_latest_snapshot_path(tmp_path: Path) -> None:
    store = SnapshotStore(base_dir=tmp_path)

    snap1 = store.new_snapshot_path("contoso.onmicrosoft.com", datetime(2024, 1, 1, tzinfo=UTC))
    snap2 = store.new_snapshot_path("contoso.onmicrosoft.com", datetime(2024, 6, 1, tzinfo=UTC))

    store.write_manifest(snap1, _make_manifest())
    store.write_manifest(snap2, _make_manifest())

    latest = store.latest_snapshot_path("contoso.onmicrosoft.com")
    assert latest is not None
    assert "20240601" in latest.name


def test_list_tenants(tmp_path: Path) -> None:
    store = SnapshotStore(base_dir=tmp_path)
    for tenant in ["contoso.onmicrosoft.com", "fabrikam.onmicrosoft.com"]:
        snap = store.new_snapshot_path(tenant)
        store.write_manifest(snap, _make_manifest(tenant))

    tenants = store.list_tenants()
    assert "contoso.onmicrosoft.com" in tenants
    assert "fabrikam.onmicrosoft.com" in tenants


def test_resource_not_found_raises(tmp_path: Path) -> None:
    store = SnapshotStore(base_dir=tmp_path)
    snap = store.new_snapshot_path("contoso.onmicrosoft.com")
    snap.mkdir(parents=True, exist_ok=True)

    with pytest.raises(ResourceNotFoundError):
        store.read_resource_raw(snap, "nonexistent_resource")


def test_snapshot_version_mismatch_raises(tmp_path: Path) -> None:
    store = SnapshotStore(base_dir=tmp_path)
    snap = store.new_snapshot_path("contoso.onmicrosoft.com")
    snap.mkdir(parents=True, exist_ok=True)

    bad_manifest = {
        "schemaVersion": "99",
        "tenantId": "x",
        "capturedAt": "2024-01-01T00:00:00Z",
        "toolVersion": "0.0.1",
    }
    (snap / "manifest.json").write_text(json.dumps(bad_manifest), encoding="utf-8")

    with pytest.raises(SnapshotVersionError):
        store.read_manifest(snap)


def test_no_tenants_returns_empty(tmp_path: Path) -> None:
    store = SnapshotStore(base_dir=tmp_path / "empty")
    assert store.list_tenants() == []
    assert store.latest_snapshot_path("nobody") is None
