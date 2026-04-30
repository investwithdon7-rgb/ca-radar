"""End-to-end test: collector against a fake Graph loaded from fixtures.

Uses a FakeGraphClient that serves responses from tests/fixtures/fake_graph/
instead of hitting the real Microsoft Graph API.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

from ca_radar.graph.client import GraphClient
from ca_radar.snapshot.collector import collect_snapshot
from ca_radar.snapshot.models import ConditionalAccessPolicy
from ca_radar.snapshot.store import SnapshotStore

FIXTURES_DIR = Path(__file__).parent.parent / "fixtures" / "fake_graph"


# ---------------------------------------------------------------------------
# Fake Graph client that reads from fixture files
# ---------------------------------------------------------------------------


class _FakeAuth:
    def get_auth_header(self) -> dict[str, str]:
        return {"Authorization": "Bearer fake"}


class FakeGraphClient(GraphClient):
    """GraphClient subclass that reads responses from fixture JSON files.

    Overrides get_all / get_single instead of making HTTP calls.
    """

    def __init__(self) -> None:
        super().__init__(auth=_FakeAuth())
        self._fixture_dir = FIXTURES_DIR

    def _load(self, filename: str) -> Any:
        path = self._fixture_dir / filename
        if not path.exists():
            return None
        return json.loads(path.read_text(encoding="utf-8"))

    async def get_all(self, path: str, params: dict[str, Any] | None = None) -> list[Any]:
        resource = _path_to_resource(path)
        data = self._load(f"{resource}.json")
        return data if isinstance(data, list) else []

    async def get_single(
        self, path: str, params: dict[str, Any] | None = None
    ) -> dict[str, Any] | None:
        resource = _path_to_resource(path)
        data = self._load(f"{resource}.json")
        return data if isinstance(data, dict) else None


def _path_to_resource(path: str) -> str:
    """Map a Graph URL path to a fixture file stem."""
    _map = {
        "identity/conditionalAccess/policies": "conditional_access_policies",
        "identity/conditionalAccess/namedLocations": "named_locations",
        "identity/conditionalAccess/authenticationStrength/policies": "authentication_strength_policies",
        "policies/authenticationMethodsPolicy": "authentication_methods_policy",
        "users": "users",
        "groups": "groups",
        "directoryRoles": "directory_roles",
        "roleManagement/directory/roleAssignments": "role_assignments",
        "roleManagement/directory/roleEligibilitySchedules": "pim_eligible_role_assignments",
        "servicePrincipals": "service_principals",
        "applications": "applications",
        "deviceManagement/deviceCompliancePolicies": "device_compliance_policies",
        "identityProtection/riskyUsers": "risky_users",
        "auditLogs/signIns": "sign_in_logs",
    }
    # Strip leading slash and base URL if present
    clean = path.replace("https://graph.microsoft.com/v1.0/", "").lstrip("/")
    return _map.get(clean, clean.replace("/", "_"))


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_collector_writes_snapshot_structure(tmp_path: Path) -> None:
    """Collector must write all expected resource files and a manifest."""
    store = SnapshotStore(base_dir=tmp_path)
    client = FakeGraphClient()
    ts = datetime(2024, 6, 1, 12, 0, 0, tzinfo=UTC)

    result = await collect_snapshot(
        client=client,
        store=store,
        tenant_id="contoso.onmicrosoft.com",
        redact=True,
        captured_at=ts,
    )

    # Snapshot directory exists
    assert result.snapshot_path.exists()

    # Manifest is present and readable
    manifest = store.read_manifest(result.snapshot_path)
    assert manifest.tenant_id == "contoso.onmicrosoft.com"
    assert manifest.redacted is True
    assert manifest.schema_version == "1"

    # Core resource files exist
    for resource in ["conditional_access_policies", "users", "groups", "named_locations"]:
        assert (result.snapshot_path / f"{resource}.json").exists(), f"Missing {resource}.json"


@pytest.mark.asyncio
async def test_collector_captures_ca_policies(tmp_path: Path) -> None:
    """CA policies from fixture are parsed and stored correctly."""
    store = SnapshotStore(base_dir=tmp_path)
    client = FakeGraphClient()

    result = await collect_snapshot(
        client=client,
        store=store,
        tenant_id="contoso.onmicrosoft.com",
        redact=False,
    )

    policies = store.read_resource_list(
        result.snapshot_path, "conditional_access_policies", ConditionalAccessPolicy
    )
    assert len(policies) == 2
    policy_names = {p.display_name for p in policies}
    assert "Require MFA for all users" in policy_names
    assert "Block legacy authentication" in policy_names


@pytest.mark.asyncio
async def test_collector_redacts_upns(tmp_path: Path) -> None:
    """With redaction on, UPNs in the snapshot must not match originals."""
    store = SnapshotStore(base_dir=tmp_path)
    client = FakeGraphClient()

    result = await collect_snapshot(
        client=client,
        store=store,
        tenant_id="contoso.onmicrosoft.com",
        redact=True,
    )

    raw_users = store.read_resource_raw(result.snapshot_path, "users")
    assert isinstance(raw_users, list)
    for user in raw_users:
        upn = user.get("userPrincipalName", "")
        assert "@contoso.com" not in upn, f"UPN was not redacted: {upn}"
        assert upn.startswith("upn:")


@pytest.mark.asyncio
async def test_collector_no_redact_preserves_upns(tmp_path: Path) -> None:
    """With --no-redact, UPNs are stored in plain text."""
    store = SnapshotStore(base_dir=tmp_path)
    client = FakeGraphClient()

    result = await collect_snapshot(
        client=client,
        store=store,
        tenant_id="contoso.onmicrosoft.com",
        redact=False,
    )

    raw_users = store.read_resource_raw(result.snapshot_path, "users")
    upns = [u["userPrincipalName"] for u in raw_users]
    assert "alice@contoso.com" in upns


@pytest.mark.asyncio
async def test_collector_records_failed_resources(tmp_path: Path) -> None:
    """Resources that raise during collection are recorded as failed, not crash."""

    class PartiallyBrokenClient(FakeGraphClient):
        async def get_all(self, path: str, params: object = None) -> list:
            if "servicePrincipals" in path:
                raise RuntimeError("simulated Graph error")
            return await super().get_all(path, params)

    store = SnapshotStore(base_dir=tmp_path)
    client = PartiallyBrokenClient()

    result = await collect_snapshot(
        client=client,
        store=store,
        tenant_id="contoso.onmicrosoft.com",
        redact=False,
    )

    assert "service_principals" in result.resources_failed
    # Other resources should still be captured
    assert "conditional_access_policies" in result.resources_captured


@pytest.mark.asyncio
async def test_collector_snapshot_path_uses_timestamp(tmp_path: Path) -> None:
    """Snapshot directory name embeds the UTC timestamp."""
    store = SnapshotStore(base_dir=tmp_path)
    client = FakeGraphClient()
    ts = datetime(2024, 11, 25, 14, 30, 0, tzinfo=UTC)

    result = await collect_snapshot(
        client=client,
        store=store,
        tenant_id="contoso.onmicrosoft.com",
        captured_at=ts,
    )

    assert "20241125T143000Z" in result.snapshot_path.name


@pytest.mark.asyncio
async def test_collector_manifest_lists_captured_resources(tmp_path: Path) -> None:
    """Manifest resources_captured matches result.resources_captured."""
    store = SnapshotStore(base_dir=tmp_path)
    client = FakeGraphClient()

    result = await collect_snapshot(
        client=client,
        store=store,
        tenant_id="contoso.onmicrosoft.com",
    )

    manifest = store.read_manifest(result.snapshot_path)
    assert set(manifest.resources_captured) == set(result.resources_captured)
