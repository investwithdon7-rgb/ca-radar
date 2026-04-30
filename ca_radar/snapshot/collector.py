"""Snapshot collector — orchestrates concurrent Graph resource collection.

Runs all endpoint functions in parallel behind a semaphore so we don't
hammer Graph with too many simultaneous requests on large tenants.

Usage:
    async with GraphClient(auth) as client:
        result = await collect_snapshot(
            client=client,
            store=SnapshotStore("./snapshot"),
            tenant_id="contoso.onmicrosoft.com",
        )
    print(result.summary())
"""

from __future__ import annotations

import asyncio
import logging
import time
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from ca_radar import __version__
from ca_radar.graph.client import GraphClient
from ca_radar.graph.endpoints import (
    get_applications,
    get_authentication_methods_policy,
    get_authentication_strength_policies,
    get_ca_policies,
    get_device_compliance_policies,
    get_directory_roles,
    get_groups,
    get_identity_protection_summary,
    get_named_locations,
    get_pim_eligible_assignments,
    get_risky_users,
    get_role_assignments,
    get_service_principals,
    get_sign_in_logs,
    get_users,
)
from ca_radar.snapshot.models import SnapshotManifest
from ca_radar.snapshot.store import SnapshotStore
from ca_radar.utils.redaction import Redactor

log = logging.getLogger(__name__)

DEFAULT_CONCURRENCY = 5


@dataclass
class CollectionResult:
    tenant_id: str
    snapshot_path: Path
    captured_at: datetime
    resources_captured: list[str] = field(default_factory=list)
    resources_failed: list[str] = field(default_factory=list)
    scope_warnings: list[str] = field(default_factory=list)
    elapsed_seconds: float = 0.0

    def summary(self) -> str:
        lines = [
            f"Tenant      : {self.tenant_id}",
            f"Snapshot    : {self.snapshot_path}",
            f"Captured    : {len(self.resources_captured)} resources",
            f"Failed      : {len(self.resources_failed)} resources",
            f"Warnings    : {len(self.scope_warnings)} scope warnings",
            f"Duration    : {self.elapsed_seconds:.1f}s",
        ]
        if self.resources_failed:
            lines.append(f"Failed list : {', '.join(self.resources_failed)}")
        if self.scope_warnings:
            for w in self.scope_warnings:
                lines.append(f"  ⚠ {w}")
        return "\n".join(lines)


async def collect_snapshot(
    client: GraphClient,
    store: SnapshotStore,
    tenant_id: str,
    redact: bool = True,
    concurrency: int = DEFAULT_CONCURRENCY,
    captured_at: datetime | None = None,
) -> CollectionResult:
    """Collect all Graph resources and write them to the snapshot store.

    Args:
        client:      Authenticated GraphClient (already opened).
        store:       SnapshotStore to write into.
        tenant_id:   Tenant ID or domain name.
        redact:      Hash UPNs in the snapshot (default True).
        concurrency: Max parallel Graph requests (default 5).
        captured_at: Override the snapshot timestamp (for testing).
    """
    ts = captured_at or datetime.now(UTC)
    snapshot_path = store.new_snapshot_path(tenant_id, ts)
    redactor = Redactor.generate() if redact else None
    sem = asyncio.Semaphore(concurrency)

    result = CollectionResult(
        tenant_id=tenant_id,
        snapshot_path=snapshot_path,
        captured_at=ts,
    )

    start = time.monotonic()

    # Build the task list: (resource_name, coroutine, is_list)
    tasks: list[tuple[str, Any, bool]] = [
        ("conditional_access_policies", get_ca_policies(client), True),
        ("named_locations", get_named_locations(client), True),
        ("authentication_strength_policies", get_authentication_strength_policies(client), True),
        ("authentication_methods_policy", get_authentication_methods_policy(client), False),
        ("users", get_users(client), True),
        ("groups", get_groups(client), True),
        ("directory_roles", get_directory_roles(client), True),
        ("role_assignments", get_role_assignments(client), True),
        ("pim_eligible_role_assignments", get_pim_eligible_assignments(client), True),
        ("service_principals", get_service_principals(client), True),
        ("applications", get_applications(client), True),
        ("device_compliance_policies", get_device_compliance_policies(client), True),
        ("identity_protection_summary", get_identity_protection_summary(client), False),
        ("risky_users", get_risky_users(client), True),
        ("sign_in_logs", get_sign_in_logs(client), True),
    ]

    async def run_task(name: str, coro: Any) -> tuple[str, Any]:
        async with sem:
            try:
                data = await coro
                log.debug("Collected %s", name)
                return name, data
            except Exception as exc:
                log.warning("Failed to collect %s: %s", name, exc)
                return name, None

    gathered = await asyncio.gather(*[run_task(n, c) for n, c, _ in tasks])

    is_list_map = {n: is_list for n, _, is_list in tasks}

    for name, data in gathered:
        if data is None:
            result.resources_failed.append(name)
            continue

        # Serialise (Pydantic models → dicts) + optionally redact
        if is_list_map[name]:
            raw: Any = [
                item.model_dump(by_alias=True) if hasattr(item, "model_dump") else item
                for item in data
            ]
        else:
            raw = data.model_dump(by_alias=True) if hasattr(data, "model_dump") else data

        if redactor and raw is not None:
            raw = redactor.redact_dict(raw)

        store.write_resource(snapshot_path, name, raw)
        result.resources_captured.append(name)

    result.elapsed_seconds = time.monotonic() - start
    result.scope_warnings = client.scope_warnings

    manifest = SnapshotManifest(
        tenant_id=tenant_id,
        captured_at=ts,
        tool_version=__version__,
        redacted=redact,
        redaction_salt_hint=redactor.salt_hint if redactor else "",
        resources_captured=result.resources_captured,
        resources_failed=result.resources_failed,
        scope_warnings=result.scope_warnings,
    )
    store.write_manifest(snapshot_path, manifest)

    log.info(
        "Snapshot complete for %s: %d captured, %d failed, %.1fs",
        tenant_id,
        len(result.resources_captured),
        len(result.resources_failed),
        result.elapsed_seconds,
    )
    return result
