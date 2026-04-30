"""Unit tests: Pydantic model round-trip serialisation."""

from __future__ import annotations

import json
from datetime import UTC, datetime

from ca_radar.snapshot.models import (
    ConditionalAccessPolicy,
    Group,
    IpNamedLocation,
    PolicyState,
    SnapshotManifest,
    User,
)


def _policy_fixture() -> dict:
    return {
        "id": "policy-001",
        "displayName": "Require MFA for all users",
        "state": "enabled",
        "conditions": {
            "users": {
                "includeUsers": ["All"],
                "excludeUsers": [],
                "includeGroups": [],
                "excludeGroups": ["break-glass-group-id"],
                "includeRoles": [],
                "excludeRoles": [],
            },
            "applications": {
                "includeApplications": ["All"],
                "excludeApplications": [],
                "includeUserActions": [],
                "includeAuthenticationContextClassReferences": [],
            },
            "clientAppTypes": ["browser", "mobileAppsAndDesktopClients"],
        },
        "grantControls": {
            "operator": "OR",
            "builtInControls": ["mfa"],
            "customAuthenticationFactors": [],
            "termsOfUse": [],
        },
    }


def test_ca_policy_round_trip() -> None:
    data = _policy_fixture()
    policy = ConditionalAccessPolicy.model_validate(data)

    assert policy.id == "policy-001"
    assert policy.state == PolicyState.enabled
    assert policy.conditions.users is not None
    assert "All" in policy.conditions.users.include_users
    assert "break-glass-group-id" in policy.conditions.users.exclude_groups
    assert policy.grant_controls is not None
    assert "mfa" in policy.grant_controls.built_in_controls

    # Round-trip: serialise back to dict and re-parse
    serialised = json.loads(policy.model_dump_json(by_alias=True))
    policy2 = ConditionalAccessPolicy.model_validate(serialised)
    assert policy2.id == policy.id
    assert policy2.state == policy.state


def test_ca_policy_report_only_state() -> None:
    data = _policy_fixture()
    data["state"] = "enabledForReportingButNotEnforced"
    policy = ConditionalAccessPolicy.model_validate(data)
    assert policy.state == PolicyState.enabledForReportingButNotEnforced


def test_ca_policy_unknown_extra_fields_ignored() -> None:
    data = _policy_fixture()
    data["futureGraphField"] = "someValue"
    policy = ConditionalAccessPolicy.model_validate(data)
    assert policy.id == "policy-001"


def test_user_model() -> None:
    raw = {
        "id": "user-001",
        "userPrincipalName": "alice@contoso.com",
        "displayName": "Alice Smith",
        "accountEnabled": True,
        "userType": "Member",
        "createdDateTime": "2023-01-15T10:00:00Z",
        "signInActivity": {
            "lastSignInDateTime": "2024-03-01T08:30:00Z",
            "lastSignInRequestId": "req-abc",
        },
    }
    user = User.model_validate(raw)
    assert user.id == "user-001"
    assert user.user_principal_name == "alice@contoso.com"
    assert user.account_enabled is True
    assert user.sign_in_activity is not None
    assert user.sign_in_activity.last_sign_in_date_time is not None
    assert user.is_break_glass is False


def test_group_model() -> None:
    raw = {
        "id": "grp-001",
        "displayName": "MFA Exclusions",
        "groupTypes": [],
        "securityEnabled": True,
        "mailEnabled": False,
    }
    group = Group.model_validate(raw)
    assert group.id == "grp-001"
    assert group.transitive_member_ids == []


def test_ip_named_location() -> None:
    raw = {
        "id": "loc-001",
        "displayName": "Office Network",
        "isTrusted": True,
        "ipRanges": [
            {"cidrAddress": "203.0.113.0/24"},
            {"cidrAddress": "198.51.100.0/24"},
        ],
    }
    loc = IpNamedLocation.model_validate(raw)
    assert loc.is_trusted is True
    assert len(loc.ip_ranges) == 2
    assert loc.ip_ranges[0].cidr_address == "203.0.113.0/24"


def test_snapshot_manifest_defaults() -> None:
    manifest = SnapshotManifest(
        tenant_id="contoso.onmicrosoft.com",
        captured_at=datetime(2024, 6, 1, 12, 0, 0, tzinfo=UTC),
        tool_version="0.1.0",
    )
    assert manifest.schema_version == "1"
    assert manifest.redacted is True
    assert manifest.resources_captured == []
