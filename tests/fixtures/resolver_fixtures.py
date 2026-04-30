"""Reusable in-memory SnapshotData fixtures for resolver tests.

Three tenants:
  simple_tenant()        — 3 users, 1 group, 2 policies (MFA + block legacy)
  nested_groups_tenant() — groups nested 3 deep, membership via recursion
  exclusion_heavy_tenant() — break-glass exclusion, role exclusion, nested exclusion
"""

from __future__ import annotations

from ca_radar.resolver.policy_graph import SnapshotData
from ca_radar.snapshot.models import (
    CaApplicationCondition,
    CaConditions,
    CaGrantControl,
    CaSessionControl,
    CaUserCondition,
    ConditionalAccessPolicy,
    DirectoryRole,
    Group,
    PolicyState,
    RoleAssignment,
    User,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _user(id: str, upn: str, roles: list[str] | None = None) -> User:
    return User(id=id, user_principal_name=upn, account_enabled=True, assigned_roles=roles or [])


def _group(
    id: str, name: str, members: list[str] | None = None, nested: list[str] | None = None
) -> Group:
    """members = direct user IDs; nested = sub-group IDs (stored in member_ids)."""
    all_members = (members or []) + (nested or [])
    return Group(
        id=id, display_name=name, member_ids=all_members, transitive_member_ids=members or []
    )


def _group_nested(id: str, name: str, all_user_ids: list[str]) -> Group:
    """Group whose transitive_member_ids are pre-computed (simulates Graph expansion)."""
    return Group(
        id=id, display_name=name, transitive_member_ids=all_user_ids, member_ids=all_user_ids
    )


def _policy(
    id: str,
    name: str,
    state: PolicyState = PolicyState.enabled,
    include_users: list[str] | None = None,
    exclude_users: list[str] | None = None,
    include_groups: list[str] | None = None,
    exclude_groups: list[str] | None = None,
    include_roles: list[str] | None = None,
    exclude_roles: list[str] | None = None,
    include_apps: list[str] | None = None,
    client_app_types: list[str] | None = None,
    grant_controls: list[str] | None = None,
    session_controls: dict | None = None,
) -> ConditionalAccessPolicy:
    user_cond = CaUserCondition(
        include_users=include_users or [],
        exclude_users=exclude_users or [],
        include_groups=include_groups or [],
        exclude_groups=exclude_groups or [],
        include_roles=include_roles or [],
        exclude_roles=exclude_roles or [],
    )
    app_cond = CaApplicationCondition(
        include_applications=include_apps or ["All"],
        exclude_applications=[],
        include_user_actions=[],
        include_authentication_context_class_references=[],
    )
    sc = None
    if session_controls:
        sc = CaSessionControl(
            sign_in_frequency=session_controls.get("signInFrequency"),
            persistent_browser=session_controls.get("persistentBrowser"),
        )
    return ConditionalAccessPolicy(
        id=id,
        display_name=name,
        state=state,
        conditions=CaConditions(
            users=user_cond,
            applications=app_cond,
            client_app_types=client_app_types or [],
        ),
        grant_controls=CaGrantControl(
            operator="OR",
            built_in_controls=grant_controls or ["mfa"],
        )
        if grant_controls is not None
        else CaGrantControl(
            operator="OR",
            built_in_controls=["mfa"],
        ),
        session_controls=sc,
    )


# ---------------------------------------------------------------------------
# Tenant 1 — simple
# ---------------------------------------------------------------------------


def simple_tenant() -> SnapshotData:
    """3 users, 1 break-glass group, 2 policies.

    alice  → Global Admin role
    bob    → regular user
    bglass → member of break-glass group

    Policy 1: Require MFA for All users, excluding break-glass group
    Policy 2: Block legacy auth for All users (no exclusions)
    """
    users = [
        _user("u-alice", "alice@contoso.com"),
        _user("u-bob", "bob@contoso.com"),
        _user("u-bg", "breakglass@contoso.com"),
    ]
    groups = [
        _group("g-bg", "Break Glass Accounts", members=["u-bg"]),
    ]
    roles = [
        DirectoryRole(id="r-ga", display_name="Global Administrator", role_template_id="tid-ga"),
    ]
    role_assignments = [
        RoleAssignment(
            id="ra-1", principal_id="u-alice", role_definition_id="tid-ga", directory_scope_id="/"
        ),
    ]
    policies = [
        _policy(
            "p-mfa",
            "Require MFA for all users",
            include_users=["All"],
            exclude_groups=["g-bg"],
            grant_controls=["mfa"],
        ),
        _policy(
            "p-legacy",
            "Block legacy auth",
            include_users=["All"],
            client_app_types=["exchangeActiveSync", "other"],
            grant_controls=["block"],
        ),
    ]
    data = SnapshotData(
        policies=policies,
        users=users,
        groups=groups,
        roles=roles,
        role_assignments=role_assignments,
    )
    data._build_indexes()
    return data


# ---------------------------------------------------------------------------
# Tenant 2 — nested groups
# ---------------------------------------------------------------------------


def nested_groups_tenant() -> SnapshotData:
    """3-deep group nesting with cycle detection test node.

    all-staff
      └── engineers
            └── backend-team
                  └── u-carol, u-dave

    Policy: Require MFA for group all-staff
    The resolver must find carol/dave via transitive membership.
    """
    users = [
        _user("u-carol", "carol@fabrikam.com"),
        _user("u-dave", "dave@fabrikam.com"),
        _user("u-eve", "eve@fabrikam.com"),  # NOT in any group
    ]
    # Build from leaf up; transitive members are pre-computed for leaf groups
    backend = _group_nested("g-backend", "backend-team", ["u-carol", "u-dave"])
    # Engineers has backend as sub-group — use member_ids to trigger recursion
    engineers = Group(
        id="g-engineers",
        display_name="engineers",
        member_ids=["u-carol", "u-dave", "g-backend"],  # pre-expanded + nested ref
        transitive_member_ids=[],  # empty → force recursive expansion
    )
    all_staff = Group(
        id="g-all-staff",
        display_name="all-staff",
        member_ids=["g-engineers"],  # chain through engineers
        transitive_member_ids=[],
    )
    policies = [
        _policy(
            "p-mfa-staff",
            "MFA for all staff",
            include_groups=["g-all-staff"],
            grant_controls=["mfa"],
        ),
    ]
    data = SnapshotData(
        policies=policies,
        users=users,
        groups=[backend, engineers, all_staff],
    )
    data._build_indexes()
    return data


# ---------------------------------------------------------------------------
# Tenant 3 — exclusion-heavy
# ---------------------------------------------------------------------------


def exclusion_heavy_tenant() -> SnapshotData:
    """Tests every exclusion path: direct user, group, and role exclusions.

    frank  → Global Admin (excluded by role from policy-B)
    grace  → member of VIP exclusion group (excluded from policy-A)
    harry  → no exclusions (covered by both policies)

    Policy A: MFA for All, exclude VIP group
    Policy B: Phishing-resistant MFA for admins, exclude Global Admin role
    Policy C: Block legacy, report-only
    """
    users = [
        _user("u-frank", "frank@woodgrove.com"),
        _user("u-grace", "grace@woodgrove.com"),
        _user("u-harry", "harry@woodgrove.com"),
    ]
    groups = [
        _group("g-vip", "VIP Exclusions", members=["u-grace"]),
    ]
    roles = [
        DirectoryRole(id="r-ga", display_name="Global Administrator", role_template_id="tid-ga"),
    ]
    role_assignments = [
        RoleAssignment(
            id="ra-frank",
            principal_id="u-frank",
            role_definition_id="tid-ga",
            directory_scope_id="/",
        ),
    ]
    policies = [
        _policy(
            "p-mfa-all",
            "MFA for all",
            include_users=["All"],
            exclude_groups=["g-vip"],
            grant_controls=["mfa"],
        ),
        _policy(
            "p-phish",
            "Phishing-resistant for admins",
            include_roles=["tid-ga"],
            exclude_roles=[
                "tid-ga"
            ],  # deliberately odd: exclude = include (should result in no match)
            grant_controls=["mfa"],
        ),
        _policy(
            "p-legacy-ro",
            "Block legacy (report-only)",
            state=PolicyState.enabledForReportingButNotEnforced,
            include_users=["All"],
            grant_controls=["block"],
        ),
    ]
    data = SnapshotData(
        policies=policies,
        users=users,
        groups=groups,
        roles=roles,
        role_assignments=role_assignments,
    )
    data._build_indexes()
    return data
