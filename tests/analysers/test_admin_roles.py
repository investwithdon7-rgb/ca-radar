"""Tests for admin role CA coverage analyser (CA-ADMIN-001, CA-ADMIN-002)."""

from __future__ import annotations

from ca_radar.analysers.packs.admin_roles.admin_roles import AdminRolesAnalyser
from ca_radar.analysers.packs.coverage.mfa_coverage import PRIVILEGED_ROLE_IDS
from ca_radar.resolver.effective_controls import PolicyResolver
from ca_radar.resolver.policy_graph import SnapshotData
from ca_radar.snapshot.models import (
    CaApplicationCondition,
    CaConditions,
    CaGrantControl,
    CaUserCondition,
    ConditionalAccessPolicy,
    PimEligibleRoleAssignment,
    PolicyState,
    RoleAssignment,
    User,
)

_GA_ROLE_ID = "62e90394-69f5-4237-9190-012177145e10"  # Global Administrator
assert _GA_ROLE_ID in PRIVILEGED_ROLE_IDS


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _user(uid: str, upn: str, *, enabled: bool = True) -> User:
    return User(id=uid, user_principal_name=upn, account_enabled=enabled)


def _policy(
    pid: str,
    *,
    include_users: list[str] | None = None,
    include_roles: list[str] | None = None,
    grant_controls: list[str] | None = None,
    state: PolicyState = PolicyState.enabled,
) -> ConditionalAccessPolicy:
    uc = CaUserCondition(
        include_users=include_users or [],
        include_roles=include_roles or [],
    )
    gc = CaGrantControl(operator="OR", built_in_controls=grant_controls or ["mfa"])
    return ConditionalAccessPolicy(
        id=pid,
        display_name=pid,
        state=state,
        conditions=CaConditions(
            users=uc,
            applications=CaApplicationCondition(include_applications=["All"]),
        ),
        grant_controls=gc,
    )


def _mfa_all(pid: str = "p-mfa") -> ConditionalAccessPolicy:
    return _policy(pid, include_users=["All"], grant_controls=["mfa"])


def _pim(uid: str, role_id: str) -> PimEligibleRoleAssignment:
    return PimEligibleRoleAssignment(id=f"pim-{uid}", principal_id=uid, role_definition_id=role_id)


def _make_data(
    users: list[User],
    policies: list[ConditionalAccessPolicy],
    *,
    role_assignments: list[RoleAssignment] | None = None,
    pim_eligible: list[PimEligibleRoleAssignment] | None = None,
) -> SnapshotData:
    data = SnapshotData(
        users=users,
        policies=policies,
        role_assignments=role_assignments or [],
        pim_eligible_role_assignments=pim_eligible or [],
    )
    data._build_indexes()
    return data


# ---------------------------------------------------------------------------
# CA-ADMIN-001 — no role-targeted CA policy
# ---------------------------------------------------------------------------


class TestAdminRoles001:
    def test_all_users_only_raises_001(self):
        """Only 'All users' MFA policy — no role-targeted policy → CA-ADMIN-001."""
        data = _make_data([_user("u1", "alice@test.com")], [_mfa_all()])
        resolver = PolicyResolver.from_data(data)

        findings = AdminRolesAnalyser().analyse(data, resolver)

        assert any(f.id == "CA-ADMIN-001" for f in findings)

    def test_role_targeted_policy_no_001(self):
        """A policy with include_roles containing a privileged role → no CA-ADMIN-001."""
        data = _make_data(
            [_user("u1", "alice@test.com")],
            [_mfa_all(), _policy("p-admin", include_roles=[_GA_ROLE_ID])],
        )
        resolver = PolicyResolver.from_data(data)

        findings = AdminRolesAnalyser().analyse(data, resolver)

        assert not any(f.id == "CA-ADMIN-001" for f in findings)

    def test_unprivileged_role_targeted_still_raises_001(self):
        """Policy targeting a non-privileged role doesn't satisfy CA-ADMIN-001."""
        data = _make_data(
            [_user("u1", "alice@test.com")],
            [_policy("p-custom", include_roles=["custom-role-id"])],
        )
        resolver = PolicyResolver.from_data(data)

        findings = AdminRolesAnalyser().analyse(data, resolver)

        assert any(f.id == "CA-ADMIN-001" for f in findings)

    def test_disabled_role_policy_raises_001(self):
        """A disabled role-targeted policy doesn't count."""
        data = _make_data(
            [_user("u1", "alice@test.com")],
            [_policy("p-admin", include_roles=[_GA_ROLE_ID], state=PolicyState.disabled)],
        )
        resolver = PolicyResolver.from_data(data)

        findings = AdminRolesAnalyser().analyse(data, resolver)

        assert any(f.id == "CA-ADMIN-001" for f in findings)

    def test_report_only_role_policy_raises_001(self):
        """A report-only role-targeted policy doesn't count."""
        data = _make_data(
            [_user("u1", "alice@test.com")],
            [
                _policy(
                    "p-admin",
                    include_roles=[_GA_ROLE_ID],
                    state=PolicyState.enabledForReportingButNotEnforced,
                )
            ],
        )
        resolver = PolicyResolver.from_data(data)

        findings = AdminRolesAnalyser().analyse(data, resolver)

        assert any(f.id == "CA-ADMIN-001" for f in findings)

    def test_any_privileged_role_satisfies_001(self):
        """Policy targeting any privileged role (not just GA) satisfies CA-ADMIN-001."""
        sec_admin_id = "194ae4cb-b126-40b2-bd5b-6091b380977d"  # Security Administrator
        assert sec_admin_id in PRIVILEGED_ROLE_IDS
        data = _make_data(
            [_user("u1", "alice@test.com")],
            [_policy("p-sec-admin", include_roles=[sec_admin_id])],
        )
        resolver = PolicyResolver.from_data(data)

        findings = AdminRolesAnalyser().analyse(data, resolver)

        assert not any(f.id == "CA-ADMIN-001" for f in findings)


# ---------------------------------------------------------------------------
# CA-ADMIN-002 — PIM-eligible users not covered by MFA
# ---------------------------------------------------------------------------


class TestAdminRoles002:
    def test_pim_user_not_covered_by_mfa_raises_002(self):
        """PIM-eligible user for GA with no MFA coverage → CA-ADMIN-002."""
        users = [_user("u-pim", "pim@test.com")]
        data = _make_data(
            users,
            policies=[],  # no MFA policy at all
            pim_eligible=[_pim("u-pim", _GA_ROLE_ID)],
        )
        resolver = PolicyResolver.from_data(data)

        findings = AdminRolesAnalyser().analyse(data, resolver)

        f002 = next((f for f in findings if f.id == "CA-ADMIN-002"), None)
        assert f002 is not None
        assert "u-pim" in f002.affected_principals

    def test_pim_user_covered_by_mfa_no_002(self):
        """PIM-eligible user covered by all-users MFA → no CA-ADMIN-002."""
        users = [_user("u-pim", "pim@test.com")]
        data = _make_data(
            users,
            policies=[_mfa_all()],
            pim_eligible=[_pim("u-pim", _GA_ROLE_ID)],
        )
        resolver = PolicyResolver.from_data(data)

        findings = AdminRolesAnalyser().analyse(data, resolver)

        assert not any(f.id == "CA-ADMIN-002" for f in findings)

    def test_no_pim_assignments_no_002(self):
        """No PIM eligible assignments → no CA-ADMIN-002."""
        data = _make_data([_user("u1", "alice@test.com")], [_mfa_all()])
        resolver = PolicyResolver.from_data(data)

        findings = AdminRolesAnalyser().analyse(data, resolver)

        assert not any(f.id == "CA-ADMIN-002" for f in findings)

    def test_pim_for_unprivileged_role_no_002(self):
        """PIM eligible for a non-privileged role doesn't trigger CA-ADMIN-002."""
        users = [_user("u1", "alice@test.com")]
        data = _make_data(
            users,
            policies=[],  # no MFA at all
            pim_eligible=[_pim("u1", "custom-role-id")],
        )
        resolver = PolicyResolver.from_data(data)

        findings = AdminRolesAnalyser().analyse(data, resolver)

        assert not any(f.id == "CA-ADMIN-002" for f in findings)

    def test_disabled_pim_user_not_checked(self):
        """Disabled accounts are not included in CA-ADMIN-002 checks."""
        users = [_user("u-pim", "pim@test.com", enabled=False)]
        data = _make_data(
            users,
            policies=[],
            pim_eligible=[_pim("u-pim", _GA_ROLE_ID)],
        )
        resolver = PolicyResolver.from_data(data)

        findings = AdminRolesAnalyser().analyse(data, resolver)

        assert not any(f.id == "CA-ADMIN-002" for f in findings)

    def test_pim_index_built_correctly(self):
        """SnapshotData._build_indexes populates user_pim_role_index from PIM assignments."""
        users = [_user("u1", "alice@test.com")]
        data = _make_data(users, [], pim_eligible=[_pim("u1", _GA_ROLE_ID)])

        assert _GA_ROLE_ID in data.user_pim_role_index.get("u1", set())
