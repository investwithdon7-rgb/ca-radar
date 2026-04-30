"""Tests for MFA coverage analyser (CA-MFA-001, CA-MFA-002)."""

from __future__ import annotations

from ca_radar.analysers.packs.coverage.mfa_coverage import (
    PRIVILEGED_ROLE_IDS,
    MfaCoverageAnalyser,
)
from ca_radar.resolver.effective_controls import PolicyResolver
from ca_radar.resolver.policy_graph import SnapshotData
from ca_radar.snapshot.models import (
    CaApplicationCondition,
    CaConditions,
    CaGrantControl,
    CaUserCondition,
    ConditionalAccessPolicy,
    Group,
    PolicyState,
    RoleAssignment,
    User,
)

# Real Global Administrator template ID (from PRIVILEGED_ROLE_IDS)
_GA_ROLE_ID = "62e90394-69f5-4237-9190-012177145e10"
assert _GA_ROLE_ID in PRIVILEGED_ROLE_IDS, "fixture sanity check"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _user(uid: str, upn: str, *, enabled: bool = True, user_type: str | None = None) -> User:
    return User(id=uid, user_principal_name=upn, account_enabled=enabled, user_type=user_type)


def _mfa_policy(
    pid: str = "p-mfa",
    *,
    include_users: list[str] | None = None,
    exclude_users: list[str] | None = None,
    exclude_groups: list[str] | None = None,
    state: PolicyState = PolicyState.enabled,
) -> ConditionalAccessPolicy:
    uc = CaUserCondition(
        include_users=include_users or ["All"],
        exclude_users=exclude_users or [],
        exclude_groups=exclude_groups or [],
    )
    gc = CaGrantControl(operator="OR", built_in_controls=["mfa"])
    return ConditionalAccessPolicy(
        id=pid,
        display_name="Require MFA",
        state=state,
        conditions=CaConditions(
            users=uc,
            applications=CaApplicationCondition(include_applications=["All"]),
        ),
        grant_controls=gc,
    )


def _phish_resistant_policy(
    pid: str = "p-phish",
    *,
    include_roles: list[str] | None = None,
    include_users: list[str] | None = None,
) -> ConditionalAccessPolicy:
    uc = CaUserCondition(
        include_roles=include_roles or [],
        include_users=include_users or [],
    )
    gc = CaGrantControl(operator="OR", built_in_controls=["phishingResistant"])
    return ConditionalAccessPolicy(
        id=pid,
        display_name="Phishing-resistant MFA",
        state=PolicyState.enabled,
        conditions=CaConditions(
            users=uc,
            applications=CaApplicationCondition(include_applications=["All"]),
        ),
        grant_controls=gc,
    )


def _make_data(
    users: list[User],
    policies: list[ConditionalAccessPolicy],
    *,
    groups: list[Group] | None = None,
    role_assignments: list[RoleAssignment] | None = None,
) -> SnapshotData:
    data = SnapshotData(
        users=users,
        policies=policies,
        groups=groups or [],
        role_assignments=role_assignments or [],
    )
    data._build_indexes()
    return data


# ---------------------------------------------------------------------------
# CA-MFA-001 — users not covered by any MFA policy
# ---------------------------------------------------------------------------


class TestMfaCoverage001:
    def test_all_users_covered_no_finding(self):
        """When all-users MFA policy exists and no exclusions, no finding."""
        users = [_user("u1", "alice@test.com"), _user("u2", "bob@test.com")]
        data = _make_data(users, [_mfa_policy()])
        resolver = PolicyResolver.from_data(data)

        findings = MfaCoverageAnalyser().analyse(data, resolver)

        assert not any(f.id == "CA-MFA-001" for f in findings)

    def test_excluded_user_triggers_001(self):
        """User excluded from the only MFA policy is counted as uncovered."""
        users = [_user("u1", "alice@test.com"), _user("u2", "bob@test.com")]
        data = _make_data(users, [_mfa_policy(exclude_users=["u2"])])
        resolver = PolicyResolver.from_data(data)

        findings = MfaCoverageAnalyser().analyse(data, resolver)

        f001 = next((f for f in findings if f.id == "CA-MFA-001"), None)
        assert f001 is not None
        assert "u2" in f001.affected_principals
        assert "u1" not in f001.affected_principals

    def test_excluded_group_member_triggers_001(self):
        """User in an excluded group is counted as uncovered."""
        users = [_user("u1", "alice@test.com"), _user("u2", "bob@test.com")]
        group = Group(id="g-bg", display_name="BG", member_ids=["u2"], transitive_member_ids=["u2"])
        data = _make_data(users, [_mfa_policy(exclude_groups=["g-bg"])], groups=[group])
        resolver = PolicyResolver.from_data(data)

        findings = MfaCoverageAnalyser().analyse(data, resolver)

        f001 = next((f for f in findings if f.id == "CA-MFA-001"), None)
        assert f001 is not None
        assert "u2" in f001.affected_principals

    def test_no_policies_all_uncovered(self):
        """With no CA policies every member user triggers CA-MFA-001."""
        users = [_user("u1", "alice@test.com")]
        data = _make_data(users, [])
        resolver = PolicyResolver.from_data(data)

        findings = MfaCoverageAnalyser().analyse(data, resolver)

        assert any(f.id == "CA-MFA-001" for f in findings)

    def test_disabled_policy_not_counted(self):
        """A disabled MFA policy provides no coverage."""
        users = [_user("u1", "alice@test.com")]
        data = _make_data(users, [_mfa_policy(state=PolicyState.disabled)])
        resolver = PolicyResolver.from_data(data)

        findings = MfaCoverageAnalyser().analyse(data, resolver)

        assert any(f.id == "CA-MFA-001" for f in findings)

    def test_report_only_policy_not_counted(self):
        """A report-only MFA policy provides no enforcement coverage."""
        users = [_user("u1", "alice@test.com")]
        data = _make_data(
            users,
            [_mfa_policy(state=PolicyState.enabledForReportingButNotEnforced)],
        )
        resolver = PolicyResolver.from_data(data)

        findings = MfaCoverageAnalyser().analyse(data, resolver)

        assert any(f.id == "CA-MFA-001" for f in findings)

    def test_guest_users_excluded_from_check(self):
        """Guest users (user_type='Guest') are skipped entirely."""
        users = [
            _user("u1", "member@test.com"),
            User(
                id="u-guest",
                user_principal_name="guest#EXT#@test.com",
                account_enabled=True,
                user_type="Guest",
            ),
        ]
        # u1 covered; u-guest excluded from MFA but is a Guest so irrelevant
        data = _make_data(users, [_mfa_policy(exclude_users=["u-guest"])])
        resolver = PolicyResolver.from_data(data)

        findings = MfaCoverageAnalyser().analyse(data, resolver)

        assert not any(f.id == "CA-MFA-001" for f in findings)

    def test_disabled_accounts_excluded_from_check(self):
        """Accounts with account_enabled=False are not analysed."""
        users = [
            _user("u1", "alice@test.com"),
            _user("u2", "disabled@test.com", enabled=False),
        ]
        data = _make_data(users, [_mfa_policy(exclude_users=["u2"])])
        resolver = PolicyResolver.from_data(data)

        findings = MfaCoverageAnalyser().analyse(data, resolver)

        assert not any(f.id == "CA-MFA-001" for f in findings)

    def test_empty_user_list_returns_no_findings(self):
        """Empty user list returns an empty result (no crash)."""
        data = _make_data([], [_mfa_policy()])
        resolver = PolicyResolver.from_data(data)

        findings = MfaCoverageAnalyser().analyse(data, resolver)

        assert findings == []

    def test_finding_lists_affected_principals(self):
        """CA-MFA-001 evidence contains the uncovered user count."""
        users = [_user("u1", "alice@test.com"), _user("u2", "bob@test.com")]
        data = _make_data(users, [])
        resolver = PolicyResolver.from_data(data)

        findings = MfaCoverageAnalyser().analyse(data, resolver)

        f001 = next(f for f in findings if f.id == "CA-MFA-001")
        assert f001.evidence["uncovered_user_count"] == 2


# ---------------------------------------------------------------------------
# CA-MFA-002 — admin accounts without phishing-resistant auth
# ---------------------------------------------------------------------------


class TestMfaCoverage002:
    def test_admin_with_basic_mfa_triggers_002(self):
        """Admin with only basic MFA policy raises CA-MFA-002."""
        users = [_user("u-admin", "admin@test.com")]
        ra = RoleAssignment(
            id="ra1",
            principal_id="u-admin",
            role_definition_id=_GA_ROLE_ID,
            directory_scope_id="/",
        )
        data = _make_data(users, [_mfa_policy()], role_assignments=[ra])
        resolver = PolicyResolver.from_data(data)

        findings = MfaCoverageAnalyser().analyse(data, resolver)

        f002 = next((f for f in findings if f.id == "CA-MFA-002"), None)
        assert f002 is not None
        assert "u-admin" in f002.affected_principals

    def test_admin_with_phish_resistant_no_002(self):
        """Admin covered by a phishing-resistant policy does not trigger CA-MFA-002."""
        users = [_user("u-admin", "admin@test.com")]
        ra = RoleAssignment(
            id="ra1",
            principal_id="u-admin",
            role_definition_id=_GA_ROLE_ID,
            directory_scope_id="/",
        )
        data = _make_data(
            users,
            [_mfa_policy(), _phish_resistant_policy(include_roles=[_GA_ROLE_ID])],
            role_assignments=[ra],
        )
        resolver = PolicyResolver.from_data(data)

        findings = MfaCoverageAnalyser().analyse(data, resolver)

        assert not any(f.id == "CA-MFA-002" for f in findings)

    def test_admin_covered_by_user_scoped_phish_resistant_no_002(self):
        """Admin covered by a user-scoped phishing-resistant policy is not flagged."""
        users = [_user("u-admin", "admin@test.com")]
        ra = RoleAssignment(
            id="ra1",
            principal_id="u-admin",
            role_definition_id=_GA_ROLE_ID,
            directory_scope_id="/",
        )
        data = _make_data(
            users,
            [_phish_resistant_policy(include_users=["u-admin"])],
            role_assignments=[ra],
        )
        resolver = PolicyResolver.from_data(data)

        findings = MfaCoverageAnalyser().analyse(data, resolver)

        assert not any(f.id == "CA-MFA-002" for f in findings)

    def test_non_admin_user_not_in_002(self):
        """Regular user without a privileged role is never in CA-MFA-002."""
        users = [_user("u-regular", "regular@test.com")]
        data = _make_data(users, [_mfa_policy()])
        resolver = PolicyResolver.from_data(data)

        findings = MfaCoverageAnalyser().analyse(data, resolver)

        assert not any(f.id == "CA-MFA-002" for f in findings)

    def test_unprivileged_role_not_in_002(self):
        """Custom / non-privileged role assignment does not trigger CA-MFA-002."""
        users = [_user("u1", "user@test.com")]
        ra = RoleAssignment(
            id="ra1",
            principal_id="u1",
            role_definition_id="00000000-0000-0000-0000-000000000099",  # not in PRIVILEGED_ROLE_IDS
            directory_scope_id="/",
        )
        data = _make_data(users, [_mfa_policy()], role_assignments=[ra])
        resolver = PolicyResolver.from_data(data)

        findings = MfaCoverageAnalyser().analyse(data, resolver)

        assert not any(f.id == "CA-MFA-002" for f in findings)

    def test_fido2_built_in_control_satisfies_002(self):
        """FIDO2 built-in control (not 'phishingResistant') still satisfies CA-MFA-002."""
        users = [_user("u-admin", "admin@test.com")]
        ra = RoleAssignment(
            id="ra1",
            principal_id="u-admin",
            role_definition_id=_GA_ROLE_ID,
            directory_scope_id="/",
        )
        fido2_policy = ConditionalAccessPolicy(
            id="p-fido2",
            display_name="FIDO2",
            state=PolicyState.enabled,
            conditions=CaConditions(
                users=CaUserCondition(include_users=["All"]),
                applications=CaApplicationCondition(include_applications=["All"]),
            ),
            grant_controls=CaGrantControl(operator="OR", built_in_controls=["fido2"]),
        )
        data = _make_data(users, [fido2_policy], role_assignments=[ra])
        resolver = PolicyResolver.from_data(data)

        findings = MfaCoverageAnalyser().analyse(data, resolver)

        assert not any(f.id == "CA-MFA-002" for f in findings)
