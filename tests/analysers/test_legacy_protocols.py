"""Tests for legacy authentication analyser (CA-LEGACY-001, CA-LEGACY-002)."""

from __future__ import annotations

from ca_radar.analysers.packs.legacy_auth.legacy_protocols import LegacyAuthAnalyser
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
    User,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _user(uid: str, upn: str, *, enabled: bool = True, user_type: str | None = None) -> User:
    return User(id=uid, user_principal_name=upn, account_enabled=enabled, user_type=user_type)


def _block_legacy_policy(
    pid: str = "p-legacy",
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
    gc = CaGrantControl(operator="OR", built_in_controls=["block"])
    return ConditionalAccessPolicy(
        id=pid,
        display_name="Block legacy auth",
        state=state,
        conditions=CaConditions(
            users=uc,
            applications=CaApplicationCondition(include_applications=["All"]),
            client_app_types=["exchangeActiveSync", "other"],
        ),
        grant_controls=gc,
    )


def _mfa_policy(pid: str = "p-mfa") -> ConditionalAccessPolicy:
    """Plain MFA policy with no client_app_types filter (browser + all)."""
    uc = CaUserCondition(include_users=["All"])
    gc = CaGrantControl(operator="OR", built_in_controls=["mfa"])
    return ConditionalAccessPolicy(
        id=pid,
        display_name="Require MFA",
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
) -> SnapshotData:
    data = SnapshotData(users=users, policies=policies, groups=groups or [])
    data._build_indexes()
    return data


# ---------------------------------------------------------------------------
# CA-LEGACY-002 — no policy explicitly blocks legacy auth
# ---------------------------------------------------------------------------


class TestNoLegacyBlockPolicy:
    def test_no_policies_raises_002(self):
        """With no CA policies at all, CA-LEGACY-002 must be raised."""
        data = _make_data([_user("u1", "alice@test.com")], [])
        resolver = PolicyResolver.from_data(data)

        findings = LegacyAuthAnalyser().analyse(data, resolver)

        assert any(f.id == "CA-LEGACY-002" for f in findings)

    def test_mfa_only_policy_raises_002(self):
        """An MFA policy without legacy client_app_types does not satisfy CA-LEGACY-002."""
        data = _make_data([_user("u1", "alice@test.com")], [_mfa_policy()])
        resolver = PolicyResolver.from_data(data)

        findings = LegacyAuthAnalyser().analyse(data, resolver)

        assert any(f.id == "CA-LEGACY-002" for f in findings)

    def test_blocking_policy_without_legacy_app_types_raises_002(self):
        """A 'block' policy that doesn't target legacy client types doesn't satisfy CA-LEGACY-002."""
        block_all = ConditionalAccessPolicy(
            id="p-block",
            display_name="Block",
            state=PolicyState.enabled,
            conditions=CaConditions(
                users=CaUserCondition(include_users=["All"]),
                applications=CaApplicationCondition(include_applications=["All"]),
                # No client_app_types → applies to all, but _find_legacy_blocking_policies
                # requires explicit legacy type targeting
            ),
            grant_controls=CaGrantControl(operator="OR", built_in_controls=["block"]),
        )
        data = _make_data([_user("u1", "alice@test.com")], [block_all])
        resolver = PolicyResolver.from_data(data)

        findings = LegacyAuthAnalyser().analyse(data, resolver)

        assert any(f.id == "CA-LEGACY-002" for f in findings)

    def test_report_only_block_raises_002(self):
        """A report-only legacy-block policy does not count as blocking."""
        policy = _block_legacy_policy(state=PolicyState.enabledForReportingButNotEnforced)
        data = _make_data([_user("u1", "alice@test.com")], [policy])
        resolver = PolicyResolver.from_data(data)

        findings = LegacyAuthAnalyser().analyse(data, resolver)

        assert any(f.id == "CA-LEGACY-002" for f in findings)

    def test_disabled_block_policy_raises_002(self):
        """A disabled legacy-block policy does not satisfy CA-LEGACY-002."""
        policy = _block_legacy_policy(state=PolicyState.disabled)
        data = _make_data([_user("u1", "alice@test.com")], [policy])
        resolver = PolicyResolver.from_data(data)

        findings = LegacyAuthAnalyser().analyse(data, resolver)

        assert any(f.id == "CA-LEGACY-002" for f in findings)

    def test_enabled_legacy_block_no_002(self):
        """An enabled policy targeting legacy client types with block satisfies CA-LEGACY-002."""
        data = _make_data([_user("u1", "alice@test.com")], [_block_legacy_policy()])
        resolver = PolicyResolver.from_data(data)

        findings = LegacyAuthAnalyser().analyse(data, resolver)

        assert not any(f.id == "CA-LEGACY-002" for f in findings)

    def test_eas_only_block_satisfies_002(self):
        """A policy targeting only exchangeActiveSync with block still satisfies CA-LEGACY-002."""
        eas_only = ConditionalAccessPolicy(
            id="p-eas",
            display_name="Block EAS",
            state=PolicyState.enabled,
            conditions=CaConditions(
                users=CaUserCondition(include_users=["All"]),
                applications=CaApplicationCondition(include_applications=["All"]),
                client_app_types=["exchangeActiveSync"],
            ),
            grant_controls=CaGrantControl(operator="OR", built_in_controls=["block"]),
        )
        data = _make_data([_user("u1", "alice@test.com")], [eas_only])
        resolver = PolicyResolver.from_data(data)

        findings = LegacyAuthAnalyser().analyse(data, resolver)

        assert not any(f.id == "CA-LEGACY-002" for f in findings)


# ---------------------------------------------------------------------------
# CA-LEGACY-001 — users exposed to legacy auth
# ---------------------------------------------------------------------------


class TestLegacyAuthExposedUsers:
    def test_user_with_no_block_raises_001(self):
        """User without any block policy is exposed to legacy auth."""
        data = _make_data([_user("u1", "alice@test.com")], [])
        resolver = PolicyResolver.from_data(data)

        findings = LegacyAuthAnalyser().analyse(data, resolver)

        assert any(f.id == "CA-LEGACY-001" for f in findings)

    def test_all_users_blocked_no_001(self):
        """All users fully blocked from legacy auth — no CA-LEGACY-001."""
        users = [_user("u1", "alice@test.com"), _user("u2", "bob@test.com")]
        data = _make_data(users, [_block_legacy_policy()])
        resolver = PolicyResolver.from_data(data)

        findings = LegacyAuthAnalyser().analyse(data, resolver)

        assert not any(f.id == "CA-LEGACY-001" for f in findings)

    def test_excluded_user_triggers_001(self):
        """User excluded from the block policy is counted as exposed."""
        users = [_user("u1", "alice@test.com"), _user("u2", "bob@test.com")]
        policy = _block_legacy_policy(exclude_users=["u2"])
        data = _make_data(users, [policy])
        resolver = PolicyResolver.from_data(data)

        findings = LegacyAuthAnalyser().analyse(data, resolver)

        f001 = next((f for f in findings if f.id == "CA-LEGACY-001"), None)
        assert f001 is not None
        assert "u2" in f001.affected_principals
        assert "u1" not in f001.affected_principals

    def test_excluded_group_member_triggers_001(self):
        """User in an excluded group is counted as exposed."""
        users = [_user("u1", "alice@test.com"), _user("u2", "bob@test.com")]
        group = Group(
            id="g-exc", display_name="Excluded", member_ids=["u2"], transitive_member_ids=["u2"]
        )
        policy = _block_legacy_policy(exclude_groups=["g-exc"])
        data = _make_data(users, [policy], groups=[group])
        resolver = PolicyResolver.from_data(data)

        findings = LegacyAuthAnalyser().analyse(data, resolver)

        f001 = next((f for f in findings if f.id == "CA-LEGACY-001"), None)
        assert f001 is not None
        assert "u2" in f001.affected_principals

    def test_guest_users_not_in_001(self):
        """Guest users (user_type='Guest') are excluded from the exposed-users check."""
        users = [
            _user("u1", "member@test.com"),
            User(
                id="u-guest",
                user_principal_name="guest#EXT#@test.com",
                account_enabled=True,
                user_type="Guest",
            ),
        ]
        # Only u1 is blocked; u-guest is excluded from block but is a Guest
        policy = _block_legacy_policy(exclude_users=["u-guest"])
        data = _make_data(users, [policy])
        resolver = PolicyResolver.from_data(data)

        findings = LegacyAuthAnalyser().analyse(data, resolver)

        assert not any(f.id == "CA-LEGACY-001" for f in findings)

    def test_disabled_accounts_not_in_001(self):
        """Disabled accounts are not counted as exposed."""
        users = [
            _user("u1", "alice@test.com"),
            _user("u2", "disabled@test.com", enabled=False),
        ]
        policy = _block_legacy_policy(exclude_users=["u2"])
        data = _make_data(users, [policy])
        resolver = PolicyResolver.from_data(data)

        findings = LegacyAuthAnalyser().analyse(data, resolver)

        assert not any(f.id == "CA-LEGACY-001" for f in findings)

    def test_user_counted_once_even_if_both_client_types_exposed(self):
        """A user exposed on both EAS and 'other' is counted only once in CA-LEGACY-001."""
        users = [_user("u1", "alice@test.com")]
        # No blocking policy at all → both client_app_types unblocked
        data = _make_data(users, [])
        resolver = PolicyResolver.from_data(data)

        findings = LegacyAuthAnalyser().analyse(data, resolver)

        f001 = next((f for f in findings if f.id == "CA-LEGACY-001"), None)
        assert f001 is not None
        assert f001.evidence["exposed_user_count"] == 1  # counted once

    def test_evidence_contains_blocking_policy_ids(self):
        """CA-LEGACY-001 evidence includes the IDs of blocking policies (even if partial)."""
        users = [_user("u1", "alice@test.com"), _user("u2", "bob@test.com")]
        policy = _block_legacy_policy(pid="p-block-legacy", exclude_users=["u2"])
        data = _make_data(users, [policy])
        resolver = PolicyResolver.from_data(data)

        findings = LegacyAuthAnalyser().analyse(data, resolver)

        f001 = next((f for f in findings if f.id == "CA-LEGACY-001"), None)
        assert f001 is not None
        assert "p-block-legacy" in f001.evidence["blocking_policy_ids"]
