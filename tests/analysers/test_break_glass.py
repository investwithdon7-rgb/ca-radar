"""Tests for break-glass account analyser (CA-BG-001, CA-BG-002, CA-BG-003)."""

from __future__ import annotations

import pytest

from ca_radar.analysers.packs.break_glass.break_glass import (
    _BG_NAME_PATTERN,
    BreakGlassAnalyser,
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
    User,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _user(uid: str, upn: str, *, enabled: bool = True) -> User:
    return User(id=uid, user_principal_name=upn, account_enabled=enabled)


def _policy(
    pid: str,
    name: str = "policy",
    *,
    include_users: list[str] | None = None,
    exclude_users: list[str] | None = None,
    include_groups: list[str] | None = None,
    exclude_groups: list[str] | None = None,
    grant_controls: list[str] | None = None,
    client_app_types: list[str] | None = None,
    state: PolicyState = PolicyState.enabled,
) -> ConditionalAccessPolicy:
    uc = CaUserCondition(
        include_users=include_users or [],
        exclude_users=exclude_users or [],
        include_groups=include_groups or [],
        exclude_groups=exclude_groups or [],
    )
    gc = CaGrantControl(operator="OR", built_in_controls=grant_controls or ["mfa"])
    return ConditionalAccessPolicy(
        id=pid,
        display_name=name,
        state=state,
        conditions=CaConditions(
            users=uc,
            applications=CaApplicationCondition(include_applications=["All"]),
            client_app_types=client_app_types or [],
        ),
        grant_controls=gc,
    )


def _mfa_all(
    pid: str = "p-mfa",
    *,
    exclude_users: list[str] | None = None,
    exclude_groups: list[str] | None = None,
) -> ConditionalAccessPolicy:
    return _policy(
        pid,
        "MFA for all",
        include_users=["All"],
        exclude_users=exclude_users,
        exclude_groups=exclude_groups,
        grant_controls=["mfa"],
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
# Pattern sanity checks
# ---------------------------------------------------------------------------


class TestBgNamePattern:
    """Verify _BG_NAME_PATTERN recognises all intended naming conventions."""

    @pytest.mark.parametrize(
        "upn",
        [
            "breakglass@tenant.com",
            "break-glass@tenant.com",
            "break.glass@tenant.com",
            "BREAKGLASS@tenant.com",
            "emergency@tenant.com",
            "emergency-access@tenant.com",
            "emergency.access@tenant.com",
            "emrg@tenant.com",
            "eadmin@tenant.com",
            "bg1@tenant.com",
            "bg99@tenant.com",
            "BG1@tenant.com",
        ],
    )
    def test_matches_bg_upn(self, upn: str):
        assert _BG_NAME_PATTERN.search(upn), f"Expected match for: {upn}"

    @pytest.mark.parametrize(
        "upn",
        [
            "alice@tenant.com",
            "admin@tenant.com",
            "globaladmin@tenant.com",
            "helpdesk@tenant.com",
            "bgservice@tenant.com",  # "bg" without trailing digit
        ],
    )
    def test_no_false_positives(self, upn: str):
        assert not _BG_NAME_PATTERN.search(upn), f"Unexpected match for: {upn}"


# ---------------------------------------------------------------------------
# CA-BG-001 — no break-glass account detected
# ---------------------------------------------------------------------------


class TestBreakGlass001:
    def test_regular_users_only_raises_001(self):
        """When no user matches a BG pattern, CA-BG-001 must be raised."""
        users = [_user("u1", "alice@test.com"), _user("u2", "bob@test.com")]
        data = _make_data(users, [_mfa_all()])
        resolver = PolicyResolver.from_data(data)

        findings = BreakGlassAnalyser().analyse(data, resolver)

        assert any(f.id == "CA-BG-001" for f in findings)
        # BG-002 and BG-003 must NOT appear when there are no candidates
        assert not any(f.id == "CA-BG-002" for f in findings)
        assert not any(f.id == "CA-BG-003" for f in findings)

    def test_bg_by_name_no_001(self):
        """User with a break-glass keyword in UPN prevents CA-BG-001."""
        users = [_user("u-bg", "break-glass@test.com"), _user("u1", "alice@test.com")]
        data = _make_data(users, [_mfa_all()])
        resolver = PolicyResolver.from_data(data)

        findings = BreakGlassAnalyser().analyse(data, resolver)

        assert not any(f.id == "CA-BG-001" for f in findings)

    def test_bg_by_exclusion_from_all_mfa_policies(self):
        """User excluded from all MFA policies is detected as a BG account."""
        users = [_user("u1", "alice@test.com"), _user("u-bg", "svc-account@test.com")]
        # u-bg is excluded from the only MFA policy
        data = _make_data(users, [_mfa_all(exclude_users=["u-bg"])])
        resolver = PolicyResolver.from_data(data)

        findings = BreakGlassAnalyser().analyse(data, resolver)

        assert not any(f.id == "CA-BG-001" for f in findings)

    def test_bg_by_group_exclusion_from_mfa(self):
        """User in a group excluded from all MFA policies is a BG candidate."""
        users = [_user("u1", "alice@test.com"), _user("u-bg", "regular@test.com")]
        group = Group(
            id="g-bg", display_name="BG Group", member_ids=["u-bg"], transitive_member_ids=["u-bg"]
        )
        data = _make_data(users, [_mfa_all(exclude_groups=["g-bg"])], groups=[group])
        resolver = PolicyResolver.from_data(data)

        findings = BreakGlassAnalyser().analyse(data, resolver)

        assert not any(f.id == "CA-BG-001" for f in findings)

    def test_no_enabled_users_returns_empty(self):
        """When there are no enabled users, the analyser returns an empty list."""
        users = [_user("u1", "alice@test.com", enabled=False)]
        data = _make_data(users, [])
        resolver = PolicyResolver.from_data(data)

        findings = BreakGlassAnalyser().analyse(data, resolver)

        assert findings == []

    def test_001_confidence_below_1(self):
        """CA-BG-001 should have confidence < 1.0 (we may miss custom naming patterns)."""
        data = _make_data([_user("u1", "alice@test.com")], [_mfa_all()])
        resolver = PolicyResolver.from_data(data)

        findings = BreakGlassAnalyser().analyse(data, resolver)

        f001 = next((f for f in findings if f.id == "CA-BG-001"), None)
        assert f001 is not None
        assert f001.confidence < 1.0

    def test_no_mfa_policies_and_no_bg_name_raises_001(self):
        """User excluded from all MFA policies requires MFA policies to exist.
        If there are NO MFA policies, BG-by-exclusion logic doesn't fire."""
        users = [_user("u1", "alice@test.com")]
        # No MFA-enforcing policies → _identify_break_glass_candidates checks name only
        data = _make_data(users, [])
        resolver = PolicyResolver.from_data(data)

        findings = BreakGlassAnalyser().analyse(data, resolver)

        assert any(f.id == "CA-BG-001" for f in findings)


# ---------------------------------------------------------------------------
# CA-BG-002 — break-glass not using phishing-resistant auth
# ---------------------------------------------------------------------------


class TestBreakGlass002:
    def test_bg_with_only_basic_mfa_raises_002(self):
        """BG account covered only by basic MFA triggers CA-BG-002."""
        users = [_user("u-bg", "break-glass@test.com")]
        data = _make_data(users, [_mfa_all()])
        resolver = PolicyResolver.from_data(data)

        findings = BreakGlassAnalyser().analyse(data, resolver)

        assert any(f.id == "CA-BG-002" for f in findings)

    def test_bg_excluded_from_all_policies_raises_002(self):
        """BG fully excluded from CA policies has no phishing-resistant requirement → CA-BG-002."""
        users = [_user("u-bg", "break-glass@test.com")]
        data = _make_data(users, [_mfa_all(exclude_users=["u-bg"])])
        resolver = PolicyResolver.from_data(data)

        findings = BreakGlassAnalyser().analyse(data, resolver)

        # No phishing-resistant CA policy covers the BG account at all
        assert any(f.id == "CA-BG-002" for f in findings)

    def test_bg_with_fido2_policy_no_002(self):
        """BG covered by a FIDO2-targeted CA policy does not trigger CA-BG-002."""
        users = [_user("u-bg", "break-glass@test.com")]
        fido2_policy = _policy(
            "p-fido2", "FIDO2 for BG", include_users=["u-bg"], grant_controls=["fido2"]
        )
        data = _make_data(users, [_mfa_all(), fido2_policy])
        resolver = PolicyResolver.from_data(data)

        findings = BreakGlassAnalyser().analyse(data, resolver)

        assert not any(f.id == "CA-BG-002" for f in findings)

    def test_bg_with_phishing_resistant_control_no_002(self):
        """BG covered by a 'phishingResistant' built-in control does not trigger CA-BG-002."""
        users = [_user("u-bg", "break-glass@test.com")]
        pr_policy = _policy(
            "p-pr",
            "Phishing-resistant",
            include_users=["u-bg"],
            grant_controls=["phishingResistant"],
        )
        data = _make_data(users, [pr_policy])
        resolver = PolicyResolver.from_data(data)

        findings = BreakGlassAnalyser().analyse(data, resolver)

        assert not any(f.id == "CA-BG-002" for f in findings)

    def test_bg_with_windowshello_no_002(self):
        """Windows Hello for Business satisfies the phishing-resistant requirement."""
        users = [_user("u-bg", "break-glass@test.com")]
        whfb = _policy(
            "p-whfb",
            "WHfB",
            include_users=["u-bg"],
            grant_controls=["windowsHelloForBusiness"],
        )
        data = _make_data(users, [whfb])
        resolver = PolicyResolver.from_data(data)

        findings = BreakGlassAnalyser().analyse(data, resolver)

        assert not any(f.id == "CA-BG-002" for f in findings)

    def test_002_affected_principals(self):
        """CA-BG-002 lists the affected break-glass user IDs."""
        users = [_user("u-bg", "break-glass@test.com"), _user("u1", "alice@test.com")]
        data = _make_data(users, [_mfa_all()])
        resolver = PolicyResolver.from_data(data)

        findings = BreakGlassAnalyser().analyse(data, resolver)

        f002 = next((f for f in findings if f.id == "CA-BG-002"), None)
        assert f002 is not None
        assert "u-bg" in f002.affected_principals


# ---------------------------------------------------------------------------
# CA-BG-003 — break-glass still subject to CA policies
# ---------------------------------------------------------------------------


class TestBreakGlass003:
    def test_bg_covered_by_policy_raises_003(self):
        """BG account (by name) still covered by a CA policy triggers CA-BG-003."""
        users = [_user("u-bg", "break-glass@test.com")]
        data = _make_data(users, [_mfa_all()])  # MFA covers everyone including BG
        resolver = PolicyResolver.from_data(data)

        findings = BreakGlassAnalyser().analyse(data, resolver)

        assert any(f.id == "CA-BG-003" for f in findings)

    def test_bg_excluded_from_all_policies_no_003(self):
        """BG fully excluded from all CA policies does not trigger CA-BG-003."""
        users = [_user("u-bg", "break-glass@test.com")]
        data = _make_data(users, [_mfa_all(exclude_users=["u-bg"])])
        resolver = PolicyResolver.from_data(data)

        findings = BreakGlassAnalyser().analyse(data, resolver)

        assert not any(f.id == "CA-BG-003" for f in findings)

    def test_bg_excluded_via_group_no_003(self):
        """BG excluded via group membership is not flagged by CA-BG-003."""
        users = [_user("u-bg", "break-glass@test.com")]
        bg_group = Group(
            id="g-bg",
            display_name="BG Group",
            member_ids=["u-bg"],
            transitive_member_ids=["u-bg"],
        )
        data = _make_data(
            users,
            [_mfa_all(exclude_groups=["g-bg"])],
            groups=[bg_group],
        )
        resolver = PolicyResolver.from_data(data)

        findings = BreakGlassAnalyser().analyse(data, resolver)

        assert not any(f.id == "CA-BG-003" for f in findings)

    def test_bg_covered_by_report_only_no_003(self):
        """A report-only policy covering BG does not count as 'enforced'."""
        users = [_user("u-bg", "break-glass@test.com")]
        report_only = _policy(
            "p-ro",
            "MFA report-only",
            include_users=["All"],
            grant_controls=["mfa"],
            state=PolicyState.enabledForReportingButNotEnforced,
        )
        data = _make_data(users, [report_only])
        resolver = PolicyResolver.from_data(data)

        findings = BreakGlassAnalyser().analyse(data, resolver)

        assert not any(f.id == "CA-BG-003" for f in findings)

    def test_003_affected_principals(self):
        """CA-BG-003 lists the affected break-glass user IDs."""
        users = [_user("u-bg", "break-glass@test.com")]
        data = _make_data(users, [_mfa_all()])
        resolver = PolicyResolver.from_data(data)

        findings = BreakGlassAnalyser().analyse(data, resolver)

        f003 = next((f for f in findings if f.id == "CA-BG-003"), None)
        assert f003 is not None
        assert "u-bg" in f003.affected_principals

    def test_multiple_bg_accounts_all_in_003(self):
        """Multiple BG accounts all covered by policy → all in CA-BG-003 affected list."""
        users = [
            _user("u-bg1", "break-glass-1@test.com"),
            _user("u-bg2", "break-glass-2@test.com"),
            _user("u1", "alice@test.com"),
        ]
        data = _make_data(users, [_mfa_all()])
        resolver = PolicyResolver.from_data(data)

        findings = BreakGlassAnalyser().analyse(data, resolver)

        f003 = next((f for f in findings if f.id == "CA-BG-003"), None)
        assert f003 is not None
        assert "u-bg1" in f003.affected_principals
        assert "u-bg2" in f003.affected_principals


# ---------------------------------------------------------------------------
# Cross-finding scenarios
# ---------------------------------------------------------------------------


class TestBreakGlassCrossFindings:
    def test_properly_configured_bg_only_raises_002(self):
        """A BG account excluded from all policies but without FIDO2 only raises BG-002."""
        users = [_user("u-bg", "break-glass@test.com"), _user("u1", "alice@test.com")]
        # MFA policy covers everyone except the BG account
        data = _make_data(users, [_mfa_all(exclude_users=["u-bg"])])
        resolver = PolicyResolver.from_data(data)

        findings = BreakGlassAnalyser().analyse(data, resolver)

        ids = {f.id for f in findings}
        assert "CA-BG-001" not in ids  # BG was found
        assert "CA-BG-002" in ids  # but no phishing-resistant requirement
        assert "CA-BG-003" not in ids  # BG is correctly excluded from all policies

    def test_bg_not_excluded_raises_002_and_003(self):
        """BG account covered by basic MFA policy (not excluded) raises BG-002 + BG-003."""
        users = [_user("u-bg", "break-glass@test.com")]
        data = _make_data(users, [_mfa_all()])  # no exclusion
        resolver = PolicyResolver.from_data(data)

        findings = BreakGlassAnalyser().analyse(data, resolver)

        ids = {f.id for f in findings}
        assert "CA-BG-001" not in ids
        assert "CA-BG-002" in ids
        assert "CA-BG-003" in ids

    def test_bg_with_fido2_ca_policy_raises_003_not_001_not_002(self):
        """BG excluded from general MFA but covered by a targeted FIDO2 CA policy.

        CA-BG-001: not raised   — BG candidate was found
        CA-BG-002: not raised   — FIDO2 policy covers the BG account
        CA-BG-003: IS raised    — the FIDO2 CA policy still 'subjects' the BG account
                                  to CA. Fully removing CA coverage (using Authentication
                                  Methods Policy for FIDO2 instead) would suppress BG-003.
        """
        users = [_user("u-bg", "break-glass@test.com"), _user("u1", "alice@test.com")]
        fido2_policy = _policy(
            "p-fido2", "FIDO2 for BG", include_users=["u-bg"], grant_controls=["fido2"]
        )
        mfa_policy = _mfa_all(exclude_users=["u-bg"])
        data = _make_data(users, [mfa_policy, fido2_policy])
        resolver = PolicyResolver.from_data(data)

        findings = BreakGlassAnalyser().analyse(data, resolver)

        ids = {f.id for f in findings}
        assert "CA-BG-001" not in ids  # BG was detected
        assert "CA-BG-002" not in ids  # FIDO2 policy satisfies the phish-resistant check
        assert "CA-BG-003" in ids  # BG still covered by the FIDO2 CA policy itself
