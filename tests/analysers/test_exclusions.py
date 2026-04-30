"""Tests for exclusion hygiene analyser (CA-EXCL-001, CA-EXCL-002)."""

from __future__ import annotations

from ca_radar.analysers.packs.exclusions.exclusions import (
    _LARGE_GROUP_THRESHOLD,
    ExclusionAnalyser,
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


def _user(uid: str, upn: str) -> User:
    return User(id=uid, user_principal_name=upn, account_enabled=True)


def _group(gid: str, name: str, members: list[str]) -> Group:
    return Group(id=gid, display_name=name, member_ids=members, transitive_member_ids=members)


def _policy(
    pid: str,
    *,
    grant_controls: list[str] = None,
    exclude_users: list[str] = None,
    exclude_groups: list[str] = None,
    state: PolicyState = PolicyState.enabled,
) -> ConditionalAccessPolicy:
    uc = CaUserCondition(
        include_users=["All"],
        exclude_users=exclude_users or [],
        exclude_groups=exclude_groups or [],
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


def _make_data(
    users: list[User],
    policies: list[ConditionalAccessPolicy],
    groups: list[Group] | None = None,
) -> SnapshotData:
    data = SnapshotData(users=users, policies=policies, groups=groups or [])
    data._build_indexes()
    return data


# ---------------------------------------------------------------------------
# CA-EXCL-001 — ghost exclusions
# ---------------------------------------------------------------------------


class TestGhostExclusions:
    def test_no_exclusions_no_finding(self):
        users = [_user("u1", "alice@test.com")]
        data = _make_data(users, [_policy("p1")])
        resolver = PolicyResolver.from_data(data)

        findings = ExclusionAnalyser().analyse(data, resolver)

        assert not any(f.id == "CA-EXCL-001" for f in findings)

    def test_valid_user_exclusion_no_finding(self):
        """Excluding an existing user is fine."""
        users = [_user("u1", "alice@test.com"), _user("u2", "bob@test.com")]
        data = _make_data(users, [_policy("p1", exclude_users=["u2"])])
        resolver = PolicyResolver.from_data(data)

        findings = ExclusionAnalyser().analyse(data, resolver)

        assert not any(f.id == "CA-EXCL-001" for f in findings)

    def test_ghost_user_exclusion_raises_001(self):
        """Excluding a user ID that doesn't exist triggers CA-EXCL-001."""
        users = [_user("u1", "alice@test.com")]
        data = _make_data(users, [_policy("p1", exclude_users=["ghost-user-id"])])
        resolver = PolicyResolver.from_data(data)

        findings = ExclusionAnalyser().analyse(data, resolver)

        f001 = next((f for f in findings if f.id == "CA-EXCL-001"), None)
        assert f001 is not None
        assert "ghost-user-id" in f001.affected_principals

    def test_ghost_group_exclusion_raises_001(self):
        """Excluding a group ID that doesn't exist triggers CA-EXCL-001."""
        users = [_user("u1", "alice@test.com")]
        data = _make_data(users, [_policy("p1", exclude_groups=["ghost-group-id"])])
        resolver = PolicyResolver.from_data(data)

        findings = ExclusionAnalyser().analyse(data, resolver)

        f001 = next((f for f in findings if f.id == "CA-EXCL-001"), None)
        assert f001 is not None
        assert "ghost-group-id" in f001.affected_principals

    def test_valid_group_exclusion_no_finding(self):
        """Excluding a real group is fine."""
        users = [_user("u1", "alice@test.com")]
        group = _group("g1", "BG Group", ["u1"])
        data = _make_data(users, [_policy("p1", exclude_groups=["g1"])], groups=[group])
        resolver = PolicyResolver.from_data(data)

        findings = ExclusionAnalyser().analyse(data, resolver)

        assert not any(f.id == "CA-EXCL-001" for f in findings)

    def test_disabled_policy_exclusions_not_checked(self):
        """Ghost exclusions in disabled policies are not flagged."""
        users = [_user("u1", "alice@test.com")]
        data = _make_data(
            users,
            [_policy("p1", exclude_users=["ghost-id"], state=PolicyState.disabled)],
        )
        resolver = PolicyResolver.from_data(data)

        findings = ExclusionAnalyser().analyse(data, resolver)

        assert not any(f.id == "CA-EXCL-001" for f in findings)

    def test_multiple_ghost_refs_in_evidence(self):
        """Multiple ghost references are all captured in evidence."""
        users = [_user("u1", "alice@test.com")]
        data = _make_data(
            users,
            [_policy("p1", exclude_users=["ghost-1", "ghost-2"], exclude_groups=["ghost-g1"])],
        )
        resolver = PolicyResolver.from_data(data)

        findings = ExclusionAnalyser().analyse(data, resolver)

        f001 = next(f for f in findings if f.id == "CA-EXCL-001")
        assert f001.evidence["ghost_count"] == 3

    def test_report_only_exclusions_not_checked(self):
        """Ghost exclusions in report-only policies are not flagged."""
        users = [_user("u1", "alice@test.com")]
        data = _make_data(
            users,
            [
                _policy(
                    "p1",
                    exclude_users=["ghost-id"],
                    state=PolicyState.enabledForReportingButNotEnforced,
                )
            ],
        )
        resolver = PolicyResolver.from_data(data)

        findings = ExclusionAnalyser().analyse(data, resolver)

        assert not any(f.id == "CA-EXCL-001" for f in findings)


# ---------------------------------------------------------------------------
# CA-EXCL-002 — over-broad MFA exclusion groups
# ---------------------------------------------------------------------------


class TestOverBroadExclusions:
    def test_small_exclusion_group_no_finding(self):
        """An exclusion group within the threshold does not trigger CA-EXCL-002."""
        users = [_user(f"u{i}", f"u{i}@test.com") for i in range(_LARGE_GROUP_THRESHOLD)]
        small_group = _group(
            "g-bg", "BG Group", [u.id for u in users[:2]]
        )  # 2 members — well within threshold
        data = _make_data(users, [_policy("p-mfa", exclude_groups=["g-bg"])], groups=[small_group])
        resolver = PolicyResolver.from_data(data)

        findings = ExclusionAnalyser().analyse(data, resolver)

        assert not any(f.id == "CA-EXCL-002" for f in findings)

    def test_large_exclusion_group_triggers_002(self):
        """An exclusion group exceeding the threshold triggers CA-EXCL-002."""
        member_count = _LARGE_GROUP_THRESHOLD + 5
        users = [_user(f"u{i}", f"u{i}@test.com") for i in range(member_count)]
        large_group = _group("g-large", "Large Group", [u.id for u in users])
        data = _make_data(
            users, [_policy("p-mfa", exclude_groups=["g-large"])], groups=[large_group]
        )
        resolver = PolicyResolver.from_data(data)

        findings = ExclusionAnalyser().analyse(data, resolver)

        f002 = next((f for f in findings if f.id == "CA-EXCL-002"), None)
        assert f002 is not None
        assert "g-large" in f002.affected_principals

    def test_large_exclusion_on_non_mfa_policy_no_002(self):
        """A large exclusion on a block-legacy policy (not MFA) doesn't trigger CA-EXCL-002."""
        member_count = _LARGE_GROUP_THRESHOLD + 5
        users = [_user(f"u{i}", f"u{i}@test.com") for i in range(member_count)]
        large_group = _group("g-large", "Large Group", [u.id for u in users])
        # Block policy, not MFA policy
        data = _make_data(
            users,
            [_policy("p-block", grant_controls=["block"], exclude_groups=["g-large"])],
            groups=[large_group],
        )
        resolver = PolicyResolver.from_data(data)

        findings = ExclusionAnalyser().analyse(data, resolver)

        assert not any(f.id == "CA-EXCL-002" for f in findings)

    def test_ghost_group_in_mfa_policy_no_002(self):
        """A ghost group (doesn't exist) in an MFA exclusion doesn't trigger CA-EXCL-002.
        (It will trigger CA-EXCL-001 instead.)"""
        users = [_user("u1", "alice@test.com")]
        data = _make_data(
            users,
            [_policy("p-mfa", exclude_groups=["ghost-group-id"])],
        )
        resolver = PolicyResolver.from_data(data)

        findings = ExclusionAnalyser().analyse(data, resolver)

        assert not any(f.id == "CA-EXCL-002" for f in findings)
        assert any(f.id == "CA-EXCL-001" for f in findings)

    def test_evidence_includes_member_count(self):
        """CA-EXCL-002 evidence records the offending group and member count."""
        member_count = _LARGE_GROUP_THRESHOLD + 1
        users = [_user(f"u{i}", f"u{i}@test.com") for i in range(member_count)]
        large_group = _group("g-big", "Big Group", [u.id for u in users])
        data = _make_data(users, [_policy("p-mfa", exclude_groups=["g-big"])], groups=[large_group])
        resolver = PolicyResolver.from_data(data)

        findings = ExclusionAnalyser().analyse(data, resolver)

        f002 = next(f for f in findings if f.id == "CA-EXCL-002")
        detail = f002.evidence["details"][0]
        assert detail["group_id"] == "g-big"
        assert detail["member_count"] == member_count
