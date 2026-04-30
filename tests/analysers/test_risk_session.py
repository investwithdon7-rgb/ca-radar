"""Tests for risk-based and session control analyser (CA-RISK-001, CA-RISK-002, CA-SESS-001)."""

from __future__ import annotations

from ca_radar.analysers.packs.risk_session.risk_session import RiskSessionAnalyser
from ca_radar.resolver.effective_controls import PolicyResolver
from ca_radar.resolver.policy_graph import SnapshotData
from ca_radar.snapshot.models import (
    CaApplicationCondition,
    CaConditions,
    CaGrantControl,
    CaSessionControl,
    CaUserCondition,
    ConditionalAccessPolicy,
    PolicyState,
    SignInRiskLevel,
    User,
    UserRiskLevel,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _user(uid: str = "u1", upn: str = "alice@test.com") -> User:
    return User(id=uid, user_principal_name=upn, account_enabled=True)


def _base_policy(pid: str) -> dict:
    """Return kwargs shared by all policy helpers."""
    return dict(
        id=pid,
        display_name=pid,
        state=PolicyState.enabled,
        conditions=CaConditions(
            users=CaUserCondition(include_users=["All"]),
            applications=CaApplicationCondition(include_applications=["All"]),
        ),
        grant_controls=CaGrantControl(operator="OR", built_in_controls=["mfa"]),
    )


def _sign_in_risk_policy(
    pid: str = "p-risk",
    *,
    risk_levels: list[str] | None = None,
    state: PolicyState = PolicyState.enabled,
) -> ConditionalAccessPolicy:
    conds = CaConditions(
        users=CaUserCondition(include_users=["All"]),
        applications=CaApplicationCondition(include_applications=["All"]),
        sign_in_risk_levels=[SignInRiskLevel(r) for r in (risk_levels or ["medium", "high"])],
    )
    return ConditionalAccessPolicy(
        id=pid,
        display_name=pid,
        state=state,
        conditions=conds,
        grant_controls=CaGrantControl(operator="OR", built_in_controls=["mfa"]),
    )


def _user_risk_policy(
    pid: str = "p-user-risk",
    *,
    risk_levels: list[str] | None = None,
    state: PolicyState = PolicyState.enabled,
) -> ConditionalAccessPolicy:
    conds = CaConditions(
        users=CaUserCondition(include_users=["All"]),
        applications=CaApplicationCondition(include_applications=["All"]),
        user_risk_levels=[UserRiskLevel(r) for r in (risk_levels or ["high"])],
    )
    return ConditionalAccessPolicy(
        id=pid,
        display_name=pid,
        state=state,
        conditions=conds,
        grant_controls=CaGrantControl(operator="OR", built_in_controls=["mfa"]),
    )


def _session_freq_policy(
    pid: str = "p-freq",
    *,
    state: PolicyState = PolicyState.enabled,
) -> ConditionalAccessPolicy:
    conds = CaConditions(
        users=CaUserCondition(include_users=["All"]),
        applications=CaApplicationCondition(include_applications=["All"]),
    )
    session = CaSessionControl(
        sign_in_frequency={"value": 1, "type": "hours", "isEnabled": True},
    )
    return ConditionalAccessPolicy(
        id=pid,
        display_name=pid,
        state=state,
        conditions=conds,
        grant_controls=CaGrantControl(operator="OR", built_in_controls=["mfa"]),
        session_controls=session,
    )


def _mfa_all(pid: str = "p-mfa") -> ConditionalAccessPolicy:
    return ConditionalAccessPolicy(**{**_base_policy(pid)})


def _make_data(
    policies: list[ConditionalAccessPolicy] | None = None,
) -> SnapshotData:
    data = SnapshotData(users=[_user()], policies=policies or [])
    data._build_indexes()
    return data


# ---------------------------------------------------------------------------
# CA-RISK-001 — no sign-in risk policy
# ---------------------------------------------------------------------------


class TestRisk001:
    def test_no_policies_raises_risk001(self):
        data = _make_data([])
        resolver = PolicyResolver.from_data(data)

        findings = RiskSessionAnalyser().analyse(data, resolver)

        assert any(f.id == "CA-RISK-001" for f in findings)

    def test_mfa_only_policy_raises_risk001(self):
        """An MFA policy with no sign-in risk condition doesn't satisfy CA-RISK-001."""
        data = _make_data([_mfa_all()])
        resolver = PolicyResolver.from_data(data)

        findings = RiskSessionAnalyser().analyse(data, resolver)

        assert any(f.id == "CA-RISK-001" for f in findings)

    def test_sign_in_risk_policy_no_risk001(self):
        """Policy with sign_in_risk_levels set → no CA-RISK-001."""
        data = _make_data([_sign_in_risk_policy()])
        resolver = PolicyResolver.from_data(data)

        findings = RiskSessionAnalyser().analyse(data, resolver)

        assert not any(f.id == "CA-RISK-001" for f in findings)

    def test_disabled_risk_policy_raises_risk001(self):
        """Disabled sign-in risk policy doesn't satisfy CA-RISK-001."""
        data = _make_data([_sign_in_risk_policy(state=PolicyState.disabled)])
        resolver = PolicyResolver.from_data(data)

        findings = RiskSessionAnalyser().analyse(data, resolver)

        assert any(f.id == "CA-RISK-001" for f in findings)

    def test_report_only_risk_policy_raises_risk001(self):
        """Report-only sign-in risk policy doesn't satisfy CA-RISK-001."""
        data = _make_data(
            [_sign_in_risk_policy(state=PolicyState.enabledForReportingButNotEnforced)]
        )
        resolver = PolicyResolver.from_data(data)

        findings = RiskSessionAnalyser().analyse(data, resolver)

        assert any(f.id == "CA-RISK-001" for f in findings)

    def test_evidence_shows_zero_count(self):
        data = _make_data([])
        resolver = PolicyResolver.from_data(data)

        findings = RiskSessionAnalyser().analyse(data, resolver)

        f = next(f for f in findings if f.id == "CA-RISK-001")
        assert f.evidence["sign_in_risk_policy_count"] == 0


# ---------------------------------------------------------------------------
# CA-RISK-002 — no user risk policy
# ---------------------------------------------------------------------------


class TestRisk002:
    def test_no_policies_raises_risk002(self):
        data = _make_data([])
        resolver = PolicyResolver.from_data(data)

        findings = RiskSessionAnalyser().analyse(data, resolver)

        assert any(f.id == "CA-RISK-002" for f in findings)

    def test_mfa_only_raises_risk002(self):
        """MFA policy without user_risk_levels doesn't satisfy CA-RISK-002."""
        data = _make_data([_mfa_all()])
        resolver = PolicyResolver.from_data(data)

        findings = RiskSessionAnalyser().analyse(data, resolver)

        assert any(f.id == "CA-RISK-002" for f in findings)

    def test_user_risk_policy_no_risk002(self):
        """Policy with user_risk_levels set → no CA-RISK-002."""
        data = _make_data([_user_risk_policy()])
        resolver = PolicyResolver.from_data(data)

        findings = RiskSessionAnalyser().analyse(data, resolver)

        assert not any(f.id == "CA-RISK-002" for f in findings)

    def test_sign_in_risk_policy_does_not_satisfy_risk002(self):
        """Sign-in risk policy doesn't satisfy the user-risk requirement."""
        data = _make_data([_sign_in_risk_policy()])
        resolver = PolicyResolver.from_data(data)

        findings = RiskSessionAnalyser().analyse(data, resolver)

        assert any(f.id == "CA-RISK-002" for f in findings)

    def test_disabled_user_risk_policy_raises_risk002(self):
        data = _make_data([_user_risk_policy(state=PolicyState.disabled)])
        resolver = PolicyResolver.from_data(data)

        findings = RiskSessionAnalyser().analyse(data, resolver)

        assert any(f.id == "CA-RISK-002" for f in findings)


# ---------------------------------------------------------------------------
# CA-SESS-001 — no sign-in frequency session control
# ---------------------------------------------------------------------------


class TestSession001:
    def test_no_policies_raises_sess001(self):
        data = _make_data([])
        resolver = PolicyResolver.from_data(data)

        findings = RiskSessionAnalyser().analyse(data, resolver)

        assert any(f.id == "CA-SESS-001" for f in findings)

    def test_mfa_policy_no_session_raises_sess001(self):
        """MFA policy with no session_controls → CA-SESS-001."""
        data = _make_data([_mfa_all()])
        resolver = PolicyResolver.from_data(data)

        findings = RiskSessionAnalyser().analyse(data, resolver)

        assert any(f.id == "CA-SESS-001" for f in findings)

    def test_session_freq_policy_no_sess001(self):
        """Policy with sign_in_frequency session control → no CA-SESS-001."""
        data = _make_data([_session_freq_policy()])
        resolver = PolicyResolver.from_data(data)

        findings = RiskSessionAnalyser().analyse(data, resolver)

        assert not any(f.id == "CA-SESS-001" for f in findings)

    def test_disabled_session_policy_raises_sess001(self):
        """Disabled session-frequency policy doesn't satisfy CA-SESS-001."""
        data = _make_data([_session_freq_policy(state=PolicyState.disabled)])
        resolver = PolicyResolver.from_data(data)

        findings = RiskSessionAnalyser().analyse(data, resolver)

        assert any(f.id == "CA-SESS-001" for f in findings)

    def test_persistent_browser_only_raises_sess001(self):
        """A policy with only persistent_browser (no sign_in_frequency) raises CA-SESS-001."""
        conds = CaConditions(
            users=CaUserCondition(include_users=["All"]),
            applications=CaApplicationCondition(include_applications=["All"]),
        )
        sess = CaSessionControl(persistent_browser={"mode": "never", "isEnabled": True})
        p = ConditionalAccessPolicy(
            id="p-persistent",
            display_name="p-persistent",
            state=PolicyState.enabled,
            conditions=conds,
            grant_controls=CaGrantControl(operator="OR", built_in_controls=["mfa"]),
            session_controls=sess,
        )
        data = _make_data([p])
        resolver = PolicyResolver.from_data(data)

        findings = RiskSessionAnalyser().analyse(data, resolver)

        assert any(f.id == "CA-SESS-001" for f in findings)

    def test_evidence_shows_zero_count(self):
        data = _make_data([])
        resolver = PolicyResolver.from_data(data)

        findings = RiskSessionAnalyser().analyse(data, resolver)

        f = next(f for f in findings if f.id == "CA-SESS-001")
        assert f.evidence["sign_in_frequency_policy_count"] == 0


# ---------------------------------------------------------------------------
# All three fire together with no policies
# ---------------------------------------------------------------------------


class TestAllThreeFireTogether:
    def test_empty_policies_raises_all_three(self):
        data = _make_data([])
        resolver = PolicyResolver.from_data(data)

        findings = RiskSessionAnalyser().analyse(data, resolver)

        ids = {f.id for f in findings}
        assert "CA-RISK-001" in ids
        assert "CA-RISK-002" in ids
        assert "CA-SESS-001" in ids

    def test_full_coverage_no_findings(self):
        """Sign-in risk + user risk + session frequency → no findings."""
        data = _make_data(
            [
                _sign_in_risk_policy(),
                _user_risk_policy(),
                _session_freq_policy(),
            ]
        )
        resolver = PolicyResolver.from_data(data)

        findings = RiskSessionAnalyser().analyse(data, resolver)

        assert not any(f.id in ("CA-RISK-001", "CA-RISK-002", "CA-SESS-001") for f in findings)
