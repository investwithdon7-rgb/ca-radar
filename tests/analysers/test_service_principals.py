"""Tests for service principal / workload identity analyser (CA-SP-001, CA-SP-002)."""

from __future__ import annotations

from ca_radar.analysers.packs.service_principals.service_principals import (
    _HIGH_VALUE_APP_IDS,
    ServicePrincipalAnalyser,
)
from ca_radar.resolver.effective_controls import PolicyResolver
from ca_radar.resolver.policy_graph import SnapshotData
from ca_radar.snapshot.models import (
    CaApplicationCondition,
    CaConditions,
    CaGrantControl,
    CaUserCondition,
    ConditionalAccessPolicy,
    PolicyState,
    ServicePrincipal,
    User,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _user(uid: str = "u1", upn: str = "alice@test.com") -> User:
    return User(id=uid, user_principal_name=upn, account_enabled=True)


def _sp(sid: str, name: str, app_id: str | None = None) -> ServicePrincipal:
    return ServicePrincipal(id=sid, display_name=name, app_id=app_id or sid)


def _policy_all_apps(
    pid: str, *, state: PolicyState = PolicyState.enabled
) -> ConditionalAccessPolicy:
    """Standard all-apps MFA policy (no client_applications condition)."""
    return ConditionalAccessPolicy(
        id=pid,
        display_name=pid,
        state=state,
        conditions=CaConditions(
            users=CaUserCondition(include_users=["All"]),
            applications=CaApplicationCondition(include_applications=["All"]),
        ),
        grant_controls=CaGrantControl(operator="OR", built_in_controls=["mfa"]),
    )


def _workload_policy(
    pid: str, *, state: PolicyState = PolicyState.enabled
) -> ConditionalAccessPolicy:
    """Policy with client_applications set (workload identity CA)."""
    return ConditionalAccessPolicy(
        id=pid,
        display_name=pid,
        state=state,
        conditions=CaConditions(
            users=CaUserCondition(include_users=["All"]),
            applications=CaApplicationCondition(include_applications=["All"]),
            client_applications={"servicePrincipals": ["All"]},
        ),
        grant_controls=CaGrantControl(operator="OR", built_in_controls=["mfa"]),
    )


def _app_specific_policy(pid: str, app_id: str) -> ConditionalAccessPolicy:
    """Policy targeting a specific application ID."""
    return ConditionalAccessPolicy(
        id=pid,
        display_name=pid,
        state=PolicyState.enabled,
        conditions=CaConditions(
            users=CaUserCondition(include_users=["All"]),
            applications=CaApplicationCondition(include_applications=[app_id]),
        ),
        grant_controls=CaGrantControl(operator="OR", built_in_controls=["mfa"]),
    )


def _make_data(
    users: list[User] | None = None,
    policies: list[ConditionalAccessPolicy] | None = None,
    service_principals: list[ServicePrincipal] | None = None,
) -> SnapshotData:
    data = SnapshotData(
        users=users or [_user()],
        policies=policies or [],
        service_principals=service_principals or [],
    )
    data._build_indexes()
    return data


# ---------------------------------------------------------------------------
# CA-SP-001 — no workload identity CA policy
# ---------------------------------------------------------------------------


class TestServicePrincipalSP001:
    def test_no_workload_policy_raises_sp001(self):
        """No policy has client_applications → CA-SP-001."""
        data = _make_data(policies=[_policy_all_apps("p-mfa")])
        resolver = PolicyResolver.from_data(data)

        findings = ServicePrincipalAnalyser().analyse(data, resolver)

        assert any(f.id == "CA-SP-001" for f in findings)

    def test_workload_policy_present_no_sp001(self):
        """Policy with client_applications condition → no CA-SP-001."""
        data = _make_data(policies=[_workload_policy("p-workload")])
        resolver = PolicyResolver.from_data(data)

        findings = ServicePrincipalAnalyser().analyse(data, resolver)

        assert not any(f.id == "CA-SP-001" for f in findings)

    def test_disabled_workload_policy_still_raises_sp001(self):
        """Disabled workload identity policy doesn't satisfy CA-SP-001."""
        data = _make_data(policies=[_workload_policy("p-workload", state=PolicyState.disabled)])
        resolver = PolicyResolver.from_data(data)

        findings = ServicePrincipalAnalyser().analyse(data, resolver)

        assert any(f.id == "CA-SP-001" for f in findings)

    def test_sp_count_in_evidence(self):
        """CA-SP-001 evidence includes the number of service principals."""
        sps = [_sp(f"sp{i}", f"app{i}") for i in range(3)]
        data = _make_data(policies=[], service_principals=sps)
        resolver = PolicyResolver.from_data(data)

        findings = ServicePrincipalAnalyser().analyse(data, resolver)

        f001 = next(f for f in findings if f.id == "CA-SP-001")
        assert f001.evidence["service_principal_count"] == 3

    def test_no_policies_no_sps_still_raises_sp001(self):
        """Even with no SPs registered, CA-SP-001 is raised (the feature is unconfigured)."""
        data = _make_data(policies=[], service_principals=[])
        resolver = PolicyResolver.from_data(data)

        findings = ServicePrincipalAnalyser().analyse(data, resolver)

        assert any(f.id == "CA-SP-001" for f in findings)


# ---------------------------------------------------------------------------
# CA-SP-002 — no app-specific CA policies
# ---------------------------------------------------------------------------


class TestServicePrincipalSP002:
    def test_all_apps_only_raises_sp002_when_sps_present(self):
        """All policies use 'All' apps and SPs are present → CA-SP-002."""
        sps = [_sp("sp1", "MyApp")]
        data = _make_data(policies=[_policy_all_apps("p-mfa")], service_principals=sps)
        resolver = PolicyResolver.from_data(data)

        findings = ServicePrincipalAnalyser().analyse(data, resolver)

        assert any(f.id == "CA-SP-002" for f in findings)

    def test_app_specific_policy_no_sp002(self):
        """At least one policy targeting a specific app ID → no CA-SP-002."""
        sps = [_sp("sp1", "AzureMgmt", app_id="797f4846-ba00-4fd7-ba43-dac1f8f63013")]
        data = _make_data(
            policies=[_app_specific_policy("p-azure-mgmt", "797f4846-ba00-4fd7-ba43-dac1f8f63013")],
            service_principals=sps,
        )
        resolver = PolicyResolver.from_data(data)

        findings = ServicePrincipalAnalyser().analyse(data, resolver)

        assert not any(f.id == "CA-SP-002" for f in findings)

    def test_no_sps_no_sp002(self):
        """If there are no service principals at all, CA-SP-002 is not raised."""
        data = _make_data(policies=[_policy_all_apps("p-mfa")], service_principals=[])
        resolver = PolicyResolver.from_data(data)

        findings = ServicePrincipalAnalyser().analyse(data, resolver)

        assert not any(f.id == "CA-SP-002" for f in findings)

    def test_high_value_app_ids_recognised(self):
        """High-value app IDs from _HIGH_VALUE_APP_IDS are detected in evidence."""
        azure_mgmt_id = "797f4846-ba00-4fd7-ba43-dac1f8f63013"
        assert azure_mgmt_id in _HIGH_VALUE_APP_IDS

        sps = [_sp("sp-az", "Azure Mgmt", app_id=azure_mgmt_id)]
        data = _make_data(policies=[_policy_all_apps("p-mfa")], service_principals=sps)
        resolver = PolicyResolver.from_data(data)

        findings = ServicePrincipalAnalyser().analyse(data, resolver)

        f002 = next((f for f in findings if f.id == "CA-SP-002"), None)
        assert f002 is not None
        assert azure_mgmt_id in f002.evidence["high_value_app_ids_found"]
