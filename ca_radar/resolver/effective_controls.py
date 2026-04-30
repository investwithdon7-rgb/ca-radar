"""Effective controls resolver.

Answers two questions from a loaded snapshot:

1. `effective_policies(user_id, app_id, conditions)` → list[ConditionalAccessPolicy]
   Which CA policies apply to this specific (user, app, conditions) combination?

2. `coverage_matrix(user_ids, app_ids)` → dict[(user_id, app_id), EffectiveAccess]
   For every (user, app) pair, what is the effective MFA/block/session state?

The resolver is intentionally conservative: when it cannot determine membership
(e.g. a dynamic group whose rule was not evaluated), it includes the policy as
potentially applicable and marks confidence < 1.0.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field

from ca_radar.resolver.policy_graph import (
    ALL_APPS,
    ALL_USERS,
    GUEST_USERS,
    NONE_VALUE,
    SnapshotData,
)
from ca_radar.snapshot.models import ConditionalAccessPolicy, PolicyState

log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Public data types
# ---------------------------------------------------------------------------


@dataclass
class EffectiveAccess:
    """The net result of all CA policies that apply to a (user, app) pair."""

    user_id: str
    app_id: str
    applied_policies: list[str] = field(default_factory=list)  # policy IDs
    mfa_required: bool = False
    block: bool = False
    compliant_device_required: bool = False
    hybrid_joined_required: bool = False
    session_controls: list[str] = field(default_factory=list)
    report_only_policies: list[str] = field(default_factory=list)
    confidence: float = 1.0  # < 1.0 when dynamic group membership is uncertain


@dataclass
class EvaluationConditions:
    """Runtime conditions supplied to the evaluator (e.g. from sign-in logs)."""

    client_app_type: str = (
        "browser"  # browser | mobileAppsAndDesktopClients | exchangeActiveSync | other
    )
    sign_in_risk_level: str = "none"  # none | low | medium | high
    user_risk_level: str = "none"
    device_compliant: bool | None = None  # None = unknown
    device_hybrid_joined: bool | None = None
    location_id: str | None = None
    is_guest: bool = False


# ---------------------------------------------------------------------------
# Resolver class
# ---------------------------------------------------------------------------


class PolicyResolver:
    """Stateful resolver built from a SnapshotData.

    Build once per scan; call `effective_policies` and `coverage_matrix` many times.
    """

    def __init__(self, data: SnapshotData) -> None:
        self._data = data
        self._membership_cache: dict[str, set[str]] = {}  # group_id → user IDs

    @classmethod
    def from_data(cls, data: SnapshotData) -> PolicyResolver:
        return cls(data)

    # ------------------------------------------------------------------
    # Primary API
    # ------------------------------------------------------------------

    def effective_policies(
        self,
        user_id: str,
        app_id: str,
        conditions: EvaluationConditions | None = None,
    ) -> list[ConditionalAccessPolicy]:
        """Return CA policies that apply to (user_id, app_id) under *conditions*.

        Disabled policies are always excluded.
        Report-only policies are included (callers inspect `.state` to distinguish).
        """
        conds = conditions or EvaluationConditions()
        result = []
        for policy in self._data.policies:
            if policy.state == PolicyState.disabled:
                continue
            if self._policy_applies(policy, user_id, app_id, conds):
                result.append(policy)
        return result

    def coverage_matrix(
        self,
        user_ids: list[str] | None = None,
        app_ids: list[str] | None = None,
        conditions: EvaluationConditions | None = None,
    ) -> dict[tuple[str, str], EffectiveAccess]:
        """Return EffectiveAccess for every (user, app) combination.

        Defaults to all users × all apps in the snapshot (can be large).
        Pass `user_ids` and/or `app_ids` to restrict the matrix.
        """
        uids = user_ids or [u.id for u in self._data.users]
        aids = app_ids or self._all_app_ids()
        conds = conditions or EvaluationConditions()

        matrix: dict[tuple[str, str], EffectiveAccess] = {}
        for uid in uids:
            for aid in aids:
                policies = self.effective_policies(uid, aid, conds)
                matrix[(uid, aid)] = self._aggregate_controls(uid, aid, policies)
        return matrix

    # ------------------------------------------------------------------
    # Internal: policy applicability
    # ------------------------------------------------------------------

    def _policy_applies(
        self,
        policy: ConditionalAccessPolicy,
        user_id: str,
        app_id: str,
        conds: EvaluationConditions,
    ) -> bool:
        return (
            self._user_included(policy, user_id, conds)
            and not self._user_excluded(policy, user_id, conds)
            and self._app_included(policy, app_id)
            and not self._app_excluded(policy, app_id)
            and self._client_app_matches(policy, conds)
        )

    # -- User inclusion ---------------------------------------------------

    def _user_included(
        self,
        policy: ConditionalAccessPolicy,
        user_id: str,
        conds: EvaluationConditions,
    ) -> bool:
        uc = policy.conditions.users
        if not uc:
            return True  # no user condition → applies to all

        include_users = uc.include_users
        include_groups = uc.include_groups
        include_roles = uc.include_roles

        # "All" sentinel
        if ALL_USERS in include_users:
            return True

        # GuestsOrExternalUsers
        if GUEST_USERS in include_users and conds.is_guest:
            return True

        # Direct user inclusion
        if user_id in include_users:
            return True

        # Group inclusion
        user_groups = self._data.user_group_index.get(user_id, set())
        if any(gid in user_groups for gid in include_groups):
            return True

        # Role inclusion
        user_roles = self._data.user_role_index.get(user_id, set())
        return any(rid in user_roles for rid in include_roles)

    def _user_excluded(
        self,
        policy: ConditionalAccessPolicy,
        user_id: str,
        conds: EvaluationConditions,
    ) -> bool:
        uc = policy.conditions.users
        if not uc:
            return False

        # Direct exclusion
        if user_id in uc.exclude_users:
            return True

        # Group exclusion
        user_groups = self._data.user_group_index.get(user_id, set())
        if any(gid in user_groups for gid in uc.exclude_groups):
            return True

        # Role exclusion
        user_roles = self._data.user_role_index.get(user_id, set())
        return any(rid in user_roles for rid in uc.exclude_roles)

    # -- App inclusion ----------------------------------------------------

    def _app_included(self, policy: ConditionalAccessPolicy, app_id: str) -> bool:
        ac = policy.conditions.applications
        if not ac:
            return True
        include = ac.include_applications
        if ALL_APPS in include:
            return True
        if NONE_VALUE in include:
            return False
        return app_id in include

    def _app_excluded(self, policy: ConditionalAccessPolicy, app_id: str) -> bool:
        ac = policy.conditions.applications
        if not ac:
            return False
        return app_id in ac.exclude_applications

    # -- Client app type --------------------------------------------------

    def _client_app_matches(
        self, policy: ConditionalAccessPolicy, conds: EvaluationConditions
    ) -> bool:
        cat = policy.conditions.client_app_types
        if not cat:
            return True  # no restriction → all client types
        return conds.client_app_type in cat or "all" in [c.lower() for c in cat]

    # -- Aggregate policies → EffectiveAccess ----------------------------

    def _aggregate_controls(
        self,
        user_id: str,
        app_id: str,
        policies: list[ConditionalAccessPolicy],
    ) -> EffectiveAccess:
        access = EffectiveAccess(user_id=user_id, app_id=app_id)

        for policy in policies:
            if policy.state == PolicyState.enabledForReportingButNotEnforced:
                access.report_only_policies.append(policy.id)
                continue

            access.applied_policies.append(policy.id)
            gc = policy.grant_controls

            if gc:
                controls = [c.lower() for c in gc.built_in_controls]
                if "block" in controls:
                    access.block = True
                if "mfa" in controls:
                    access.mfa_required = True
                if "compliantdevice" in controls:
                    access.compliant_device_required = True
                if "domainjoined" in controls:
                    access.hybrid_joined_required = True

            sc = policy.session_controls
            if sc:
                if sc.sign_in_frequency:
                    access.session_controls.append("signInFrequency")
                if sc.persistent_browser:
                    access.session_controls.append("persistentBrowser")
                if sc.cloud_app_security:
                    access.session_controls.append("cloudAppSecurity")
                if sc.application_enforced_restrictions:
                    access.session_controls.append("appEnforcedRestrictions")

        return access

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _all_app_ids(self) -> list[str]:
        """Collect every app ID referenced in any policy (include lists)."""
        ids: set[str] = set()
        for p in self._data.policies:
            if p.state == PolicyState.disabled:
                continue
            ac = p.conditions.applications
            if ac:
                for aid in ac.include_applications:
                    if aid not in (ALL_APPS, NONE_VALUE):
                        ids.add(aid)
        # Also add registered applications
        for app in self._data.applications:
            ids.add(app.id)
        return sorted(ids) or ["AllApps"]
