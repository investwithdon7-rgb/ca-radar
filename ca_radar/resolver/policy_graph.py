"""Builds a NetworkX directed graph representing all relationships in a snapshot.

The graph is the data structure shared between the resolver (for logic) and the
renderer (for the D3 visualisation).  Every node has a `node_type` attribute;
every edge has a `rel` attribute describing the relationship.

Node types:   user | group | role | policy | application | service_principal
Edge rel:     member_of | has_role | includes_user | excludes_user |
              includes_group | excludes_group | includes_role | excludes_role |
              includes_app | excludes_app | grants_control | requires

Usage:
    graph = PolicyGraph.from_snapshot(snapshot_path, store)
    nx_graph = graph.nx        # raw NetworkX DiGraph
    graph_json = graph.to_json_dict()   # for D3 rendering
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import networkx as nx

from ca_radar.resolver.exclusion_walker import build_user_group_index
from ca_radar.snapshot.models import (
    Application,
    AuthenticationStrengthPolicy,
    ConditionalAccessPolicy,
    DirectoryRole,
    Group,
    PimEligibleRoleAssignment,
    PolicyState,
    RoleAssignment,
    ServicePrincipal,
    User,
)
from ca_radar.snapshot.store import SnapshotStore

log = logging.getLogger(__name__)

# Well-known sentinel values used in CA policy conditions
ALL_USERS = "All"
ALL_APPS = "All"
GUEST_USERS = "GuestsOrExternalUsers"
NONE_VALUE = "None"


@dataclass
class SnapshotData:
    """All resolver-relevant resources loaded from a snapshot."""

    policies: list[ConditionalAccessPolicy] = field(default_factory=list)
    users: list[User] = field(default_factory=list)
    groups: list[Group] = field(default_factory=list)
    roles: list[DirectoryRole] = field(default_factory=list)
    role_assignments: list[RoleAssignment] = field(default_factory=list)
    pim_eligible_role_assignments: list[PimEligibleRoleAssignment] = field(default_factory=list)
    applications: list[Application] = field(default_factory=list)
    service_principals: list[ServicePrincipal] = field(default_factory=list)
    authentication_strength_policies: list[AuthenticationStrengthPolicy] = field(
        default_factory=list
    )

    # Derived indexes (populated by _build_indexes)
    users_by_id: dict[str, User] = field(default_factory=dict)
    groups_by_id: dict[str, Group] = field(default_factory=dict)
    roles_by_id: dict[str, DirectoryRole] = field(default_factory=dict)
    apps_by_id: dict[str, Application] = field(default_factory=dict)
    sps_by_id: dict[str, ServicePrincipal] = field(default_factory=dict)
    # user_id → set of role template IDs (from active assignments)
    user_role_index: dict[str, set[str]] = field(default_factory=dict)
    # user_id → set of group IDs (transitive)
    user_group_index: dict[str, set[str]] = field(default_factory=dict)
    # user_id → set of role_definition_ids from PIM eligible assignments
    user_pim_role_index: dict[str, set[str]] = field(default_factory=dict)

    @classmethod
    def from_store(cls, snapshot_path: Path, store: SnapshotStore) -> SnapshotData:
        """Load all resolver-relevant resources from a snapshot."""

        def _load_list(name: str, model: type) -> list:
            try:
                return store.read_resource_list(snapshot_path, name, model)
            except Exception as exc:
                log.warning("Could not load %s from snapshot: %s", name, exc)
                return []

        data = cls(
            policies=_load_list("conditional_access_policies", ConditionalAccessPolicy),
            users=_load_list("users", User),
            groups=_load_list("groups", Group),
            roles=_load_list("directory_roles", DirectoryRole),
            role_assignments=_load_list("role_assignments", RoleAssignment),
            pim_eligible_role_assignments=_load_list(
                "pim_eligible_role_assignments", PimEligibleRoleAssignment
            ),
            applications=_load_list("applications", Application),
            service_principals=_load_list("service_principals", ServicePrincipal),
            authentication_strength_policies=_load_list(
                "authentication_strength_policies", AuthenticationStrengthPolicy
            ),
        )
        data._build_indexes()
        return data

    def _build_indexes(self) -> None:
        self.users_by_id = {u.id: u for u in self.users}
        self.groups_by_id = {g.id: g for g in self.groups}
        self.roles_by_id = {r.id: r for r in self.roles}
        self.apps_by_id = {a.id: a for a in self.applications}
        self.sps_by_id = {s.id: s for s in self.service_principals}

        # user_role_index: map user → set of role_definition_id (active assignments)
        for ra in self.role_assignments:
            self.user_role_index.setdefault(ra.principal_id, set()).add(ra.role_definition_id)

        # user_pim_role_index: map user → set of role_definition_id (PIM eligible)
        for pra in self.pim_eligible_role_assignments:
            self.user_pim_role_index.setdefault(pra.principal_id, set()).add(pra.role_definition_id)

        # user_group_index: transitive group memberships per user
        self.user_group_index = build_user_group_index(self.groups_by_id)


class PolicyGraph:
    """Wraps a NetworkX DiGraph and exposes high-level graph queries."""

    def __init__(self, data: SnapshotData) -> None:
        self.data = data
        self.nx: nx.DiGraph = nx.DiGraph()
        self._build()

    @classmethod
    def from_snapshot(cls, snapshot_path: Path, store: SnapshotStore) -> PolicyGraph:
        data = SnapshotData.from_store(snapshot_path, store)
        return cls(data)

    @classmethod
    def from_data(cls, data: SnapshotData) -> PolicyGraph:
        return cls(data)

    # ------------------------------------------------------------------
    # Graph construction
    # ------------------------------------------------------------------

    def _build(self) -> None:
        g = self.nx

        for user in self.data.users:
            g.add_node(user.id, node_type="user", label=user.user_principal_name or user.id)

        for group in self.data.groups:
            g.add_node(group.id, node_type="group", label=group.display_name)

        for role in self.data.roles:
            node_id = role.role_template_id or role.id
            g.add_node(node_id, node_type="role", label=role.display_name)

        for app in self.data.applications:
            g.add_node(app.id, node_type="application", label=app.display_name)

        for sp in self.data.service_principals:
            g.add_node(sp.id, node_type="service_principal", label=sp.display_name)

        for policy in self.data.policies:
            if policy.state == PolicyState.disabled:
                continue
            g.add_node(
                policy.id, node_type="policy", label=policy.display_name, state=policy.state.value
            )

        # User → group memberships
        for user_id, group_ids in self.data.user_group_index.items():
            for gid in group_ids:
                if g.has_node(user_id) and g.has_node(gid):
                    g.add_edge(user_id, gid, rel="member_of")

        # User → role assignments
        for user_id, role_ids in self.data.user_role_index.items():
            for rid in role_ids:
                if g.has_node(user_id) and g.has_node(rid):
                    g.add_edge(user_id, rid, rel="has_role")

        # Policy → condition edges
        for policy in self.data.policies:
            if policy.state == PolicyState.disabled:
                continue
            cond = policy.conditions
            if cond.users:
                for uid in cond.users.include_users:
                    if uid not in (ALL_USERS, NONE_VALUE, GUEST_USERS):
                        _safe_add_edge(g, policy.id, uid, rel="includes_user")
                for uid in cond.users.exclude_users:
                    _safe_add_edge(g, policy.id, uid, rel="excludes_user")
                for gid in cond.users.include_groups:
                    _safe_add_edge(g, policy.id, gid, rel="includes_group")
                for gid in cond.users.exclude_groups:
                    _safe_add_edge(g, policy.id, gid, rel="excludes_group")
                for rid in cond.users.include_roles:
                    _safe_add_edge(g, policy.id, rid, rel="includes_role")
                for rid in cond.users.exclude_roles:
                    _safe_add_edge(g, policy.id, rid, rel="excludes_role")
            if cond.applications:
                for aid in cond.applications.include_applications:
                    if aid not in (ALL_APPS, NONE_VALUE):
                        _safe_add_edge(g, policy.id, aid, rel="includes_app")
                for aid in cond.applications.exclude_applications:
                    _safe_add_edge(g, policy.id, aid, rel="excludes_app")

    # ------------------------------------------------------------------
    # Serialisation (for D3)
    # ------------------------------------------------------------------

    def to_json_dict(self) -> dict[str, Any]:
        """Return a {nodes, links} dict suitable for D3 force-directed graph."""
        nodes = [{"id": n, **self.nx.nodes[n]} for n in self.nx.nodes]
        links = [
            {"source": u, "target": v, "rel": d.get("rel", "")}
            for u, v, d in self.nx.edges(data=True)
        ]
        return {"nodes": nodes, "links": links}

    # ------------------------------------------------------------------
    # Convenience queries
    # ------------------------------------------------------------------

    def policies_for_user(self, user_id: str) -> list[str]:
        """Return policy node IDs that have any edge to this user (direct or via group/role)."""
        result = []
        for policy in self.data.policies:
            if policy.state == PolicyState.disabled:
                continue
            if (
                policy.id in self.nx
                and user_id in self.nx
                and nx.has_path(self.nx, policy.id, user_id)
            ):
                result.append(policy.id)
        return result


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _safe_add_edge(g: nx.DiGraph, src: str, dst: str, **attrs: Any) -> None:
    """Add an edge only if both nodes exist (avoids phantom nodes from policy refs)."""
    if not g.has_node(src):
        g.add_node(src, node_type="unknown")
    if not g.has_node(dst):
        g.add_node(dst, node_type="unknown")
    g.add_edge(src, dst, **attrs)
