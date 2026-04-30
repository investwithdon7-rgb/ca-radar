"""Tests for PolicyResolver and PolicyGraph across all three fixture tenants."""

from __future__ import annotations

from ca_radar.resolver.effective_controls import EvaluationConditions, PolicyResolver
from ca_radar.resolver.policy_graph import PolicyGraph, SnapshotData
from ca_radar.snapshot.models import PolicyState
from tests.fixtures.resolver_fixtures import (
    exclusion_heavy_tenant,
    nested_groups_tenant,
    simple_tenant,
)

# ============================================================================
# Simple tenant
# ============================================================================


class TestSimpleTenant:
    def setup_method(self) -> None:
        self.data = simple_tenant()
        self.resolver = PolicyResolver.from_data(self.data)

    def test_mfa_policy_applies_to_regular_user(self) -> None:
        policies = self.resolver.effective_policies("u-bob", "AllApps")
        ids = [p.id for p in policies]
        assert "p-mfa" in ids

    def test_break_glass_excluded_from_mfa_policy(self) -> None:
        policies = self.resolver.effective_policies("u-bg", "AllApps")
        ids = [p.id for p in policies]
        assert "p-mfa" not in ids

    def test_legacy_block_applies_to_legacy_client(self) -> None:
        conds = EvaluationConditions(client_app_type="exchangeActiveSync")
        policies = self.resolver.effective_policies("u-bob", "AllApps", conds)
        ids = [p.id for p in policies]
        assert "p-legacy" in ids

    def test_legacy_block_does_not_apply_to_browser(self) -> None:
        conds = EvaluationConditions(client_app_type="browser")
        policies = self.resolver.effective_policies("u-bob", "AllApps", conds)
        ids = [p.id for p in policies]
        assert "p-legacy" not in ids

    def test_disabled_policy_never_returned(self) -> None:
        # Temporarily mark MFA policy as disabled
        self.data.policies[0].state = PolicyState.disabled
        policies = self.resolver.effective_policies("u-alice", "AllApps")
        assert all(p.id != "p-mfa" for p in policies)
        self.data.policies[0].state = PolicyState.enabled  # restore

    def test_effective_access_mfa_required_for_bob(self) -> None:
        matrix = self.resolver.coverage_matrix(
            user_ids=["u-bob"],
            app_ids=["AllApps"],
            conditions=EvaluationConditions(client_app_type="browser"),
        )
        access = matrix[("u-bob", "AllApps")]
        assert access.mfa_required is True
        assert access.block is False

    def test_effective_access_block_for_legacy_client(self) -> None:
        matrix = self.resolver.coverage_matrix(
            user_ids=["u-bob"],
            app_ids=["AllApps"],
            conditions=EvaluationConditions(client_app_type="exchangeActiveSync"),
        )
        access = matrix[("u-bob", "AllApps")]
        assert access.block is True

    def test_coverage_matrix_returns_all_users(self) -> None:
        matrix = self.resolver.coverage_matrix(app_ids=["AllApps"])
        user_ids = {k[0] for k in matrix}
        assert "u-alice" in user_ids
        assert "u-bob" in user_ids
        assert "u-bg" in user_ids


# ============================================================================
# Nested groups tenant
# ============================================================================


class TestNestedGroupsTenant:
    def setup_method(self) -> None:
        self.data = nested_groups_tenant()
        self.resolver = PolicyResolver.from_data(self.data)

    def test_leaf_user_covered_via_nested_group(self) -> None:
        """carol is in backend-team → engineers → all-staff; policy targets all-staff."""
        policies = self.resolver.effective_policies("u-carol", "AllApps")
        ids = [p.id for p in policies]
        assert "p-mfa-staff" in ids

    def test_leaf_user_dave_also_covered(self) -> None:
        policies = self.resolver.effective_policies("u-dave", "AllApps")
        assert any(p.id == "p-mfa-staff" for p in policies)

    def test_user_not_in_group_not_covered(self) -> None:
        """eve is not in any group — should not be covered by the staff policy."""
        policies = self.resolver.effective_policies("u-eve", "AllApps")
        assert all(p.id != "p-mfa-staff" for p in policies)

    def test_user_group_index_built_correctly(self) -> None:
        index = self.data.user_group_index
        # carol should be in backend-team at minimum
        assert "g-backend" in index.get("u-carol", set())

    def test_no_policy_for_non_existent_user(self) -> None:
        policies = self.resolver.effective_policies("u-phantom", "AllApps")
        assert policies == []


# ============================================================================
# Exclusion-heavy tenant
# ============================================================================


class TestExclusionHeavyTenant:
    def setup_method(self) -> None:
        self.data = exclusion_heavy_tenant()
        self.resolver = PolicyResolver.from_data(self.data)

    def test_grace_excluded_from_mfa_via_group(self) -> None:
        """grace is in VIP exclusion group → excluded from p-mfa-all."""
        policies = self.resolver.effective_policies("u-grace", "AllApps")
        ids = [p.id for p in policies]
        assert "p-mfa-all" not in ids

    def test_harry_not_excluded_from_mfa(self) -> None:
        """harry has no exclusions → covered by p-mfa-all."""
        policies = self.resolver.effective_policies("u-harry", "AllApps")
        ids = [p.id for p in policies]
        assert "p-mfa-all" in ids

    def test_report_only_policy_not_in_enforced_controls(self) -> None:
        """p-legacy-ro is report-only — should appear in report_only_policies not applied_policies."""
        matrix = self.resolver.coverage_matrix(user_ids=["u-harry"], app_ids=["AllApps"])
        access = matrix[("u-harry", "AllApps")]
        assert "p-legacy-ro" in access.report_only_policies
        assert "p-legacy-ro" not in access.applied_policies

    def test_report_only_does_not_set_block(self) -> None:
        """Report-only block policy must not mark block=True in effective access."""
        matrix = self.resolver.coverage_matrix(user_ids=["u-harry"], app_ids=["AllApps"])
        access = matrix[("u-harry", "AllApps")]
        assert access.block is False

    def test_frank_include_and_exclude_same_role_no_match(self) -> None:
        """p-phish includes AND excludes tid-ga → frank should not match it."""
        policies = self.resolver.effective_policies("u-frank", "AllApps")
        ids = [p.id for p in policies]
        assert "p-phish" not in ids


# ============================================================================
# PolicyGraph
# ============================================================================


class TestPolicyGraph:
    def setup_method(self) -> None:
        self.data = simple_tenant()
        self.graph = PolicyGraph.from_data(self.data)

    def test_graph_has_user_nodes(self) -> None:
        g = self.graph.nx
        assert g.nodes["u-alice"]["node_type"] == "user"
        assert g.nodes["u-bob"]["node_type"] == "user"

    def test_graph_has_group_nodes(self) -> None:
        g = self.graph.nx
        assert g.nodes["g-bg"]["node_type"] == "group"

    def test_graph_has_policy_nodes(self) -> None:
        g = self.graph.nx
        assert g.nodes["p-mfa"]["node_type"] == "policy"

    def test_graph_has_member_of_edge(self) -> None:
        g = self.graph.nx
        assert g.has_edge("u-bg", "g-bg")
        assert g.edges["u-bg", "g-bg"]["rel"] == "member_of"

    def test_graph_has_excludes_group_edge(self) -> None:
        g = self.graph.nx
        assert g.has_edge("p-mfa", "g-bg")
        assert g.edges["p-mfa", "g-bg"]["rel"] == "excludes_group"

    def test_graph_has_role_edge(self) -> None:
        g = self.graph.nx
        # alice has Global Admin role
        role_node = "tid-ga"
        assert g.has_edge("u-alice", role_node)
        assert g.edges["u-alice", role_node]["rel"] == "has_role"

    def test_disabled_policy_not_in_graph(self) -> None:
        from ca_radar.snapshot.models import PolicyState

        self.data.policies[0].state = PolicyState.disabled
        graph = PolicyGraph.from_data(self.data)
        assert "p-mfa" not in graph.nx.nodes
        self.data.policies[0].state = PolicyState.enabled

    def test_to_json_dict_structure(self) -> None:
        d = self.graph.to_json_dict()
        assert "nodes" in d
        assert "links" in d
        node_ids = {n["id"] for n in d["nodes"]}
        assert "u-alice" in node_ids
        assert "p-mfa" in node_ids

    def test_to_json_dict_links_have_rel(self) -> None:
        d = self.graph.to_json_dict()
        rels = {lnk["rel"] for lnk in d["links"]}
        assert "member_of" in rels
        assert "excludes_group" in rels

    def test_nested_groups_graph(self) -> None:
        data = nested_groups_tenant()
        graph = PolicyGraph.from_data(data)
        assert "g-all-staff" in graph.nx.nodes
        assert "g-backend" in graph.nx.nodes


# ============================================================================
# SnapshotData index building
# ============================================================================


class TestSnapshotDataIndexes:
    def test_users_by_id_populated(self) -> None:
        data = simple_tenant()
        assert "u-alice" in data.users_by_id
        assert data.users_by_id["u-alice"].user_principal_name == "alice@contoso.com"

    def test_user_role_index_populated(self) -> None:
        data = simple_tenant()
        assert "tid-ga" in data.user_role_index.get("u-alice", set())

    def test_user_group_index_populated(self) -> None:
        data = simple_tenant()
        assert "g-bg" in data.user_group_index.get("u-bg", set())

    def test_empty_snapshot_data_builds_cleanly(self) -> None:
        data = SnapshotData()
        data._build_indexes()
        assert data.users_by_id == {}
        assert data.user_role_index == {}
