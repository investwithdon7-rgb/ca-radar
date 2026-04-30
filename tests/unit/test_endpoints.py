"""Tests for typed endpoint wrappers using respx global mock."""

from __future__ import annotations

import httpx
import pytest
import respx

from ca_radar.graph.client import GRAPH_BASE, GraphClient
from ca_radar.graph.endpoints import (
    get_authentication_methods_policy,
    get_ca_policies,
    get_directory_roles,
    get_groups,
    get_risky_users,
    get_users,
)
from ca_radar.snapshot.models import PolicyState


class FakeAuth:
    def get_auth_header(self) -> dict[str, str]:
        return {"Authorization": "Bearer fake-token"}


def make_client() -> GraphClient:
    return GraphClient(auth=FakeAuth(), base_url=GRAPH_BASE)


def _policy_raw() -> dict:
    return {
        "id": "policy-001",
        "displayName": "Require MFA",
        "state": "enabled",
        "conditions": {
            "users": {
                "includeUsers": ["All"],
                "excludeUsers": [],
                "includeGroups": [],
                "excludeGroups": [],
                "includeRoles": [],
                "excludeRoles": [],
            },
            "applications": {
                "includeApplications": ["All"],
                "excludeApplications": [],
                "includeUserActions": [],
                "includeAuthenticationContextClassReferences": [],
            },
        },
        "grantControls": {
            "operator": "OR",
            "builtInControls": ["mfa"],
            "customAuthenticationFactors": [],
            "termsOfUse": [],
        },
    }


@pytest.mark.asyncio
async def test_get_ca_policies() -> None:
    with respx.mock:
        respx.get(f"{GRAPH_BASE}/identity/conditionalAccess/policies").mock(
            return_value=httpx.Response(200, json={"value": [_policy_raw()]})
        )
        client = make_client()
        policies = await get_ca_policies(client)
        await client.aclose()

    assert len(policies) == 1
    assert policies[0].id == "policy-001"
    assert policies[0].state == PolicyState.enabled


@pytest.mark.asyncio
async def test_get_users_returns_typed_models() -> None:
    with respx.mock:
        respx.get(f"{GRAPH_BASE}/users").mock(
            return_value=httpx.Response(
                200,
                json={
                    "value": [
                        {
                            "id": "u1",
                            "userPrincipalName": "alice@contoso.com",
                            "displayName": "Alice",
                            "accountEnabled": True,
                            "userType": "Member",
                        }
                    ]
                },
            )
        )
        client = make_client()
        users = await get_users(client)
        await client.aclose()

    assert len(users) == 1
    assert users[0].user_principal_name == "alice@contoso.com"


@pytest.mark.asyncio
async def test_get_groups() -> None:
    with respx.mock:
        respx.get(f"{GRAPH_BASE}/groups").mock(
            return_value=httpx.Response(
                200,
                json={
                    "value": [
                        {
                            "id": "g1",
                            "displayName": "Admins",
                            "groupTypes": [],
                            "securityEnabled": True,
                            "mailEnabled": False,
                        }
                    ]
                },
            )
        )
        client = make_client()
        groups = await get_groups(client)
        await client.aclose()

    assert groups[0].id == "g1"
    assert groups[0].display_name == "Admins"


@pytest.mark.asyncio
async def test_get_directory_roles() -> None:
    with respx.mock:
        respx.get(f"{GRAPH_BASE}/directoryRoles").mock(
            return_value=httpx.Response(
                200,
                json={
                    "value": [
                        {
                            "id": "r1",
                            "displayName": "Global Administrator",
                            "roleTemplateId": "62e90394-69f5-4237-9190-012177145e10",
                        }
                    ]
                },
            )
        )
        client = make_client()
        roles = await get_directory_roles(client)
        await client.aclose()

    assert roles[0].display_name == "Global Administrator"


@pytest.mark.asyncio
async def test_get_risky_users_empty_on_scope_denied() -> None:
    with respx.mock:
        respx.get(f"{GRAPH_BASE}/identityProtection/riskyUsers").mock(
            return_value=httpx.Response(403, json={"error": {"message": "denied"}})
        )
        client = make_client()
        risky = await get_risky_users(client)
        await client.aclose()

    assert risky == []
    assert len(client.scope_warnings) == 1


@pytest.mark.asyncio
async def test_get_authentication_methods_policy_none_on_403() -> None:
    with respx.mock:
        respx.get(f"{GRAPH_BASE}/policies/authenticationMethodsPolicy").mock(
            return_value=httpx.Response(403, json={"error": {"message": "denied"}})
        )
        client = make_client()
        result = await get_authentication_methods_policy(client)
        await client.aclose()

    assert result is None


@pytest.mark.asyncio
async def test_malformed_items_skipped_gracefully() -> None:
    with respx.mock:
        respx.get(f"{GRAPH_BASE}/identity/conditionalAccess/policies").mock(
            return_value=httpx.Response(
                200,
                json={
                    "value": [
                        _policy_raw(),
                        {"broken": "no id or state here"},
                    ]
                },
            )
        )
        client = make_client()
        policies = await get_ca_policies(client)
        await client.aclose()

    assert len(policies) == 1
