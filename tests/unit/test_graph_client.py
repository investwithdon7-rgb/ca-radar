"""Tests for GraphClient using respx global mock — no live tenant required."""

from __future__ import annotations

import httpx
import pytest
import respx

from ca_radar.graph.client import (
    GRAPH_BASE,
    GraphClient,
    GraphRequestError,
)


class FakeAuth:
    def get_auth_header(self) -> dict[str, str]:
        return {"Authorization": "Bearer fake-token"}


def make_client() -> GraphClient:
    """Create a client with a fresh httpx.AsyncClient (created inside respx.mock context)."""
    return GraphClient(auth=FakeAuth(), base_url=GRAPH_BASE)


# ---------------------------------------------------------------------------
# Basic GET
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_get_single_page() -> None:
    with respx.mock:
        respx.get(f"{GRAPH_BASE}/identity/conditionalAccess/policies").mock(
            return_value=httpx.Response(200, json={"value": [{"id": "p1"}]})
        )
        client = make_client()
        body = await client.get("identity/conditionalAccess/policies")
        await client.aclose()
    assert body["value"][0]["id"] == "p1"


# ---------------------------------------------------------------------------
# Pagination
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_get_all_follows_next_link() -> None:
    """Pagination logic tested by mocking _get_url directly (avoids Windows asyncio + respx multi-request hang)."""
    page2_url = f"{GRAPH_BASE}/users?skiptoken=page2token"
    responses = [
        {"value": [{"id": "u1"}], "@odata.nextLink": page2_url},
        {"value": [{"id": "u2"}]},
    ]
    call_idx = 0

    async def mock_get_url(url: str, params: object = None) -> dict:
        nonlocal call_idx
        result = responses[call_idx]
        call_idx += 1
        return result

    client = make_client()
    client._get_url = mock_get_url  # type: ignore[method-assign]
    items = await client.get_all("users")

    assert len(items) == 2
    assert items[0]["id"] == "u1"
    assert items[1]["id"] == "u2"
    assert call_idx == 2


# ---------------------------------------------------------------------------
# Scope not granted (403)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_get_all_returns_empty_on_403() -> None:
    with respx.mock:
        respx.get(f"{GRAPH_BASE}/auditLogs/signIns").mock(
            return_value=httpx.Response(
                403,
                json={
                    "error": {
                        "code": "Authorization_RequestDenied",
                        "message": "Insufficient privileges",
                    }
                },
            )
        )
        client = make_client()
        items = await client.get_all("auditLogs/signIns")
        await client.aclose()

    assert items == []
    assert len(client.scope_warnings) == 1


@pytest.mark.asyncio
async def test_get_single_returns_none_on_403() -> None:
    with respx.mock:
        respx.get(f"{GRAPH_BASE}/policies/authenticationMethodsPolicy").mock(
            return_value=httpx.Response(403, json={"error": {"message": "denied"}})
        )
        client = make_client()
        result = await client.get_single("policies/authenticationMethodsPolicy")
        await client.aclose()

    assert result is None
    assert len(client.scope_warnings) == 1


# ---------------------------------------------------------------------------
# Throttling (429) with Retry-After
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_retries_on_429(monkeypatch: pytest.MonkeyPatch) -> None:
    slept: list[float] = []

    async def fake_sleep(s: float) -> None:
        slept.append(s)

    monkeypatch.setattr("ca_radar.graph.client.asyncio.sleep", fake_sleep)

    with respx.mock:
        route = respx.get(f"{GRAPH_BASE}/groups")
        route.side_effect = [
            httpx.Response(429, headers={"Retry-After": "1"}, json={}),
            httpx.Response(200, json={"value": [{"id": "g1"}]}),
        ]
        client = make_client()
        items = await client.get_all("groups")
        await client.aclose()

    assert len(items) == 1
    assert len(slept) == 1


# ---------------------------------------------------------------------------
# Non-retryable 4xx
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_raises_on_404() -> None:
    with respx.mock:
        respx.get(f"{GRAPH_BASE}/nonexistent").mock(
            return_value=httpx.Response(404, json={"error": {"message": "Not found"}})
        )
        client = make_client()
        with pytest.raises(GraphRequestError, match="404"):
            await client.get("nonexistent")
        await client.aclose()


# ---------------------------------------------------------------------------
# Request log
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_request_log_populated() -> None:
    with respx.mock:
        respx.get(f"{GRAPH_BASE}/directoryRoles").mock(
            return_value=httpx.Response(200, json={"value": []})
        )
        client = make_client()
        await client.get_all("directoryRoles")
        await client.aclose()

    assert len(client.request_log) == 1
    assert client.request_log[0]["status"] == 200
    assert "directoryRoles" in client.request_log[0]["url"]


# ---------------------------------------------------------------------------
# Absolute URL passthrough
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_absolute_url_passthrough() -> None:
    absolute = f"{GRAPH_BASE}/users?skiptoken=xyz"
    with respx.mock:
        respx.get(absolute).mock(return_value=httpx.Response(200, json={"value": [{"id": "u3"}]}))
        client = make_client()
        body = await client.get(absolute)
        await client.aclose()

    assert body["value"][0]["id"] == "u3"
