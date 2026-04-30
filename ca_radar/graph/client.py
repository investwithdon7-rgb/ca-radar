"""Async Microsoft Graph client.

Features:
- Throttle-aware: honours Retry-After on 429 and 503, with exponential backoff cap.
- Pagination: transparently follows @odata.nextLink across all pages.
- Scope detection: catches 403 Forbidden and records the missing permission as a
  warning instead of raising, so the caller can mark dependent findings indeterminate.
- Structured request log: every request/response pair is recorded for audit.
- Read-only: only GET requests are issued; any attempt to call non-GET methods raises.
"""

from __future__ import annotations

import asyncio
import logging
import time
from typing import Any, Protocol, cast, runtime_checkable

import httpx

from ca_radar.graph.pagination import extract_next_link, extract_value

log = logging.getLogger(__name__)

GRAPH_BASE = "https://graph.microsoft.com/v1.0"
BETA_BASE = "https://graph.microsoft.com/beta"

# Throttle / backoff constants
_INITIAL_BACKOFF = 1.0  # seconds
_MAX_BACKOFF = 64.0  # seconds
_MAX_RETRIES = 6


@runtime_checkable
class AuthProvider(Protocol):
    """Minimal interface both AppAuthProvider and DelegatedAuthProvider satisfy."""

    def get_auth_header(self) -> dict[str, str]: ...


class ScopeNotGrantedError(Exception):
    """Raised (and caught internally) when Graph returns 403 for a resource."""

    def __init__(self, url: str, message: str) -> None:
        super().__init__(message)
        self.url = url


class GraphRequestError(Exception):
    """Raised for unrecoverable Graph errors (4xx other than 403, 5xx after retries)."""


class GraphClient:
    """Async, throttle-aware, paginating Microsoft Graph client.

    Accepts an optional ``http_client`` for testing (injected httpx.AsyncClient).
    In production a fresh client is created lazily on first use and reused.
    """

    def __init__(
        self,
        auth: AuthProvider,
        base_url: str = GRAPH_BASE,
        timeout: float = 30.0,
        http_client: httpx.AsyncClient | None = None,
    ) -> None:
        self._auth = auth
        self._base_url = base_url.rstrip("/")
        self._timeout = timeout
        self._scope_warnings: list[str] = []
        self._request_log: list[dict[str, Any]] = []
        self._http_client = http_client  # injected for tests
        self._owns_client = http_client is None

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def get(self, path: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
        """Issue a single GET request and return the parsed JSON body."""
        url = self._build_url(path)
        return await self._get_url(url, params=params)

    async def get_all(self, path: str, params: dict[str, Any] | None = None) -> list[Any]:
        """Fetch all pages for a collection endpoint and return a flat list."""
        url: str | None = self._build_url(path)
        items: list[Any] = []

        while url:
            try:
                body = await self._get_url(url, params=params)
            except ScopeNotGrantedError as exc:
                warning = (
                    f"Scope not granted for {exc.url} — dependent findings will be indeterminate"
                )
                log.warning(warning)
                self._scope_warnings.append(warning)
                return []

            items.extend(extract_value(body))
            url = extract_next_link(body)
            params = None  # nextLink already contains query params

        return items

    async def get_single(
        self, path: str, params: dict[str, Any] | None = None
    ) -> dict[str, Any] | None:
        """Fetch a single resource, returning None if scope was not granted."""
        try:
            return await self.get(path, params=params)
        except ScopeNotGrantedError as exc:
            warning = f"Scope not granted for {exc.url} — dependent findings will be indeterminate"
            log.warning(warning)
            self._scope_warnings.append(warning)
            return None

    @property
    def scope_warnings(self) -> list[str]:
        return list(self._scope_warnings)

    @property
    def request_log(self) -> list[dict[str, Any]]:
        return list(self._request_log)

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _build_url(self, path: str) -> str:
        if path.startswith("https://"):
            return path
        return f"{self._base_url}/{path.lstrip('/')}"

    def _session(self) -> httpx.AsyncClient:
        """Return the shared http session, creating it on first use."""
        if self._http_client is None:
            self._http_client = httpx.AsyncClient(timeout=self._timeout)
        return self._http_client

    async def aclose(self) -> None:
        """Close the underlying HTTP session if we own it."""
        if self._owns_client and self._http_client is not None:
            await self._http_client.aclose()

    async def __aenter__(self) -> GraphClient:
        return self

    async def __aexit__(self, *_: object) -> None:
        await self.aclose()

    async def _get_url(
        self,
        url: str,
        params: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        backoff = _INITIAL_BACKOFF
        attempt = 0
        session = self._session()

        while attempt <= _MAX_RETRIES:
            headers = self._auth.get_auth_header()
            headers["Accept"] = "application/json"
            headers["ConsistencyLevel"] = "eventual"

            start = time.monotonic()
            try:
                response = await session.get(url, headers=headers, params=params)
            except httpx.TransportError as exc:
                log.warning("Transport error on %s (attempt %d): %s", url, attempt, exc)
                await self._sleep_backoff(backoff)
                backoff = min(backoff * 2, _MAX_BACKOFF)
                attempt += 1
                continue
            finally:
                elapsed = time.monotonic() - start

            self._log_request(url, response.status_code, elapsed)

            if response.status_code == 200:
                return cast(dict[str, Any], response.json())

            if response.status_code == 403:
                body = _safe_json(response)
                msg = _extract_error_message(body)
                raise ScopeNotGrantedError(url, f"403 Forbidden on {url}: {msg}")

            if response.status_code in (429, 503):
                retry_after = _parse_retry_after(response, backoff)
                log.warning(
                    "Throttled (%d) on %s — waiting %.1fs (attempt %d/%d)",
                    response.status_code,
                    url,
                    retry_after,
                    attempt,
                    _MAX_RETRIES,
                )
                await self._sleep_backoff(retry_after)
                backoff = min(backoff * 2, _MAX_BACKOFF)
                attempt += 1
                continue

            if response.status_code >= 500:
                log.warning(
                    "Server error %d on %s (attempt %d/%d)",
                    response.status_code,
                    url,
                    attempt,
                    _MAX_RETRIES,
                )
                await self._sleep_backoff(backoff)
                backoff = min(backoff * 2, _MAX_BACKOFF)
                attempt += 1
                continue

            # 4xx other than 403/429 — not retryable
            body = _safe_json(response)
            raise GraphRequestError(
                f"HTTP {response.status_code} on {url}: {_extract_error_message(body)}"
            )

        raise GraphRequestError(f"Exceeded {_MAX_RETRIES} retries for {url}")

    def _log_request(self, url: str, status: int, elapsed: float) -> None:
        self._request_log.append({"url": url, "status": status, "elapsed_s": round(elapsed, 3)})

    @staticmethod
    async def _sleep_backoff(seconds: float) -> None:
        await asyncio.sleep(seconds)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _parse_retry_after(response: httpx.Response, default: float) -> float:
    header = response.headers.get("Retry-After")
    if header:
        try:
            return float(header)
        except ValueError:
            pass
    return default


def _safe_json(response: httpx.Response) -> dict[str, Any]:
    try:
        return response.json()  # type: ignore[no-any-return]
    except Exception:
        return {}


def _extract_error_message(body: dict[str, Any]) -> str:
    error = body.get("error", {})
    if isinstance(error, dict):
        return str(error.get("message", body))
    return str(body)
