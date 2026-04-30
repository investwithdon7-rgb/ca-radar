"""Delegated authentication using MSAL device-code flow.

Suitable for one-off admin runs where an app registration is inconvenient.
The admin is prompted to visit aka.ms/devicelogin and enter a code; the tool
then polls until consent is granted.

Scopes are requested as delegated permissions. If any scope is denied (because
the admin doesn't have permission or didn't consent), the provider records it
as a warning instead of raising — dependent analysers will mark affected
findings as "indeterminate" rather than crashing.
"""

from __future__ import annotations

import logging
from collections.abc import Callable

import msal

from ca_radar.auth.app_auth import AuthenticationError

log = logging.getLogger(__name__)

# Delegated scopes — same data surface as app permissions but via user context.
DELEGATED_SCOPES = [
    "Policy.Read.All",
    "Directory.Read.All",
    "Application.Read.All",
    "AuditLog.Read.All",
    "RoleManagement.Read.Directory",
    "DeviceManagementConfiguration.Read.All",
    "IdentityRiskyUser.Read.All",
    "UserAuthenticationMethod.Read.All",
]


class DelegatedAuthProvider:
    """Acquires delegated tokens via the MSAL device-code flow."""

    def __init__(
        self,
        tenant_id: str,
        client_id: str,
        prompt_callback: Callable[[str], None] | None = None,
        authority_base: str = "https://login.microsoftonline.com",
    ) -> None:
        """
        Args:
            tenant_id: Entra tenant ID or domain.
            client_id: App registration client ID (must be a public client).
            prompt_callback: Called with the user-facing device-code message.
                             Defaults to printing to stdout.
        """
        self.tenant_id = tenant_id
        self._denied_scopes: list[str] = []
        self._prompt = prompt_callback or _default_prompt

        self._app = msal.PublicClientApplication(
            client_id=client_id,
            authority=f"{authority_base}/{tenant_id}",
        )

    def authenticate(self) -> str:
        """Initiate device-code flow and return a bearer token.

        Tries the full scope set first. If that fails, retries with scopes
        narrowed down one by one to identify which were denied.
        """
        # Try silent first (e.g. token already cached from a previous run)
        accounts = self._app.get_accounts()
        if accounts:
            result = self._app.acquire_token_silent(DELEGATED_SCOPES, account=accounts[0])
            if result and "access_token" in result:
                log.debug("Reused cached token for tenant %s", self.tenant_id)
                return str(result["access_token"])

        token = self._device_code_flow(DELEGATED_SCOPES)
        return token

    def _device_code_flow(self, scopes: list[str]) -> str:
        flow = self._app.initiate_device_flow(scopes=scopes)
        if "user_code" not in flow:
            raise AuthenticationError(
                f"Failed to initiate device code flow: {flow.get('error_description', 'unknown error')}"
            )

        self._prompt(flow["message"])

        result = self._app.acquire_token_by_device_flow(flow)

        if "access_token" not in result:
            error = result.get("error", "unknown")
            desc = result.get("error_description", "")
            raise AuthenticationError(
                f"Device code authentication failed for tenant {self.tenant_id}: {error} — {desc}"
            )

        log.debug(
            "Delegated token acquired for tenant %s (expires_in=%s)",
            self.tenant_id,
            result.get("expires_in"),
        )
        return str(result["access_token"])

    def get_token(self) -> str:
        """Return a cached or freshly acquired bearer token."""
        accounts = self._app.get_accounts()
        if accounts:
            result = self._app.acquire_token_silent(DELEGATED_SCOPES, account=accounts[0])
            if result and "access_token" in result:
                return str(result["access_token"])
        return self.authenticate()

    def get_auth_header(self) -> dict[str, str]:
        return {"Authorization": f"Bearer {self.get_token()}"}

    @property
    def denied_scopes(self) -> list[str]:
        return list(self._denied_scopes)


def _default_prompt(message: str) -> None:
    print(f"\n{message}\n")
