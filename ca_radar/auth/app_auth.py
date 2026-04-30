"""App-registration authentication using MSAL confidential client.

Supports two credential types:
- Certificate (recommended): pass cert_path to a PEM file.
- Client secret (fallback):   pass client_secret directly.

The acquired token is cached in memory for the lifetime of the object.
For MSP scenarios, instantiate one AppAuthProvider per tenant.
"""

from __future__ import annotations

import logging
from pathlib import Path

import msal

log = logging.getLogger(__name__)

# Scopes required for a full ca-radar scan.
# These are application permissions — the admin consents once at app registration.
REQUIRED_SCOPES = ["https://graph.microsoft.com/.default"]

# Scopes mapped to the Graph resources they unlock.
# Used to generate friendly warnings when a scope is missing.
SCOPE_RESOURCE_MAP: dict[str, list[str]] = {
    "Policy.Read.All": [
        "conditional_access_policies",
        "named_locations",
        "authentication_strength_policies",
    ],
    "Directory.Read.All": ["users", "groups", "directory_roles", "role_assignments"],
    "Application.Read.All": ["service_principals", "applications"],
    "AuditLog.Read.All": ["sign_in_logs"],
    "RoleManagement.Read.Directory": ["pim_eligible_role_assignments"],
    "DeviceManagementConfiguration.Read.All": ["device_compliance_policies"],
    "IdentityRiskyUser.Read.All": ["risky_users"],
    "UserAuthenticationMethod.Read.All": ["authentication_methods_policy"],
}


class AppAuthProvider:
    """Acquires and caches app-only tokens via MSAL confidential client."""

    def __init__(
        self,
        tenant_id: str,
        client_id: str,
        cert_path: str | Path | None = None,
        client_secret: str | None = None,
        authority_base: str = "https://login.microsoftonline.com",
    ) -> None:
        if not cert_path and not client_secret:
            raise ValueError("Provide either cert_path or client_secret.")

        self.tenant_id = tenant_id
        self._authority = f"{authority_base}/{tenant_id}"

        if cert_path:
            pem = Path(cert_path).read_text(encoding="utf-8")
            self._app: msal.ConfidentialClientApplication = msal.ConfidentialClientApplication(
                client_id=client_id,
                authority=self._authority,
                client_credential={"private_key": pem},
            )
            log.debug("AppAuthProvider initialised with certificate for tenant %s", tenant_id)
        else:
            self._app = msal.ConfidentialClientApplication(
                client_id=client_id,
                authority=self._authority,
                client_credential=client_secret,
            )
            log.debug("AppAuthProvider initialised with client secret for tenant %s", tenant_id)

    def get_token(self) -> str:
        """Return a valid bearer token, acquiring a new one if necessary."""
        result = self._app.acquire_token_silent(REQUIRED_SCOPES, account=None)
        if not result:
            result = self._app.acquire_token_for_client(scopes=REQUIRED_SCOPES)

        if "access_token" not in result:
            error = result.get("error", "unknown")
            desc = result.get("error_description", "")
            raise AuthenticationError(
                f"Failed to acquire token for tenant {self.tenant_id}: {error} — {desc}"
            )

        log.debug(
            "Token acquired for tenant %s (expires_in=%s)", self.tenant_id, result.get("expires_in")
        )
        return str(result["access_token"])

    def get_auth_header(self) -> dict[str, str]:
        return {"Authorization": f"Bearer {self.get_token()}"}


class AuthenticationError(Exception):
    """Raised when token acquisition fails."""
