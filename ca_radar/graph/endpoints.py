"""Typed endpoint wrappers for every Graph resource in a ca-radar snapshot.

Each function takes a GraphClient and returns parsed Pydantic model instances.
All calls go through the client's pagination and scope-detection logic.

Lightweight user projections are used where Graph returns large objects by default,
to stay within reasonable rate-limit budgets on large tenants.
"""

from __future__ import annotations

import logging
from typing import Any

from ca_radar.graph.client import GraphClient
from ca_radar.snapshot.models import (
    Application,
    AuthenticationMethodsPolicy,
    AuthenticationStrengthPolicy,
    ConditionalAccessPolicy,
    DeviceCompliancePolicy,
    DirectoryRole,
    Group,
    IdentityProtectionSummary,
    IpNamedLocation,
    PimEligibleRoleAssignment,
    RiskyUser,
    RoleAssignment,
    ServicePrincipal,
    SignInLogEntry,
    User,
    UserRiskLevel,
)

log = logging.getLogger(__name__)

# Lightweight $select for users — avoids pulling every attribute on large tenants
_USER_SELECT = (
    "id,userPrincipalName,displayName,accountEnabled,userType,createdDateTime,signInActivity"
)

_GROUP_SELECT = (
    "id,displayName,description,groupTypes,membershipRule,"
    "membershipRuleProcessingState,securityEnabled,mailEnabled,"
    "isAssignableToRole,createdDateTime"
)


# ---------------------------------------------------------------------------
# Conditional Access
# ---------------------------------------------------------------------------


async def get_ca_policies(client: GraphClient) -> list[ConditionalAccessPolicy]:
    items = await client.get_all("identity/conditionalAccess/policies")
    return _parse_list(items, ConditionalAccessPolicy, "conditionalAccessPolicies")


async def get_named_locations(client: GraphClient) -> list[IpNamedLocation]:
    items = await client.get_all("identity/conditionalAccess/namedLocations")
    # Return raw dicts so store can handle both IP and country location types
    return items  # raw dicts; store handles both IP and country subtypes


async def get_authentication_strength_policies(
    client: GraphClient,
) -> list[AuthenticationStrengthPolicy]:
    items = await client.get_all("identity/conditionalAccess/authenticationStrength/policies")
    return _parse_list(items, AuthenticationStrengthPolicy, "authenticationStrengthPolicies")


# ---------------------------------------------------------------------------
# Authentication Methods
# ---------------------------------------------------------------------------


async def get_authentication_methods_policy(
    client: GraphClient,
) -> AuthenticationMethodsPolicy | None:
    data = await client.get_single("policies/authenticationMethodsPolicy")
    if data is None:
        return None
    return AuthenticationMethodsPolicy.model_validate(data)


# ---------------------------------------------------------------------------
# Users, Groups, Roles
# ---------------------------------------------------------------------------


async def get_users(client: GraphClient) -> list[User]:
    items = await client.get_all("users", params={"$select": _USER_SELECT})
    return _parse_list(items, User, "users")


async def get_groups(client: GraphClient) -> list[Group]:
    items = await client.get_all("groups", params={"$select": _GROUP_SELECT})
    return _parse_list(items, Group, "groups")


async def get_group_transitive_members(client: GraphClient, group_id: str) -> list[str]:
    """Return object IDs of all transitive members of a group."""
    items = await client.get_all(
        f"groups/{group_id}/transitiveMembers",
        params={"$select": "id"},
    )
    return [i["id"] for i in items if "id" in i]


async def get_directory_roles(client: GraphClient) -> list[DirectoryRole]:
    items = await client.get_all("directoryRoles")
    return _parse_list(items, DirectoryRole, "directoryRoles")


async def get_role_assignments(client: GraphClient) -> list[RoleAssignment]:
    items = await client.get_all(
        "roleManagement/directory/roleAssignments",
        params={"$expand": "principal"},
    )
    return _parse_list(items, RoleAssignment, "roleAssignments")


async def get_pim_eligible_assignments(
    client: GraphClient,
) -> list[PimEligibleRoleAssignment]:
    items = await client.get_all(
        "roleManagement/directory/roleEligibilitySchedules",
        params={"$expand": "principal,roleDefinition"},
    )
    return _parse_list(items, PimEligibleRoleAssignment, "pimEligibleRoleAssignments")


# ---------------------------------------------------------------------------
# Service Principals & Applications
# ---------------------------------------------------------------------------


async def get_service_principals(client: GraphClient) -> list[ServicePrincipal]:
    items = await client.get_all(
        "servicePrincipals",
        params={
            "$select": "id,displayName,appId,servicePrincipalType,accountEnabled,signInAudience,tags,createdDateTime",
            "$expand": "appRoleAssignments",
        },
    )
    return _parse_list(items, ServicePrincipal, "servicePrincipals")


async def get_oauth2_permission_grants(client: GraphClient) -> list[dict[str, Any]]:
    return await client.get_all("oauth2PermissionGrants")


async def get_applications(client: GraphClient) -> list[Application]:
    items = await client.get_all(
        "applications",
        params={
            "$select": "id,appId,displayName,signInAudience,createdDateTime,requiredResourceAccess"
        },
    )
    return _parse_list(items, Application, "applications")


# ---------------------------------------------------------------------------
# Device Compliance
# ---------------------------------------------------------------------------


async def get_device_compliance_policies(
    client: GraphClient,
) -> list[DeviceCompliancePolicy]:
    items = await client.get_all(
        "deviceManagement/deviceCompliancePolicies",
        params={"$expand": "assignments"},
    )
    return _parse_list(items, DeviceCompliancePolicy, "deviceCompliancePolicies")


# ---------------------------------------------------------------------------
# Identity Protection
# ---------------------------------------------------------------------------


async def get_risky_users(client: GraphClient) -> list[RiskyUser]:
    items = await client.get_all(
        "identityProtection/riskyUsers",
        params={
            "$select": "id,userPrincipalName,userDisplayName,riskState,riskLevel,riskDetail,riskLastUpdatedDateTime,isDeleted,isProcessing"
        },
    )
    return _parse_list(items, RiskyUser, "riskyUsers")


async def get_identity_protection_summary(
    client: GraphClient,
) -> IdentityProtectionSummary:
    """Build a lightweight summary from risky-user counts and policy states."""
    risky = await client.get_all(
        "identityProtection/riskyUsers",
        params={"$select": "id,riskLevel"},
    )
    high = sum(1 for u in risky if u.get("riskLevel") == UserRiskLevel.high)
    medium = sum(1 for u in risky if u.get("riskLevel") == UserRiskLevel.medium)
    return IdentityProtectionSummary(
        risky_users_count=len(risky),
        high_risk_users_count=high,
        medium_risk_users_count=medium,
    )


# ---------------------------------------------------------------------------
# Sign-in Logs (sampled — last 30 days, non-interactive excluded by default)
# ---------------------------------------------------------------------------


async def get_sign_in_logs(
    client: GraphClient,
    days: int = 30,
    max_records: int = 5000,
) -> list[SignInLogEntry]:
    from datetime import UTC, datetime, timedelta

    since = (datetime.now(UTC) - timedelta(days=days)).strftime("%Y-%m-%dT%H:%M:%SZ")
    items = await client.get_all(
        "auditLogs/signIns",
        params={
            "$filter": f"createdDateTime ge {since}",
            "$select": (
                "id,createdDateTime,userId,userPrincipalName,appId,appDisplayName,"
                "ipAddress,clientAppUsed,conditionalAccessStatus,"
                "appliedConditionalAccessPolicies,status,"
                "riskLevelDuringSignIn,riskState,isInteractive"
            ),
            "$top": str(min(max_records, 999)),
        },
    )
    return _parse_list(items[:max_records], SignInLogEntry, "signInLogs")


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _parse_list(
    items: list[Any],
    model: Any,
    resource_name: str,
) -> list[Any]:
    results = []
    errors = 0
    for item in items:
        try:
            results.append(model.model_validate(item))
        except Exception as exc:
            errors += 1
            log.debug("Failed to parse %s item: %s", resource_name, exc)
    if errors:
        log.warning("%d %s items failed to parse and were skipped", errors, resource_name)
    return results
