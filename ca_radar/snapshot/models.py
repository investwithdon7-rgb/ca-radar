"""Pydantic models for every Microsoft Graph resource captured in a snapshot.

All models use alias_generator so Graph's camelCase JSON maps to snake_case Python.
Every field is Optional where Graph may omit it, so partial responses don't crash.
"""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field
from pydantic.alias_generators import to_camel

# ---------------------------------------------------------------------------
# Base
# ---------------------------------------------------------------------------


class _Base(BaseModel):
    model_config = ConfigDict(
        alias_generator=to_camel,
        populate_by_name=True,
        extra="allow",
        str_strip_whitespace=True,
    )


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------


class PolicyState(StrEnum):
    enabled = "enabled"
    disabled = "disabled"
    enabledForReportingButNotEnforced = "enabledForReportingButNotEnforced"


class GrantControlOperator(StrEnum):
    AND = "AND"
    OR = "OR"


class SignInRiskLevel(StrEnum):
    low = "low"
    medium = "medium"
    high = "high"
    hidden = "hidden"
    none = "none"
    unknownFutureValue = "unknownFutureValue"


class UserRiskLevel(StrEnum):
    low = "low"
    medium = "medium"
    high = "high"
    hidden = "hidden"
    none = "none"
    unknownFutureValue = "unknownFutureValue"


# ---------------------------------------------------------------------------
# Conditional Access sub-models
# ---------------------------------------------------------------------------


class CaUserCondition(_Base):
    include_users: list[str] = Field(default_factory=list)
    exclude_users: list[str] = Field(default_factory=list)
    include_groups: list[str] = Field(default_factory=list)
    exclude_groups: list[str] = Field(default_factory=list)
    include_roles: list[str] = Field(default_factory=list)
    exclude_roles: list[str] = Field(default_factory=list)
    include_guests_or_external_users: dict[str, Any] | None = None


class CaApplicationCondition(_Base):
    include_applications: list[str] = Field(default_factory=list)
    exclude_applications: list[str] = Field(default_factory=list)
    include_user_actions: list[str] = Field(default_factory=list)
    include_authentication_context_class_references: list[dict[str, Any]] = Field(
        default_factory=list
    )
    application_filter: dict[str, Any] | None = None


class CaLocationCondition(_Base):
    include_locations: list[str] = Field(default_factory=list)
    exclude_locations: list[str] = Field(default_factory=list)


class CaConditions(_Base):
    users: CaUserCondition | None = None
    applications: CaApplicationCondition | None = None
    locations: CaLocationCondition | None = None
    devices: dict[str, Any] | None = None
    sign_in_risk_levels: list[SignInRiskLevel] = Field(default_factory=list)
    user_risk_levels: list[UserRiskLevel] = Field(default_factory=list)
    client_app_types: list[str] = Field(default_factory=list)
    platforms: dict[str, Any] | None = None
    client_applications: dict[str, Any] | None = None


class CaGrantControl(_Base):
    operator: GrantControlOperator | None = None
    built_in_controls: list[str] = Field(default_factory=list)
    custom_authentication_factors: list[str] = Field(default_factory=list)
    terms_of_use: list[str] = Field(default_factory=list)
    authentication_strength: dict[str, Any] | None = None


class CaSessionControl(_Base):
    application_enforced_restrictions: dict[str, Any] | None = None
    cloud_app_security: dict[str, Any] | None = None
    sign_in_frequency: dict[str, Any] | None = None
    persistent_browser: dict[str, Any] | None = None
    continuous_access_evaluation: dict[str, Any] | None = None
    disable_resilience_defaults: bool | None = None


class ConditionalAccessPolicy(_Base):
    id: str
    display_name: str
    description: str | None = None
    state: PolicyState
    conditions: CaConditions
    grant_controls: CaGrantControl | None = None
    session_controls: CaSessionControl | None = None
    created_date_time: datetime | None = None
    modified_date_time: datetime | None = None
    template_id: str | None = None


# ---------------------------------------------------------------------------
# Named Locations
# ---------------------------------------------------------------------------


class IpRange(_Base):
    cidr_address: str


class IpNamedLocation(_Base):
    id: str
    display_name: str
    is_trusted: bool = False
    ip_ranges: list[IpRange] = Field(default_factory=list)
    created_date_time: datetime | None = None
    modified_date_time: datetime | None = None


class CountryNamedLocation(_Base):
    id: str
    display_name: str
    countries_and_regions: list[str] = Field(default_factory=list)
    include_unknown_countries_and_regions: bool = False
    created_date_time: datetime | None = None
    modified_date_time: datetime | None = None


# ---------------------------------------------------------------------------
# Authentication Strength Policies
# ---------------------------------------------------------------------------


class AuthenticationStrengthPolicy(_Base):
    id: str
    display_name: str
    description: str | None = None
    policy_type: str | None = None
    requirement_satisfaction_choices: list[str] = Field(default_factory=list)
    allowed_combinations: list[list[str]] = Field(default_factory=list)
    created_date_time: datetime | None = None
    modified_date_time: datetime | None = None


# ---------------------------------------------------------------------------
# Authentication Methods Policy
# ---------------------------------------------------------------------------


class AuthenticationMethodConfig(_Base):
    id: str
    state: str | None = None
    include_targets: list[dict[str, Any]] = Field(default_factory=list)
    exclude_targets: list[dict[str, Any]] = Field(default_factory=list)


class AuthenticationMethodsPolicy(_Base):
    id: str | None = None
    display_name: str | None = None
    description: str | None = None
    policy_version: str | None = None
    registration_enforcement: dict[str, Any] | None = None
    authentication_method_configurations: list[AuthenticationMethodConfig] = Field(
        default_factory=list
    )
    last_modified_date_time: datetime | None = None


# ---------------------------------------------------------------------------
# Users
# ---------------------------------------------------------------------------


class SignInActivity(_Base):
    last_sign_in_date_time: datetime | None = None
    last_sign_in_request_id: str | None = None
    last_non_interactive_sign_in_date_time: datetime | None = None
    last_non_interactive_sign_in_request_id: str | None = None
    last_successful_sign_in_date_time: datetime | None = None


class User(_Base):
    id: str
    user_principal_name: str
    display_name: str | None = None
    account_enabled: bool | None = None
    user_type: str | None = None
    created_date_time: datetime | None = None
    sign_in_activity: SignInActivity | None = None
    assigned_roles: list[str] = Field(default_factory=list)
    is_break_glass: bool = False


# ---------------------------------------------------------------------------
# Groups
# ---------------------------------------------------------------------------


class Group(_Base):
    id: str
    display_name: str
    description: str | None = None
    group_types: list[str] = Field(default_factory=list)
    membership_rule: str | None = None
    membership_rule_processing_state: str | None = None
    security_enabled: bool | None = None
    mail_enabled: bool | None = None
    is_assignable_to_role: bool | None = None
    created_date_time: datetime | None = None
    transitive_member_ids: list[str] = Field(default_factory=list)
    member_ids: list[str] = Field(default_factory=list)


# ---------------------------------------------------------------------------
# Directory Roles & Role Assignments
# ---------------------------------------------------------------------------


class DirectoryRole(_Base):
    id: str
    display_name: str
    role_template_id: str | None = None
    description: str | None = None


class RoleAssignment(_Base):
    id: str
    principal_id: str
    role_definition_id: str
    directory_scope_id: str | None = None
    app_scope_id: str | None = None


class PimEligibleRoleAssignment(_Base):
    id: str
    principal_id: str
    role_definition_id: str
    start_date_time: datetime | None = None
    end_date_time: datetime | None = None
    assignment_type: str | None = None
    member_type: str | None = None
    status: str | None = None


# ---------------------------------------------------------------------------
# Service Principals & Applications
# ---------------------------------------------------------------------------


class AppRoleAssignment(_Base):
    id: str
    app_role_id: str
    principal_id: str
    principal_type: str | None = None
    resource_id: str | None = None
    resource_display_name: str | None = None
    created_date_time: datetime | None = None


class OAuth2PermissionGrant(_Base):
    id: str
    client_id: str
    consent_type: str | None = None
    principal_id: str | None = None
    resource_id: str | None = None
    scope: str | None = None


class ServicePrincipal(_Base):
    id: str
    display_name: str
    app_id: str | None = None
    service_principal_type: str | None = None
    account_enabled: bool | None = None
    sign_in_audience: str | None = None
    tags: list[str] = Field(default_factory=list)
    app_role_assignments: list[AppRoleAssignment] = Field(default_factory=list)
    oauth2_permission_grants: list[OAuth2PermissionGrant] = Field(default_factory=list)
    created_date_time: datetime | None = None


class Application(_Base):
    id: str
    app_id: str | None = None
    display_name: str
    sign_in_audience: str | None = None
    created_date_time: datetime | None = None
    required_resource_access: list[dict[str, Any]] = Field(default_factory=list)


# ---------------------------------------------------------------------------
# Device Compliance Policies
# ---------------------------------------------------------------------------


class CompliancePolicyAssignment(_Base):
    id: str
    target: dict[str, Any] | None = None


class DeviceCompliancePolicy(_Base):
    id: str
    display_name: str
    description: str | None = None
    created_date_time: datetime | None = None
    last_modified_date_time: datetime | None = None
    version: int | None = None
    assignments: list[CompliancePolicyAssignment] = Field(default_factory=list)


# ---------------------------------------------------------------------------
# Identity Protection
# ---------------------------------------------------------------------------


class RiskyUser(_Base):
    id: str
    user_principal_name: str | None = None
    user_display_name: str | None = None
    risk_state: str | None = None
    risk_level: UserRiskLevel | None = None
    risk_detail: str | None = None
    risk_last_updated_date_time: datetime | None = None
    is_deleted: bool | None = None
    is_processing: bool | None = None


class IdentityProtectionSummary(_Base):
    risky_users_count: int = 0
    high_risk_users_count: int = 0
    medium_risk_users_count: int = 0
    sign_in_risk_policy_state: str | None = None
    user_risk_policy_state: str | None = None


# ---------------------------------------------------------------------------
# Sign-in Logs (sampled)
# ---------------------------------------------------------------------------


class SignInLogEntry(_Base):
    id: str
    created_date_time: datetime | None = None
    user_id: str | None = None
    user_principal_name: str | None = None
    app_id: str | None = None
    app_display_name: str | None = None
    ip_address: str | None = None
    client_app_used: str | None = None
    conditional_access_status: str | None = None
    applied_conditional_access_policies: list[dict[str, Any]] = Field(default_factory=list)
    status: dict[str, Any] | None = None
    risk_level_during_sign_in: SignInRiskLevel | None = None
    risk_state: str | None = None
    is_interactive: bool | None = None


# ---------------------------------------------------------------------------
# Snapshot manifest
# ---------------------------------------------------------------------------

SNAPSHOT_SCHEMA_VERSION = "1"


class SnapshotManifest(_Base):
    schema_version: str = SNAPSHOT_SCHEMA_VERSION
    tenant_id: str
    captured_at: datetime
    tool_version: str
    redacted: bool = True
    redaction_salt_hint: str = ""
    resources_captured: list[str] = Field(default_factory=list)
    resources_failed: list[str] = Field(default_factory=list)
    scope_warnings: list[str] = Field(default_factory=list)
