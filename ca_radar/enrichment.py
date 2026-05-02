"""Post-analysis enrichment for owners, exceptions, and priority scoring."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import date
from pathlib import Path
from typing import Any

import yaml

from ca_radar.analysers.base import Finding, Severity


@dataclass
class OwnerConfig:
    principals: dict[str, str] = field(default_factory=dict)
    findings: dict[str, str] = field(default_factory=dict)
    default: str = "Unassigned"


@dataclass
class ExceptionRule:
    finding_id: str
    principal: str = ""
    status: str = "accepted_risk"
    reason: str = ""
    owner: str = ""
    approved_by: str = ""
    expires: str = ""


@dataclass
class EnrichmentConfig:
    owners: OwnerConfig = field(default_factory=OwnerConfig)
    exceptions: list[ExceptionRule] = field(default_factory=list)


def load_enrichment_inputs(owners_path: str = "", exceptions_path: str = "") -> EnrichmentConfig:
    """Load optional owner and exception YAML files."""
    return EnrichmentConfig(
        owners=_load_owner_config(owners_path) if owners_path else OwnerConfig(),
        exceptions=_load_exception_rules(exceptions_path) if exceptions_path else [],
    )


def enrich_findings(
    findings: list[Finding],
    *,
    config: EnrichmentConfig | None = None,
    owner_map: dict[str, Any] | None = None,
    exception_items: list[dict[str, Any]] | None = None,
    today: date | None = None,
) -> list[Finding]:
    """Attach owner, exception, and priority metadata to each finding."""
    active_config = config or EnrichmentConfig(
        owners=_normalise_owner_config(owner_map or {}),
        exceptions=_normalise_exception_rules(exception_items or []),
    )
    as_of = today or date.today()

    for finding in findings:
        finding.owner = _resolve_owner(finding, active_config.owners)
        finding.exception = _resolve_exception(finding, active_config.exceptions, as_of)
        finding.priority = _score_priority(finding)

    return findings


def _load_yaml(path: str) -> Any:
    raw = Path(path).read_text(encoding="utf-8")
    return yaml.safe_load(raw) or {}


def _load_owner_config(path: str) -> OwnerConfig:
    raw = _load_yaml(path)
    return _normalise_owner_config(raw.get("owners", raw) if isinstance(raw, dict) else {})


def _load_exception_rules(path: str) -> list[ExceptionRule]:
    raw = _load_yaml(path)
    items = raw.get("exceptions", []) if isinstance(raw, dict) else raw
    return _normalise_exception_rules(items if isinstance(items, list) else [])


def _normalise_owner_config(raw: dict[str, Any]) -> OwnerConfig:
    principals = raw.get("principals", {}) if isinstance(raw, dict) else {}
    findings = raw.get("findings", {}) if isinstance(raw, dict) else {}
    default = raw.get("default", "Unassigned") if isinstance(raw, dict) else "Unassigned"
    return OwnerConfig(
        principals=_string_map(principals),
        findings=_string_map(findings),
        default=str(default or "Unassigned"),
    )


def _normalise_exception_rules(items: list[dict[str, Any]]) -> list[ExceptionRule]:
    rules: list[ExceptionRule] = []
    for item in items:
        if not isinstance(item, dict) or not item.get("finding_id"):
            continue
        rules.append(
            ExceptionRule(
                finding_id=str(item.get("finding_id", "")),
                principal=str(item.get("principal", "")),
                status=str(item.get("status", "accepted_risk")),
                reason=str(item.get("reason", "")),
                owner=str(item.get("owner", "")),
                approved_by=str(item.get("approved_by", "")),
                expires=str(item.get("expires", "")),
            )
        )
    return rules


def _string_map(raw: Any) -> dict[str, str]:
    if not isinstance(raw, dict):
        return {}
    result: dict[str, str] = {}
    for key, value in raw.items():
        if isinstance(value, dict):
            value = value.get("name", "")
        if key and value:
            result[str(key)] = str(value)
    return result


def _resolve_owner(finding: Finding, owners: OwnerConfig) -> dict[str, Any]:
    matched = []
    for principal in finding.affected_principals:
        owner = owners.principals.get(principal)
        if owner:
            matched.append(owner)

    if matched:
        return {
            "names": sorted(set(matched)),
            "source": "principal",
            "matched": True,
        }

    owner = owners.findings.get(finding.id)
    if owner:
        return {"names": [owner], "source": "finding", "matched": True}

    if owners.default:
        return {"names": [owners.default], "source": "default", "matched": False}

    return {"names": ["Unassigned"], "source": "unknown", "matched": False}


def _resolve_exception(finding: Finding, rules: list[ExceptionRule], as_of: date) -> dict[str, Any]:
    matches = [
        rule
        for rule in rules
        if rule.finding_id == finding.id and _principal_matches(rule.principal, finding)
    ]
    if not matches:
        return {
            "status": "none",
            "active": False,
            "expired": False,
            "reason": "",
            "owner": "",
            "approved_by": "",
            "expires": "",
        }

    active = [rule for rule in matches if not _is_expired(rule.expires, as_of)]
    rule = active[0] if active else matches[0]
    expired = _is_expired(rule.expires, as_of)
    return {
        "status": "expired" if expired else rule.status,
        "original_status": rule.status,
        "active": not expired,
        "expired": expired,
        "reason": rule.reason,
        "owner": rule.owner,
        "approved_by": rule.approved_by,
        "expires": rule.expires,
        "principal": rule.principal,
    }


def _principal_matches(principal: str, finding: Finding) -> bool:
    return not principal or principal == "*" or principal in finding.affected_principals


def _is_expired(expires: str, as_of: date) -> bool:
    if not expires:
        return False
    try:
        return date.fromisoformat(expires) < as_of
    except ValueError:
        return False


def _score_priority(finding: Finding) -> dict[str, Any]:
    factors: list[str] = []
    score = {
        Severity.critical: 78,
        Severity.high: 60,
        Severity.medium: 40,
        Severity.low: 20,
        Severity.info: 5,
    }[finding.severity]
    factors.append(f"{finding.severity.value} severity")

    affected_count = len(finding.affected_principals)
    if affected_count:
        score += min(affected_count * 2, 10)
        factors.append(f"{affected_count} affected principal{'s' if affected_count != 1 else ''}")

    if finding.confidence < 1:
        score = int(score * finding.confidence)
        factors.append(f"{finding.confidence:.0%} confidence")

    if finding.id.startswith("CA-SP-"):
        score += 10
        factors.append("service principal impact")
    if finding.id.startswith("CA-ADMIN-"):
        score += 10
        factors.append("admin impact")
    if finding.id.startswith("CA-BG-"):
        score += 5
        factors.append("break-glass impact")
    if _contains_guest_signal(finding):
        score += 8
        factors.append("guest impact")

    exception = finding.exception or {}
    if exception.get("expired"):
        score += 15
        factors.append("expired exception")
    elif exception.get("active"):
        score -= 30
        factors.append("active exception")
    else:
        factors.append("no active exception")

    final_score = max(0, min(100, score))
    return {
        "score": final_score,
        "band": _priority_band(final_score),
        "factors": factors,
    }


def _contains_guest_signal(finding: Finding) -> bool:
    haystack = f"{finding.id} {finding.title} {finding.summary} {finding.evidence}".lower()
    return "guest" in haystack or "#ext#" in haystack


def _priority_band(score: int) -> str:
    if score >= 80:
        return "urgent"
    if score >= 60:
        return "high"
    if score >= 35:
        return "medium"
    return "low"
