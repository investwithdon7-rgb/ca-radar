"""Tests for release assets — docs structure, mkdocs config, Dockerfile, CHANGELOG.

These tests do not run application code; they verify that all required files
exist and are structurally valid. This catches regressions where docs pages
are accidentally deleted or renamed.
"""

from __future__ import annotations

import tomllib
from pathlib import Path

import pytest
import yaml

# Root of the repository (two levels up from this test file)
REPO_ROOT = Path(__file__).parent.parent.parent


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _exists(rel: str) -> Path:
    p = REPO_ROOT / rel
    assert p.exists(), f"Expected file/dir not found: {rel}"
    return p


# ===========================================================================
# mkdocs.yml
# ===========================================================================


class TestMkdocsYml:
    def test_file_exists(self):
        _exists("mkdocs.yml")

    def test_is_valid_yaml(self):
        p = REPO_ROOT / "mkdocs.yml"
        raw = yaml.safe_load(p.read_text(encoding="utf-8"))
        assert isinstance(raw, dict)

    def test_site_name_present(self):
        raw = yaml.safe_load((REPO_ROOT / "mkdocs.yml").read_text(encoding="utf-8"))
        assert "site_name" in raw

    def test_theme_is_material(self):
        raw = yaml.safe_load((REPO_ROOT / "mkdocs.yml").read_text(encoding="utf-8"))
        assert raw.get("theme", {}).get("name") == "material"

    def test_nav_is_list(self):
        raw = yaml.safe_load((REPO_ROOT / "mkdocs.yml").read_text(encoding="utf-8"))
        assert isinstance(raw.get("nav"), list)

    def test_nav_references_index(self):
        raw = yaml.safe_load((REPO_ROOT / "mkdocs.yml").read_text(encoding="utf-8"))
        nav_str = str(raw.get("nav", ""))
        assert "index.md" in nav_str


# ===========================================================================
# docs/ pages
# ===========================================================================

_REQUIRED_DOCS = [
    "docs/index.md",
    "docs/getting-started.md",
    "docs/first-scan.md",
    "docs/architecture.md",
    "docs/findings-reference.md",
    "docs/baseline-alignment.md",
    "docs/scan-all.md",
    "docs/html-report.md",
    "docs/exports.md",
    "docs/cli-reference.md",
    "docs/contributing.md",
]


class TestDocsPages:
    @pytest.mark.parametrize("rel_path", _REQUIRED_DOCS)
    def test_page_exists(self, rel_path):
        _exists(rel_path)

    @pytest.mark.parametrize("rel_path", _REQUIRED_DOCS)
    def test_page_not_empty(self, rel_path):
        p = REPO_ROOT / rel_path
        content = p.read_text(encoding="utf-8").strip()
        assert len(content) > 100, f"{rel_path} is suspiciously short ({len(content)} chars)"

    def test_index_mentions_all_finding_ids(self):
        """Every finding ID defined in the codebase should be listed in the index."""
        index = (REPO_ROOT / "docs" / "index.md").read_text(encoding="utf-8")
        finding_ids = [
            "CA-MFA-001",
            "CA-MFA-002",
            "CA-LEGACY-001",
            "CA-LEGACY-002",
            "CA-ADMIN-001",
            "CA-ADMIN-002",
            "CA-BG-001",
            "CA-BG-002",
            "CA-BG-003",
            "CA-EXCL-001",
            "CA-EXCL-002",
            "CA-RISK-001",
            "CA-RISK-002",
            "CA-SESS-001",
            "CA-SP-001",
            "CA-SP-002",
        ]
        for fid in finding_ids:
            assert fid in index, f"{fid} not listed in docs/index.md"

    def test_findings_reference_covers_all_ids(self):
        ref = (REPO_ROOT / "docs" / "findings-reference.md").read_text(encoding="utf-8")
        for fid in ["CA-MFA-001", "CA-LEGACY-001", "CA-BG-001", "CA-RISK-001", "CA-SESS-001"]:
            assert fid in ref, f"{fid} missing from findings-reference.md"

    def test_cli_reference_documents_scan_command(self):
        ref = (REPO_ROOT / "docs" / "cli-reference.md").read_text(encoding="utf-8")
        assert "ca-radar scan" in ref
        assert "--tenant" in ref
        assert "--auth" in ref


# ===========================================================================
# Dockerfile
# ===========================================================================


class TestDockerfile:
    def test_file_exists(self):
        _exists("Dockerfile")

    def test_dockerignore_exists(self):
        _exists(".dockerignore")

    def test_multistage_build(self):
        content = (REPO_ROOT / "Dockerfile").read_text(encoding="utf-8")
        assert content.count("FROM ") >= 2, "Expected multi-stage Dockerfile (≥2 FROM lines)"

    def test_distroless_base(self):
        content = (REPO_ROOT / "Dockerfile").read_text(encoding="utf-8")
        assert "distroless" in content

    def test_nonroot_user(self):
        content = (REPO_ROOT / "Dockerfile").read_text(encoding="utf-8")
        assert "nonroot" in content

    def test_entrypoint_is_ca_radar(self):
        content = (REPO_ROOT / "Dockerfile").read_text(encoding="utf-8")
        assert "ca-radar" in content
        assert "ENTRYPOINT" in content

    def test_volume_snapshot(self):
        content = (REPO_ROOT / "Dockerfile").read_text(encoding="utf-8")
        assert "/snapshot" in content


# ===========================================================================
# CHANGELOG.md
# ===========================================================================


class TestChangelog:
    def test_file_exists(self):
        _exists("CHANGELOG.md")

    def test_contains_v010_entry(self):
        content = (REPO_ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
        assert "0.1.0" in content

    def test_follows_keepachangelog_format(self):
        content = (REPO_ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
        assert "## [" in content  # at least one version section header

    def test_added_section_present(self):
        content = (REPO_ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
        assert "### Added" in content


# ===========================================================================
# Package metadata
# ===========================================================================


class TestPackageMetadata:
    def test_runtime_dependencies_do_not_include_unused_msgraph_sdk(self):
        pyproject = tomllib.loads((REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8"))
        dependencies = pyproject["project"]["dependencies"]
        assert not any(dep.lower().startswith("msgraph-sdk") for dep in dependencies)


# ===========================================================================
# GitHub Actions workflows
# ===========================================================================


class TestGitHubWorkflows:
    def test_ci_yml_exists(self):
        _exists(".github/workflows/ci.yml")

    def test_release_yml_exists(self):
        _exists(".github/workflows/release.yml")

    def test_ci_yml_valid_yaml(self):
        p = REPO_ROOT / ".github" / "workflows" / "ci.yml"
        raw = yaml.safe_load(p.read_text(encoding="utf-8"))
        assert "jobs" in raw

    def test_release_yml_valid_yaml(self):
        p = REPO_ROOT / ".github" / "workflows" / "release.yml"
        raw = yaml.safe_load(p.read_text(encoding="utf-8"))
        assert "jobs" in raw

    def test_ci_triggers_on_main(self):
        raw = yaml.safe_load(
            (REPO_ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
        )
        # PyYAML 1.1 parses the `on:` key as boolean True
        trigger = raw.get(True, raw.get("on", {}))
        branches = trigger.get("push", {}).get("branches", [])
        assert "main" in branches

    def test_release_triggers_on_version_tag(self):
        raw = yaml.safe_load(
            (REPO_ROOT / ".github" / "workflows" / "release.yml").read_text(encoding="utf-8")
        )
        trigger = raw.get(True, raw.get("on", {}))
        tags = trigger.get("push", {}).get("tags", [])
        assert any("v*" in t for t in tags)

    def test_ci_has_test_job(self):
        raw = yaml.safe_load(
            (REPO_ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
        )
        assert "test" in raw.get("jobs", {})

    def test_release_has_pypi_job(self):
        raw = yaml.safe_load(
            (REPO_ROOT / ".github" / "workflows" / "release.yml").read_text(encoding="utf-8")
        )
        assert "pypi" in raw.get("jobs", {})

    def test_release_has_docker_job(self):
        raw = yaml.safe_load(
            (REPO_ROOT / ".github" / "workflows" / "release.yml").read_text(encoding="utf-8")
        )
        assert "docker" in raw.get("jobs", {})
