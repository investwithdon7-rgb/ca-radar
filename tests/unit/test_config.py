"""Tests for ca_radar.config — load, save, and merge logic."""

from __future__ import annotations

from pathlib import Path

import yaml

from ca_radar.config import RadarConfig

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _write_config(tmp_path: Path, data: dict) -> Path:
    p = tmp_path / "config.yaml"
    p.write_text(yaml.safe_dump(data), encoding="utf-8")
    return p


# ===========================================================================
# Default / empty state
# ===========================================================================


class TestDefaults:
    def test_empty_config_has_defaults(self):
        cfg = RadarConfig()
        assert cfg.tenant == ""
        assert cfg.client_id == ""
        assert cfg.auth_mode == "delegated"
        assert cfg.out == "./snapshot"
        assert cfg.redact is True
        assert cfg.concurrency == 5

    def test_load_missing_file_returns_defaults(self, tmp_path: Path):
        cfg = RadarConfig.load(path=tmp_path / "nonexistent.yaml")
        assert cfg.tenant == ""
        assert cfg.auth_mode == "delegated"

    def test_load_empty_file_returns_defaults(self, tmp_path: Path):
        p = tmp_path / "config.yaml"
        p.write_text("", encoding="utf-8")
        cfg = RadarConfig.load(path=p)
        assert cfg.tenant == ""


# ===========================================================================
# Load
# ===========================================================================


class TestLoad:
    def test_load_tenant_and_client_id(self, tmp_path: Path):
        p = _write_config(
            tmp_path,
            {
                "tenant": "contoso.onmicrosoft.com",
                "client_id": "aaaa-bbbb",
            },
        )
        cfg = RadarConfig.load(path=p)
        assert cfg.tenant == "contoso.onmicrosoft.com"
        assert cfg.client_id == "aaaa-bbbb"

    def test_load_all_known_fields(self, tmp_path: Path):
        p = _write_config(
            tmp_path,
            {
                "tenant": "fabrikam.com",
                "client_id": "cccc-dddd",
                "auth_mode": "app",
                "cert_path": "/certs/my.pem",
                "client_secret": "s3cr3t",
                "out": "/data/snapshots",
                "redact": False,
                "concurrency": 10,
            },
        )
        cfg = RadarConfig.load(path=p)
        assert cfg.auth_mode == "app"
        assert cfg.cert_path == "/certs/my.pem"
        assert cfg.client_secret == "s3cr3t"
        assert cfg.out == "/data/snapshots"
        assert cfg.redact is False
        assert cfg.concurrency == 10

    def test_load_extra_keys_preserved(self, tmp_path: Path):
        """Unknown keys should round-trip safely."""
        p = _write_config(
            tmp_path,
            {
                "tenant": "x.com",
                "future_option": "hello",
            },
        )
        cfg = RadarConfig.load(path=p)
        assert cfg._extra.get("future_option") == "hello"

    def test_load_invalid_yaml_returns_defaults(self, tmp_path: Path):
        p = tmp_path / "config.yaml"
        p.write_text("not: valid: yaml: [[[", encoding="utf-8")
        cfg = RadarConfig.load(path=p)
        assert cfg.tenant == ""


# ===========================================================================
# Save
# ===========================================================================


class TestSave:
    def test_save_creates_file(self, tmp_path: Path):
        cfg = RadarConfig(tenant="contoso.com", client_id="1234")
        p = cfg.save(path=tmp_path / "config.yaml")
        assert p.exists()

    def test_save_creates_parent_dirs(self, tmp_path: Path):
        deep = tmp_path / "a" / "b" / "c" / "config.yaml"
        cfg = RadarConfig(tenant="x.com")
        cfg.save(path=deep)
        assert deep.exists()

    def test_save_round_trips(self, tmp_path: Path):
        original = RadarConfig(
            tenant="roundtrip.com",
            client_id="abcd-efgh",
            auth_mode="app",
            out="/tmp/snap",
            redact=False,
            concurrency=3,
        )
        p = original.save(path=tmp_path / "config.yaml")
        loaded = RadarConfig.load(path=p)
        assert loaded.tenant == "roundtrip.com"
        assert loaded.client_id == "abcd-efgh"
        assert loaded.auth_mode == "app"
        assert loaded.out == "/tmp/snap"
        assert loaded.redact is False
        assert loaded.concurrency == 3

    def test_save_omits_empty_strings(self, tmp_path: Path):
        cfg = RadarConfig(tenant="", client_id="", cert_path="")
        p = cfg.save(path=tmp_path / "config.yaml")
        raw = yaml.safe_load(p.read_text())
        # Empty-string fields should NOT appear in the YAML
        assert "tenant" not in raw
        assert "client_id" not in raw
        assert "cert_path" not in raw

    def test_save_preserves_extra_keys(self, tmp_path: Path):
        cfg = RadarConfig(tenant="x.com")
        cfg._extra["future_option"] = "preserved"
        p = cfg.save(path=tmp_path / "config.yaml")
        raw = yaml.safe_load(p.read_text())
        assert raw["future_option"] == "preserved"


# ===========================================================================
# merge_cli
# ===========================================================================


class TestMergeCli:
    def test_merge_overrides_tenant(self):
        base = RadarConfig(tenant="base.com", client_id="base-id")
        merged = base.merge_cli(tenant="override.com")
        assert merged.tenant == "override.com"
        assert merged.client_id == "base-id"  # unchanged

    def test_merge_empty_string_does_not_override(self):
        base = RadarConfig(tenant="keep.com")
        merged = base.merge_cli(tenant="")
        assert merged.tenant == "keep.com"

    def test_merge_none_does_not_override_redact(self):
        base = RadarConfig(redact=False)
        merged = base.merge_cli(redact=None)
        assert merged.redact is False

    def test_merge_false_overrides_redact(self):
        base = RadarConfig(redact=True)
        merged = base.merge_cli(redact=False)
        assert merged.redact is False

    def test_merge_zero_does_not_override_concurrency(self):
        base = RadarConfig(concurrency=8)
        merged = base.merge_cli(concurrency=None)
        assert merged.concurrency == 8

    def test_merge_does_not_mutate_base(self):
        base = RadarConfig(tenant="original.com")
        base.merge_cli(tenant="changed.com")
        assert base.tenant == "original.com"

    def test_merge_all_fields(self):
        base = RadarConfig()
        merged = base.merge_cli(
            tenant="t.com",
            client_id="cid",
            auth_mode="app",
            cert_path="/cert.pem",
            client_secret="s",
            out="/out",
            redact=False,
            concurrency=2,
        )
        assert merged.tenant == "t.com"
        assert merged.client_id == "cid"
        assert merged.auth_mode == "app"
        assert merged.cert_path == "/cert.pem"
        assert merged.client_secret == "s"
        assert merged.out == "/out"
        assert merged.redact is False
        assert merged.concurrency == 2
