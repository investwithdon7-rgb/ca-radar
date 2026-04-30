"""Smoke tests for the CLI entry point."""

import re

from typer.testing import CliRunner

from ca_radar import __version__
from ca_radar.cli import app

runner = CliRunner()


def _plain(text: str) -> str:
    """Strip ANSI escape codes so assertions work regardless of terminal colour mode."""
    return re.sub(r"\x1b\[[0-9;]*[mK]", "", text)


def test_version_flag() -> None:
    result = runner.invoke(app, ["--version"])
    assert result.exit_code == 0
    assert __version__ in _plain(result.output)


def test_help() -> None:
    result = runner.invoke(app, ["--help"])
    assert result.exit_code == 0
    out = _plain(result.output)
    assert "scan" in out
    assert "setup" in out


def test_scan_help() -> None:
    result = runner.invoke(app, ["scan", "--help"])
    assert result.exit_code == 0
    out = _plain(result.output)
    assert "--tenant" in out
    # --tenant is now optional (reads from saved config)
    assert "optional" in out.lower() or "config" in out.lower()


def test_scan_all_help() -> None:
    result = runner.invoke(app, ["scan-all", "--help"])
    assert result.exit_code == 0
    assert "--tenants" in _plain(result.output)


def test_setup_help() -> None:
    result = runner.invoke(app, ["setup", "--help"])
    assert result.exit_code == 0
    assert "setup" in _plain(result.output).lower()


def test_scan_no_config_no_args_fails(tmp_path) -> None:
    """scan with no tenant and no saved config should exit non-zero with a helpful message."""
    import os

    # Point HOME to a temp dir so no real ~/.ca-radar/config.yaml is read
    old_home = os.environ.get("HOME", "")
    old_userprofile = os.environ.get("USERPROFILE", "")
    try:
        os.environ["HOME"] = str(tmp_path)
        os.environ["USERPROFILE"] = str(tmp_path)
        result = runner.invoke(app, ["scan"])
        assert result.exit_code != 0
        out = _plain(result.output).lower()
        assert "tenant" in out or "setup" in out
    finally:
        os.environ["HOME"] = old_home
        os.environ["USERPROFILE"] = old_userprofile
