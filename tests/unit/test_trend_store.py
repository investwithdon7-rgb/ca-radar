"""Tests for ca_radar.trend.store — TrendStore SQLite persistence."""

from __future__ import annotations

from datetime import UTC, datetime

from ca_radar.trend.store import PortfolioSummaryRow, TrendEntry, TrendStore

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_SEV_ZERO = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}


def _sev(critical=0, high=0, medium=0, low=0, info=0):
    return {"critical": critical, "high": high, "medium": medium, "low": low, "info": info}


def _store(tmp_path) -> TrendStore:
    return TrendStore(base_dir=tmp_path)


# ---------------------------------------------------------------------------
# Schema / construction
# ---------------------------------------------------------------------------


class TestTrendStoreConstruction:
    def test_creates_db_file(self, tmp_path):
        TrendStore(base_dir=tmp_path)
        assert (tmp_path / "trend.db").exists()

    def test_creates_base_dir_if_missing(self, tmp_path):
        subdir = tmp_path / "does" / "not" / "exist"
        TrendStore(base_dir=subdir)
        assert (subdir / "trend.db").exists()

    def test_idempotent_construction(self, tmp_path):
        """Second construction must not raise (CREATE TABLE IF NOT EXISTS)."""
        TrendStore(base_dir=tmp_path)
        TrendStore(base_dir=tmp_path)  # no error


# ---------------------------------------------------------------------------
# save_scan / load_trend
# ---------------------------------------------------------------------------


class TestSaveScan:
    def test_save_and_retrieve(self, tmp_path):
        store = _store(tmp_path)
        ts = datetime(2025, 1, 1, 12, 0, 0, tzinfo=UTC)
        store.save_scan("tenant-a", ts, 82, _sev(high=1), 1, tool_version="0.1.0")
        entries = store.load_trend("tenant-a")
        assert len(entries) == 1
        e = entries[0]
        assert e.tenant_id == "tenant-a"
        assert e.posture_score == 82
        assert e.high_count == 1
        assert e.total_findings == 1
        assert e.tool_version == "0.1.0"

    def test_captured_at_datetime_stored_as_iso(self, tmp_path):
        store = _store(tmp_path)
        ts = datetime(2025, 6, 15, 9, 30, 0, tzinfo=UTC)
        store.save_scan("t", ts, 90, _SEV_ZERO, 0)
        e = store.load_trend("t")[0]
        assert "2025-06-15" in e.captured_at

    def test_captured_at_string_accepted(self, tmp_path):
        store = _store(tmp_path)
        store.save_scan("t", "2025-06-15T00:00:00Z", 70, _SEV_ZERO, 0)
        e = store.load_trend("t")[0]
        assert e.captured_at == "2025-06-15T00:00:00Z"

    def test_snapshot_path_stored(self, tmp_path):
        store = _store(tmp_path)
        store.save_scan("t", "2025-01-01", 80, _SEV_ZERO, 0, snapshot_path="/some/path")
        assert store.load_trend("t")[0].snapshot_path == "/some/path"

    def test_severity_counts_stored(self, tmp_path):
        store = _store(tmp_path)
        store.save_scan(
            "t", "2025-01-01", 60, _sev(critical=1, high=2, medium=3, low=4, info=5), 15
        )
        e = store.load_trend("t")[0]
        assert e.critical_count == 1
        assert e.high_count == 2
        assert e.medium_count == 3
        assert e.low_count == 4
        assert e.info_count == 5

    def test_missing_severity_keys_default_to_zero(self, tmp_path):
        store = _store(tmp_path)
        store.save_scan("t", "2025-01-01", 90, {}, 0)
        e = store.load_trend("t")[0]
        assert e.critical_count == 0

    def test_multiple_scans_ordered_newest_first(self, tmp_path):
        store = _store(tmp_path)
        for i, ts in enumerate(["2025-01-01", "2025-03-01", "2025-02-01"]):
            store.save_scan("t", ts, 80 - i * 5, _SEV_ZERO, i)
        entries = store.load_trend("t")
        assert entries[0].captured_at == "2025-03-01"
        assert entries[-1].captured_at == "2025-01-01"

    def test_limit_respected(self, tmp_path):
        store = _store(tmp_path)
        for i in range(25):
            store.save_scan("t", f"2025-01-{i + 1:02d}", 80, _SEV_ZERO, 0)
        assert len(store.load_trend("t", limit=10)) == 10

    def test_different_tenants_isolated(self, tmp_path):
        store = _store(tmp_path)
        store.save_scan("tenant-a", "2025-01-01", 90, _SEV_ZERO, 0)
        store.save_scan("tenant-b", "2025-01-01", 50, _SEV_ZERO, 3)
        assert len(store.load_trend("tenant-a")) == 1
        assert len(store.load_trend("tenant-b")) == 1
        assert store.load_trend("tenant-a")[0].posture_score == 90

    def test_unknown_tenant_returns_empty(self, tmp_path):
        store = _store(tmp_path)
        assert store.load_trend("no-such-tenant") == []

    def test_returns_trend_entry_objects(self, tmp_path):
        store = _store(tmp_path)
        store.save_scan("t", "2025-01-01", 80, _SEV_ZERO, 0)
        assert all(isinstance(e, TrendEntry) for e in store.load_trend("t"))


# ---------------------------------------------------------------------------
# load_portfolio_summary
# ---------------------------------------------------------------------------


class TestPortfolioSummary:
    def test_empty_returns_empty_list(self, tmp_path):
        assert _store(tmp_path).load_portfolio_summary() == []

    def test_single_tenant_single_scan(self, tmp_path):
        store = _store(tmp_path)
        store.save_scan("t", "2025-01-01", 75, _sev(high=2), 2)
        rows = store.load_portfolio_summary()
        assert len(rows) == 1
        row = rows[0]
        assert row.tenant_id == "t"
        assert row.latest_posture_score == 75
        assert row.latest_high == 2
        assert row.scan_count == 1

    def test_latest_scan_used_not_oldest(self, tmp_path):
        store = _store(tmp_path)
        store.save_scan("t", "2025-01-01", 60, _SEV_ZERO, 5)
        store.save_scan("t", "2025-06-01", 90, _SEV_ZERO, 0)  # latest
        rows = store.load_portfolio_summary()
        assert rows[0].latest_posture_score == 90

    def test_scan_count_reflects_history(self, tmp_path):
        store = _store(tmp_path)
        for i in range(5):
            store.save_scan("t", f"2025-01-{i + 1:02d}", 80, _SEV_ZERO, 0)
        rows = store.load_portfolio_summary()
        assert rows[0].scan_count == 5

    def test_trend_scores_oldest_to_newest(self, tmp_path):
        store = _store(tmp_path)
        for score, ts in [(60, "2025-01-01"), (70, "2025-02-01"), (80, "2025-03-01")]:
            store.save_scan("t", ts, score, _SEV_ZERO, 0)
        rows = store.load_portfolio_summary(trend_limit=10)
        assert rows[0].trend_scores == [60, 70, 80]

    def test_trend_scores_capped_at_limit(self, tmp_path):
        store = _store(tmp_path)
        for i in range(15):
            store.save_scan("t", f"2025-01-{i + 1:02d}", 80, _SEV_ZERO, 0)
        rows = store.load_portfolio_summary(trend_limit=5)
        assert len(rows[0].trend_scores) == 5

    def test_multiple_tenants_ordered_by_score_asc(self, tmp_path):
        store = _store(tmp_path)
        store.save_scan("good", "2025-01-01", 95, _SEV_ZERO, 0)
        store.save_scan("medium", "2025-01-01", 70, _SEV_ZERO, 2)
        store.save_scan("bad", "2025-01-01", 30, _SEV_ZERO, 8)
        rows = store.load_portfolio_summary()
        scores = [r.latest_posture_score for r in rows]
        assert scores == sorted(scores)  # ascending (worst first)

    def test_returns_portfolio_summary_row_objects(self, tmp_path):
        store = _store(tmp_path)
        store.save_scan("t", "2025-01-01", 80, _SEV_ZERO, 0)
        rows = store.load_portfolio_summary()
        assert all(isinstance(r, PortfolioSummaryRow) for r in rows)

    def test_report_path_empty_by_default(self, tmp_path):
        store = _store(tmp_path)
        store.save_scan("t", "2025-01-01", 80, _SEV_ZERO, 0)
        rows = store.load_portfolio_summary()
        assert rows[0].report_path == ""

    def test_report_path_can_be_set(self, tmp_path):
        store = _store(tmp_path)
        store.save_scan("t", "2025-01-01", 80, _SEV_ZERO, 0, snapshot_path="/reports/t/report.html")
        rows = store.load_portfolio_summary()
        rows[0].report_path = "/reports/t/report.html"
        assert rows[0].report_path == "/reports/t/report.html"


# ---------------------------------------------------------------------------
# tenant_ids
# ---------------------------------------------------------------------------


class TestTenantIds:
    def test_empty_store_returns_empty(self, tmp_path):
        assert _store(tmp_path).tenant_ids() == []

    def test_returns_all_distinct_tenants(self, tmp_path):
        store = _store(tmp_path)
        store.save_scan("alpha", "2025-01-01", 80, _SEV_ZERO, 0)
        store.save_scan("beta", "2025-01-01", 70, _SEV_ZERO, 0)
        store.save_scan("alpha", "2025-02-01", 85, _SEV_ZERO, 0)  # duplicate tenant
        ids = store.tenant_ids()
        assert sorted(ids) == ["alpha", "beta"]

    def test_ordered_alphabetically(self, tmp_path):
        store = _store(tmp_path)
        for name in ["zeta", "alpha", "mu"]:
            store.save_scan(name, "2025-01-01", 80, _SEV_ZERO, 0)
        assert store.tenant_ids() == ["alpha", "mu", "zeta"]
