"""SQLite-backed trend store — persists posture scores across scans.

A single ``trend.db`` file lives inside the snapshot base directory.
Every completed scan appends one row; queries return the history for
a tenant or a portfolio-level summary (one row per tenant, latest scan).

Schema
------
``scans`` table — one row per completed scan::

    id             INTEGER  PK AUTOINCREMENT
    tenant_id      TEXT     indexed
    captured_at    TEXT     ISO-8601 UTC
    posture_score  INTEGER  0–100
    total_findings INTEGER
    critical_count INTEGER
    high_count     INTEGER
    medium_count   INTEGER
    low_count      INTEGER
    info_count     INTEGER
    tool_version   TEXT
    snapshot_path  TEXT     absolute path to snapshot directory

Usage::

    store = TrendStore("./snapshot")
    store.save_scan(
        tenant_id="contoso.onmicrosoft.com",
        captured_at=datetime.now(UTC),
        posture_score=82,
        by_severity={"critical": 0, "high": 1, "medium": 2, "low": 0, "info": 0},
        total_findings=3,
        tool_version="0.1.0",
        snapshot_path="/path/to/snapshot",
    )
    history = store.load_trend("contoso.onmicrosoft.com", limit=20)
    summary = store.load_portfolio_summary()
"""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

# ---------------------------------------------------------------------------
# Data types
# ---------------------------------------------------------------------------


@dataclass
class TrendEntry:
    """One scan's worth of trend data."""

    tenant_id: str
    captured_at: str  # ISO-8601 string
    posture_score: int
    total_findings: int
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    info_count: int
    tool_version: str
    snapshot_path: str


@dataclass
class PortfolioSummaryRow:
    """Latest-scan summary for one tenant (used for portfolio report)."""

    tenant_id: str
    latest_captured_at: str
    latest_posture_score: int
    latest_total_findings: int
    latest_critical: int
    latest_high: int
    latest_medium: int
    latest_low: int
    latest_info: int
    scan_count: int
    trend_scores: list[int] = field(default_factory=list)  # oldest→newest
    report_path: str = ""  # filled in by caller after rendering


# ---------------------------------------------------------------------------
# Store
# ---------------------------------------------------------------------------

_DB_FILENAME = "trend.db"

_DDL = """\
CREATE TABLE IF NOT EXISTS scans (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    tenant_id      TEXT    NOT NULL,
    captured_at    TEXT    NOT NULL,
    posture_score  INTEGER NOT NULL,
    total_findings INTEGER NOT NULL DEFAULT 0,
    critical_count INTEGER NOT NULL DEFAULT 0,
    high_count     INTEGER NOT NULL DEFAULT 0,
    medium_count   INTEGER NOT NULL DEFAULT 0,
    low_count      INTEGER NOT NULL DEFAULT 0,
    info_count     INTEGER NOT NULL DEFAULT 0,
    tool_version   TEXT    NOT NULL DEFAULT '',
    snapshot_path  TEXT    NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_scans_tenant_captured
    ON scans (tenant_id, captured_at DESC);
"""


class TrendStore:
    """Read/write trend data from a SQLite database.

    The database file is created automatically on first use.
    All methods open and close their own connections so the store is
    safe to call from multiple threads / processes.

    Args:
        base_dir: The snapshot base directory (same as ``SnapshotStore.base_dir``).
                  The ``trend.db`` file is placed directly inside it.
    """

    def __init__(self, base_dir: str | Path = "snapshot") -> None:
        self._db_path = Path(base_dir) / _DB_FILENAME
        self._ensure_schema()

    # ------------------------------------------------------------------
    # Write
    # ------------------------------------------------------------------

    def save_scan(
        self,
        tenant_id: str,
        captured_at: datetime | str,
        posture_score: int,
        by_severity: dict[str, int],
        total_findings: int,
        *,
        tool_version: str = "",
        snapshot_path: str = "",
    ) -> None:
        """Append one scan record to the trend database.

        Args:
            tenant_id:      Tenant identifier string.
            captured_at:    Snapshot timestamp (datetime or ISO-8601 string).
            posture_score:  Integer 0–100.
            by_severity:    Dict with keys ``critical/high/medium/low/info``.
            total_findings: Total number of findings in this scan.
            tool_version:   ca-radar version string.
            snapshot_path:  Absolute path to the snapshot directory on disk.
        """
        captured_str = (
            captured_at.isoformat() if isinstance(captured_at, datetime) else str(captured_at)
        )
        with self._connect() as conn:
            conn.execute(
                """INSERT INTO scans
                   (tenant_id, captured_at, posture_score, total_findings,
                    critical_count, high_count, medium_count, low_count,
                    info_count, tool_version, snapshot_path)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
                (
                    tenant_id,
                    captured_str,
                    int(posture_score),
                    int(total_findings),
                    int(by_severity.get("critical", 0)),
                    int(by_severity.get("high", 0)),
                    int(by_severity.get("medium", 0)),
                    int(by_severity.get("low", 0)),
                    int(by_severity.get("info", 0)),
                    tool_version,
                    snapshot_path,
                ),
            )

    # ------------------------------------------------------------------
    # Read
    # ------------------------------------------------------------------

    def load_trend(self, tenant_id: str, limit: int = 20) -> list[TrendEntry]:
        """Return up to *limit* scan records for *tenant_id*, newest first.

        Args:
            tenant_id: Tenant to query.
            limit:     Maximum number of rows (default 20).

        Returns:
            List of :class:`TrendEntry`, newest first.
        """
        with self._connect() as conn:
            rows = conn.execute(
                """SELECT tenant_id, captured_at, posture_score, total_findings,
                          critical_count, high_count, medium_count, low_count,
                          info_count, tool_version, snapshot_path
                   FROM scans
                   WHERE tenant_id = ?
                   ORDER BY captured_at DESC
                   LIMIT ?""",
                (tenant_id, limit),
            ).fetchall()
        return [TrendEntry(*row) for row in rows]

    def load_portfolio_summary(self, trend_limit: int = 10) -> list[PortfolioSummaryRow]:
        """Return one :class:`PortfolioSummaryRow` per tenant (latest scan values).

        Rows are ordered by latest posture score ascending (worst first) so the
        portfolio report highlights tenants needing the most attention.

        Args:
            trend_limit: How many historical scores to include per tenant
                         for sparkline rendering (default 10).

        Returns:
            List of :class:`PortfolioSummaryRow`, worst posture first.
        """
        with self._connect() as conn:
            # Latest scan per tenant + scan count
            rows = conn.execute(
                """SELECT
                     s.tenant_id,
                     s.captured_at,
                     s.posture_score,
                     s.total_findings,
                     s.critical_count,
                     s.high_count,
                     s.medium_count,
                     s.low_count,
                     s.info_count,
                     cnt.scan_count
                   FROM scans s
                   INNER JOIN (
                     SELECT tenant_id, MAX(captured_at) AS max_ts
                     FROM scans
                     GROUP BY tenant_id
                   ) latest ON s.tenant_id = latest.tenant_id
                             AND s.captured_at = latest.max_ts
                   INNER JOIN (
                     SELECT tenant_id, COUNT(*) AS scan_count
                     FROM scans
                     GROUP BY tenant_id
                   ) cnt ON s.tenant_id = cnt.tenant_id
                   ORDER BY s.posture_score ASC""",
            ).fetchall()

            result: list[PortfolioSummaryRow] = []
            for row in rows:
                (tid, ts, score, total, crit, high, med, low, info, cnt) = row

                # Fetch last `trend_limit` scores oldest-first for sparkline
                trend_rows = conn.execute(
                    """SELECT posture_score FROM scans
                       WHERE tenant_id = ?
                       ORDER BY captured_at DESC
                       LIMIT ?""",
                    (tid, trend_limit),
                ).fetchall()
                # Reverse so it's oldest→newest
                trend_scores = [r[0] for r in reversed(trend_rows)]

                result.append(
                    PortfolioSummaryRow(
                        tenant_id=tid,
                        latest_captured_at=ts,
                        latest_posture_score=score,
                        latest_total_findings=total,
                        latest_critical=crit,
                        latest_high=high,
                        latest_medium=med,
                        latest_low=low,
                        latest_info=info,
                        scan_count=cnt,
                        trend_scores=trend_scores,
                    )
                )
        return result

    def tenant_ids(self) -> list[str]:
        """Return all tenant IDs that have at least one scan record."""
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT DISTINCT tenant_id FROM scans ORDER BY tenant_id"
            ).fetchall()
        return [r[0] for r in rows]

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _connect(self) -> sqlite3.Connection:
        self._db_path.parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(str(self._db_path))
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        return conn

    def _ensure_schema(self) -> None:
        with self._connect() as conn:
            conn.executescript(_DDL)
