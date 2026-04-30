"""Portfolio HTML report renderer.

Renders a single ``portfolio.html`` that shows all scanned tenants in one view,
ranked by posture score.  Each row links to the per-tenant ``report.html``.

Usage::

    from ca_radar.render.html.portfolio_renderer import render_portfolio_report
    from ca_radar.trend.store import TrendStore

    trend = TrendStore("./snapshot")
    rows  = trend.load_portfolio_summary()
    html  = render_portfolio_report(rows, captured_at=datetime.now(UTC))
    Path("./snapshot/portfolio.html").write_text(html, encoding="utf-8")
"""

from __future__ import annotations

from datetime import datetime
from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape

from ca_radar.trend.store import PortfolioSummaryRow

_TEMPLATE_DIR = Path(__file__).parent / "templates"


def render_portfolio_report(
    rows: list[PortfolioSummaryRow],
    *,
    captured_at: datetime | str | None = None,
    tool_version: str = "",
) -> str:
    """Render a portfolio HTML report from trend summary rows.

    Args:
        rows:         List of :class:`~ca_radar.trend.store.PortfolioSummaryRow`,
                      one per tenant (as returned by
                      :meth:`~ca_radar.trend.store.TrendStore.load_portfolio_summary`).
        captured_at:  Report generation timestamp (defaults to now UTC).
        tool_version: ca-radar version string for the footer.

    Returns:
        Self-contained UTF-8 HTML string.
    """
    env = Environment(
        loader=FileSystemLoader(str(_TEMPLATE_DIR)),
        autoescape=select_autoescape(["html", "j2"]),
        trim_blocks=True,
        lstrip_blocks=True,
    )

    template = env.get_template("portfolio.html.j2")

    if captured_at is None:
        from datetime import UTC

        captured_at = datetime.now(UTC)

    captured_str = (
        captured_at.isoformat() if isinstance(captured_at, datetime) else str(captured_at)
    )

    # Aggregate stats
    total_tenants = len(rows)
    avg_score = round(sum(r.latest_posture_score for r in rows) / total_tenants, 1) if rows else 0.0
    total_critical = sum(r.latest_critical for r in rows)
    total_high = sum(r.latest_high for r in rows)

    return template.render(
        rows=rows,
        total_tenants=total_tenants,
        avg_score=avg_score,
        total_critical=total_critical,
        total_high=total_high,
        captured_at=captured_str,
        tool_version=tool_version,
    )
