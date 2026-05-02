"""CLI entry point for ca-radar."""

from __future__ import annotations

import asyncio
import sys
import webbrowser
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ca_radar.graph.client import AuthProvider

import typer
from rich import print as rprint
from rich.console import Console
from rich.panel import Panel
from rich.prompt import Confirm, Prompt
from rich.table import Table

from ca_radar import __author__, __organisation__, __version__, __website__


def _make_stdio_resilient() -> None:
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is not None:
            reconfigure(errors="replace")


_make_stdio_resilient()

_BRANDING = f"[dim]{__author__} | {__organisation__} | {__website__}[/dim]"

app = typer.Typer(
    name="ca-radar",
    help=(
        "Conditional Access Gap Analyser & Visualiser for Microsoft 365 / Entra ID.\n\n"
        "Read-only. Produces a static HTML report and JSON findings file.\n"
        "No data is ever written back to the tenant.\n\n"
        "[bold cyan]Quick start:[/bold cyan]  ca-radar setup  ->  ca-radar scan\n\n"
        "[dim]By Anjula Weeranayake | TekDruid | https://tekdruid.com[/dim]"
    ),
    rich_markup_mode="rich",
    no_args_is_help=True,
)

console = Console()


def version_callback(value: bool) -> None:
    if value:
        rprint(f"[bold cyan]ca-radar[/bold cyan] version [bold]{__version__}[/bold]\n{_BRANDING}")
        raise typer.Exit()


@app.callback()
def main(
    version: bool = typer.Option(
        False,
        "--version",
        "-v",
        callback=version_callback,
        is_eager=True,
        help="Show version and exit.",
    ),
) -> None:
    pass


# ===========================================================================
# setup - interactive wizard
# ===========================================================================


@app.command()
def setup() -> None:
    """Interactive first-time setup wizard.

    Guides you through creating an Entra ID app registration,
    entering your credentials, and saving them to
    [bold]~/.ca-radar/config.yaml[/bold].

    After setup you can run [bold]ca-radar scan[/bold] with no arguments.
    """
    from ca_radar.config import RadarConfig

    console.print()
    console.print(
        Panel(
            "[bold cyan]Welcome to ca-radar setup![/bold cyan]\n\n"
            "This wizard will help you connect ca-radar to your\n"
            "Microsoft 365 / Entra ID tenant.\n\n"
            "You will need to create an [bold]App Registration[/bold] in\n"
            "the Azure portal. The wizard can open that page for you.\n\n"
            f"{_BRANDING}",
            title="ca-radar setup",
            border_style="cyan",
            expand=False,
        )
    )
    console.print()

    # Step 1 - tenant
    console.rule("[bold]Step 1 of 4 - Tenant[/bold]")
    console.print(
        "\nEnter your tenant [bold]domain name[/bold] or [bold]tenant ID[/bold] (GUID).\n"
        "[dim]Examples:  contoso.onmicrosoft.com  |  contoso.com  |  "
        "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx[/dim]\n"
    )
    tenant = Prompt.ask("[bold cyan]Tenant domain or ID[/bold cyan]").strip()
    if not tenant:
        console.print("[red]Tenant is required.[/red]")
        raise typer.Exit(1)

    # Step 2 - App Registration guide
    console.print()
    console.rule("[bold]Step 2 of 4 - App Registration[/bold]")
    console.print(
        "\nca-radar needs a [bold]read-only[/bold] app registration in your tenant.\n"
        "No write permissions are ever required.\n"
    )
    _print_app_reg_instructions()

    open_portal = Confirm.ask(
        "[bold cyan]Open the Azure portal App Registration page now?[/bold cyan]",
        default=True,
    )
    if open_portal:
        portal_url = (
            "https://portal.azure.com/#view/Microsoft_AAD_RegisteredApps"
            "/CreateApplicationBlade/quickStartType~/null/isMSAApp~/false"
        )
        webbrowser.open(portal_url)
        console.print(
            "\n[dim]Browser opened - create your app registration, then come back here.[/dim]\n"
        )
        input("  Press Enter when you have your Client ID ready...")
    console.print()

    # Step 3 - Client ID
    console.rule("[bold]Step 3 of 4 - Client ID & Auth Mode[/bold]")
    console.print(
        "\nPaste the [bold]Application (client) ID[/bold] from your app registration.\n"
        "[dim]Format: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx[/dim]\n"
    )
    client_id = Prompt.ask("[bold cyan]Client ID[/bold cyan]").strip()
    if not client_id:
        console.print("[red]Client ID is required.[/red]")
        raise typer.Exit(1)

    # Auth mode selection
    console.print(
        "\nHow should ca-radar authenticate?\n\n"
        "  [bold cyan]1[/bold cyan]  Delegated (device-code) - browser sign-in, recommended for interactive use\n"
        "  [bold cyan]2[/bold cyan]  App (certificate) - unattended / CI/CD use\n"
        "  [bold cyan]3[/bold cyan]  App (client secret) - unattended, less secure than certificate\n"
    )
    auth_choice = Prompt.ask(
        "[bold cyan]Auth mode[/bold cyan]",
        choices=["1", "2", "3"],
        default="1",
    )
    auth_map = {"1": "delegated", "2": "app", "3": "app"}
    auth_mode = auth_map[auth_choice]

    cert_path = ""
    client_secret = ""

    if auth_choice == "2":
        cert_path = Prompt.ask("[bold cyan]Path to PEM certificate file[/bold cyan]").strip()
    elif auth_choice == "3":
        client_secret = Prompt.ask(
            "[bold cyan]Client secret[/bold cyan]",
            password=True,
        ).strip()

    # Step 4 - Options
    console.print()
    console.rule("[bold]Step 4 of 4 - Options[/bold]")
    console.print()

    out = (
        Prompt.ask(
            "[bold cyan]Snapshot output directory[/bold cyan]",
            default="./snapshot",
        ).strip()
        or "./snapshot"
    )

    redact = Confirm.ask(
        "[bold cyan]Redact user UPNs in snapshots?[/bold cyan] "
        "[dim](recommended - stores SHA-256 hashes instead of real names)[/dim]",
        default=True,
    )

    # Save
    console.print()
    cfg = RadarConfig(
        tenant=tenant,
        client_id=client_id,
        auth_mode=auth_mode,
        cert_path=cert_path,
        client_secret=client_secret,
        out=out,
        redact=redact,
    )
    saved_path = cfg.save()

    console.print(
        Panel(
            f"[bold green]OK Configuration saved[/bold green]\n\n"
            f"  File     : [bold]{saved_path}[/bold]\n"
            f"  Tenant   : [bold]{tenant}[/bold]\n"
            f"  Client ID: [bold]{client_id}[/bold]\n"
            f"  Auth     : [bold]{auth_mode}[/bold]\n"
            f"  Output   : [bold]{out}[/bold]\n"
            f"  Redact   : [bold]{'yes' if redact else 'no'}[/bold]",
            border_style="green",
            expand=False,
        )
    )
    console.print()

    # Offer a first scan
    run_now = Confirm.ask(
        "[bold cyan]Run your first scan now?[/bold cyan]",
        default=True,
    )
    if run_now:
        console.print()
        _run_scan_from_config(cfg)


def _print_app_reg_instructions() -> None:
    """Print step-by-step app registration instructions."""
    console.print(
        "[bold]Steps to create the app registration:[/bold]\n\n"
        "  1. In the Azure portal, go to  [cyan]Azure Active Directory[/cyan]  ->  "
        "[cyan]App registrations[/cyan]  ->  [cyan]New registration[/cyan]\n\n"
        "  2. [bold]Name:[/bold]  ca-radar  (or any name you prefer)\n"
        "     [bold]Supported account types:[/bold]  "
        "[bold white]Accounts in this organisational directory only[/bold white]\n"
        "     [bold]Redirect URI:[/bold]  leave blank\n\n"
        "  3. Click [bold]Register[/bold].  Copy the [bold]Application (client) ID[/bold].\n\n"
        "  4. Go to [cyan]API permissions[/cyan]  ->  [cyan]Add a permission[/cyan]  "
        "->  [cyan]Microsoft Graph[/cyan]  ->  [cyan]Application permissions[/cyan]\n\n"
        "     Add the following permissions (all read-only):\n"
    )

    perms = [
        ("Policy.Read.All", "Read Conditional Access policies"),
        ("Directory.Read.All", "Read users, groups, roles"),
        ("PrivilegedAccess.Read.AzureAD", "Read PIM role assignments"),
        ("DeviceManagementConfiguration.Read.All", "Read device compliance policies"),
        ("IdentityRiskyUser.Read.All", "Read risky users"),
        ("AuditLog.Read.All", "Read sign-in logs"),
        ("Application.Read.All", "Read service principals / apps"),
    ]
    for perm, desc in perms:
        console.print(f"     - [bold cyan]{perm:<45}[/bold cyan]  [dim]{desc}[/dim]")

    console.print(
        "\n  5. Click [cyan]Grant admin consent[/cyan] for your organisation.\n\n"
        "  6. [bold](Delegated auth only)[/bold]  Go to [cyan]Authentication[/cyan]  ->  "
        "under [cyan]Advanced settings[/cyan]  enable  "
        "[bold white]Allow public client flows[/bold white].\n"
    )


# ===========================================================================
# scan - single tenant
# ===========================================================================


@app.command()
def scan(
    tenant: str = typer.Option(
        "",
        "--tenant",
        "-t",
        help="Tenant ID or domain name. Reads from saved config if omitted.",
    ),
    out: str = typer.Option(
        "",
        "--out",
        "-o",
        help="Base directory for snapshots. Reads from saved config if omitted.",
    ),
    auth_mode: str = typer.Option(
        "",
        "--auth",
        help="Auth mode: [bold]app[/bold] or [bold]delegated[/bold]. Reads from saved config if omitted.",
    ),
    client_id: str = typer.Option(
        "",
        "--client-id",
        envvar="CA_RADAR_CLIENT_ID",
        help="App registration client ID. Reads from saved config if omitted.",
    ),
    cert_path: str = typer.Option(
        "",
        "--cert-path",
        envvar="CA_RADAR_CERT_PATH",
        help="Path to PEM certificate (app auth).",
    ),
    client_secret: str = typer.Option(
        "",
        "--client-secret",
        envvar="CA_RADAR_CLIENT_SECRET",
        help="Client secret (app auth, less secure than cert).",
    ),
    no_redact: bool = typer.Option(
        False,
        "--no-redact",
        help="Disable UPN hashing in snapshots (shows real usernames).",
    ),
    retain_signins: bool = typer.Option(
        False,
        "--retain-signins",
        help="Keep sign-in log samples after the run.",
    ),
    concurrency: int = typer.Option(
        0,
        "--concurrency",
        help="Max parallel Graph requests. Reads from saved config if omitted.",
    ),
    owners: str = typer.Option(
        "",
        "--owners",
        help="Path to owner mapping YAML file.",
    ),
    exceptions: str = typer.Option(
        "",
        "--exceptions",
        help="Path to exception tracking YAML file.",
    ),
) -> None:
    """Scan a single tenant and collect a snapshot to disk.

    When [bold]~/.ca-radar/config.yaml[/bold] exists (created by
    [bold]ca-radar setup[/bold]) all options are optional - saved values
    are used as defaults.  CLI flags override saved config.
    """
    from ca_radar.config import RadarConfig

    # Load saved config then overlay CLI flags
    cfg = RadarConfig.load()
    cfg = cfg.merge_cli(
        tenant=tenant,
        client_id=client_id,
        auth_mode=auth_mode,
        cert_path=cert_path,
        client_secret=client_secret,
        out=out or "",
        # no_redact inverts to redact=False
        redact=(False if no_redact else None),
        concurrency=(concurrency if concurrency > 0 else None),
    )

    # Validate required fields
    if not cfg.tenant:
        console.print(
            "[bold red]Error:[/bold red] No tenant specified.\n\n"
            "  Run [bold cyan]ca-radar setup[/bold cyan] to save your config, or\n"
            "  pass [bold]--tenant <domain-or-id>[/bold] on the command line."
        )
        raise typer.Exit(1)

    if not cfg.client_id:
        console.print(
            "[bold red]Error:[/bold red] No client ID specified.\n\n"
            "  Run [bold cyan]ca-radar setup[/bold cyan] to save your app registration details, or\n"
            "  pass [bold]--client-id <guid>[/bold] on the command line."
        )
        raise typer.Exit(1)

    _run_scan_from_config(cfg, owners=owners, exceptions=exceptions)


def _run_scan_from_config(cfg: object, *, owners: str = "", exceptions: str = "") -> None:
    """Execute a scan using a fully-resolved RadarConfig."""
    from ca_radar.config import RadarConfig

    assert isinstance(cfg, RadarConfig)

    console.print(
        Panel.fit(
            f"[bold cyan]ca-radar[/bold cyan] [dim]v{__version__}[/dim]  {_BRANDING}\n"
            f"Tenant      : [bold]{cfg.tenant}[/bold]\n"
            f"Auth mode   : [bold]{cfg.auth_mode}[/bold]\n"
            f"Output      : [bold]{cfg.out}[/bold]\n"
            f"Redact UPNs : [bold]{'yes' if cfg.redact else 'no'}[/bold]",
            title="Scan starting",
            border_style="cyan",
        )
    )

    try:
        asyncio.run(
            _run_scan(
                tenant=cfg.tenant,
                out=cfg.out,
                auth_mode=cfg.auth_mode,
                client_id=cfg.client_id,
                cert_path=cfg.cert_path,
                client_secret=cfg.client_secret,
                redact=cfg.redact,
                concurrency=cfg.concurrency,
                owners=owners,
                exceptions=exceptions,
            )
        )
    except KeyboardInterrupt:
        console.print("\n[yellow]Scan cancelled.[/yellow]")
        raise typer.Exit(1) from None
    except Exception as exc:
        console.print(f"\n[bold red]Error:[/bold red] {exc}")
        raise typer.Exit(1) from exc


async def _run_scan(
    tenant: str,
    out: str,
    auth_mode: str,
    client_id: str,
    cert_path: str,
    client_secret: str,
    redact: bool,
    concurrency: int,
    owners: str = "",
    exceptions: str = "",
) -> dict:
    """Run a full single-tenant scan and return a summary dict.

    Returns a dict with keys: tenant_id, report_path, posture_score,
    by_severity, total_findings, captured_at, elapsed_seconds.
    """
    from ca_radar.analysers.runner import run_analysers
    from ca_radar.graph.client import GraphClient
    from ca_radar.resolver.effective_controls import PolicyResolver
    from ca_radar.resolver.policy_graph import SnapshotData
    from ca_radar.snapshot.collector import collect_snapshot
    from ca_radar.snapshot.store import SnapshotStore

    auth = _build_auth(auth_mode, tenant, client_id, cert_path, client_secret)
    store = SnapshotStore(base_dir=out)

    # 1. Collect
    with console.status("[cyan]Collecting snapshot from Graph...[/cyan]"):
        async with GraphClient(auth=auth) as client:
            collection = await collect_snapshot(
                client=client,
                store=store,
                tenant_id=tenant,
                redact=redact,
                concurrency=concurrency,
            )

    _print_collection_summary(collection)

    # 2. Analyse
    with console.status("[cyan]Running gap analysis...[/cyan]"):
        from ca_radar.resolver.policy_graph import PolicyGraph

        data = SnapshotData.from_store(collection.snapshot_path, store)
        resolver = PolicyResolver.from_data(data)
        analysis = await run_analysers(data, resolver)

    from ca_radar.enrichment import enrich_findings, load_enrichment_inputs

    enrichment_config = load_enrichment_inputs(owners_path=owners, exceptions_path=exceptions)
    enrich_findings(analysis.findings, config=enrichment_config)

    _print_analysis_summary(analysis)

    from ca_radar import __version__
    from ca_radar.exports.bicep_export import export_bicep
    from ca_radar.exports.csv_export import export_csv
    from ca_radar.exports.json_export import export_json
    from ca_radar.render.html.renderer import render_html_report

    # 3. Write findings.json (versioned schema)
    findings_path = collection.snapshot_path / "findings.json"
    findings_path.write_text(
        export_json(
            analysis,
            tenant_id=tenant,
            captured_at=collection.captured_at,
            redacted=redact,
            tool_version=__version__,
        ),
        encoding="utf-8",
    )
    console.print(f"[dim]  findings.json  -> {findings_path}[/dim]")

    # 4. Write findings.csv
    csv_path = collection.snapshot_path / "findings.csv"
    csv_path.write_text(
        export_csv(analysis, tenant_id=tenant, captured_at=collection.captured_at),
        encoding="utf-8-sig",
    )
    console.print(f"[dim]  findings.csv   -> {csv_path}[/dim]")

    # 5. Write remediation.bicep (only when findings have templates)
    bicep_src = export_bicep(
        analysis,
        tenant_id=tenant,
        captured_at=collection.captured_at,
        tool_version=__version__,
    )
    if bicep_src:
        bicep_path = collection.snapshot_path / "remediation.bicep"
        bicep_path.write_text(bicep_src, encoding="utf-8")
        console.print(f"[dim]  remediation.bicep -> {bicep_path}[/dim]")

    # 6. Write report.html
    with console.status("[cyan]Rendering HTML report...[/cyan]"):
        graph = PolicyGraph.from_data(data)
        html = render_html_report(
            analysis,
            graph.to_json_dict(),
            tenant_id=tenant,
            captured_at=collection.captured_at,
            redacted=redact,
            tool_version=__version__,
        )
    report_path = collection.snapshot_path / "report.html"
    report_path.write_text(html, encoding="utf-8")
    console.print(f"\n[bold green]OK Report ready[/bold green]  {report_path}")

    # 7. Save trend entry
    try:
        from ca_radar.analysers.base import Severity
        from ca_radar.trend.store import TrendStore

        by_sev = {s.value: len(analysis.by_severity[s]) for s in Severity}
        TrendStore(base_dir=out).save_scan(
            tenant_id=tenant,
            captured_at=collection.captured_at,
            posture_score=analysis.posture_score,
            by_severity=by_sev,
            total_findings=len(analysis.findings),
            tool_version=__version__,
            snapshot_path=str(report_path),
        )
    except Exception as exc:
        console.print(f"[dim]  (trend save skipped: {exc})[/dim]")

    return {
        "tenant_id": tenant,
        "report_path": str(report_path),
        "posture_score": analysis.posture_score,
        "total_findings": len(analysis.findings),
        "captured_at": collection.captured_at,
        "elapsed_seconds": analysis.elapsed_seconds,
    }


def _build_auth(
    mode: str,
    tenant: str,
    client_id: str,
    cert_path: str,
    client_secret: str,
) -> AuthProvider:
    from ca_radar.auth.app_auth import AppAuthProvider
    from ca_radar.auth.delegated_auth import DelegatedAuthProvider

    if mode == "app":
        if not client_id:
            console.print("[bold red]--client-id is required for app auth.[/bold red]")
            raise typer.Exit(1)
        if not cert_path and not client_secret:
            console.print(
                "[bold red]--cert-path or --client-secret is required for app auth.[/bold red]"
            )
            raise typer.Exit(1)
        return AppAuthProvider(
            tenant_id=tenant,
            client_id=client_id,
            cert_path=cert_path or None,
            client_secret=client_secret or None,
        )

    # delegated (device code)
    if not client_id:
        console.print(
            "[bold red]Error:[/bold red] No client ID configured.\n\n"
            "  Run [bold cyan]ca-radar setup[/bold cyan] to register your app, or\n"
            "  pass [bold]--client-id <guid>[/bold] on the command line.\n\n"
            "  [dim]Tip: you need to create an app registration in the Azure portal\n"
            "  and grant it the required read-only Graph permissions.[/dim]"
        )
        raise typer.Exit(1)

    return DelegatedAuthProvider(
        tenant_id=tenant,
        client_id=client_id,
        prompt_callback=lambda msg: console.print(f"\n[bold yellow]{msg}[/bold yellow]\n"),
    )


def _print_collection_summary(result: object) -> None:
    from ca_radar.snapshot.collector import CollectionResult

    assert isinstance(result, CollectionResult)

    table = Table(title="Collection summary", show_header=True, header_style="bold cyan")
    table.add_column("Resource", style="dim")
    table.add_column("Status")

    for name in result.resources_captured:
        table.add_row(name, "[green]OK captured[/green]")
    for name in result.resources_failed:
        table.add_row(name, "[red]X failed[/red]")

    console.print(table)

    if result.scope_warnings:
        console.print(
            "\n[yellow]Scope warnings (affected findings will be indeterminate):[/yellow]"
        )
        for w in result.scope_warnings:
            console.print(f"  [dim]WARN[/dim] {w}")

    console.print(
        Panel.fit(
            f"[green]Snapshot saved[/green]\n"
            f"Path     : [bold]{result.snapshot_path}[/bold]\n"
            f"Captured : [bold]{len(result.resources_captured)}[/bold] resources  "
            f"Failed : [bold]{len(result.resources_failed)}[/bold]  "
            f"Time : [bold]{result.elapsed_seconds:.1f}s[/bold]",
            border_style="green",
        )
    )


def _print_analysis_summary(result: object) -> None:
    from ca_radar.analysers.base import Severity
    from ca_radar.analysers.runner import AnalysisResult

    assert isinstance(result, AnalysisResult)

    if result.analyser_errors:
        console.print("\n[yellow]Analyser errors:[/yellow]")
        for analyser, msg in result.analyser_errors.items():
            console.print(f"  [dim]{analyser}[/dim]: {msg}")

    if not result.findings:
        console.print(
            Panel.fit(
                "[bold green]OK No findings[/bold green] - posture score [bold]100/100[/bold]\n"
                f"[dim]Analysis completed in {result.elapsed_seconds:.1f}s[/dim]",
                border_style="green",
            )
        )
        return

    # Build a Rich table: one row per finding
    table = Table(title="Gap Analysis", show_header=True, header_style="bold cyan")
    table.add_column("ID", style="bold", no_wrap=True)
    table.add_column("Severity", no_wrap=True)
    table.add_column("Priority", no_wrap=True)
    table.add_column("Title")
    table.add_column("Owner")
    table.add_column("Affected", justify="right")
    table.add_column("Conf.", justify="right", style="dim")

    _sev_colour = {
        Severity.critical: "bold red",
        Severity.high: "orange3",
        Severity.medium: "yellow",
        Severity.low: "cyan",
        Severity.info: "dim",
    }

    for f in result.findings:
        colour = _sev_colour.get(f.severity, "white")
        affected = str(len(f.affected_principals)) if f.affected_principals else "-"
        conf = f"{f.confidence:.0%}" if f.confidence < 1.0 else "100%"
        priority = f.priority or {}
        owner = f.owner or {}
        owners = owner.get("names", [])
        owner_text = (
            ", ".join(str(item) for item in owners) if isinstance(owners, list) else str(owners)
        )
        table.add_row(
            f.id,
            f"[{colour}]{f.severity.emoji} {f.severity.value}[/{colour}]",
            f"{priority.get('band', '-')}/{priority.get('score', '-')}",
            f.title,
            owner_text,
            affected,
            conf,
        )

    console.print(table)

    score = result.posture_score
    score_colour = "green" if score >= 80 else ("yellow" if score >= 50 else "red")
    console.print(
        Panel.fit(
            f"Posture score : [{score_colour}][bold]{score}/100[/bold][/{score_colour}]\n"
            + result.summary_line()
            + "\n"
            + f"[dim]Analysis completed in {result.elapsed_seconds:.1f}s[/dim]",
            title="Analysis complete",
            border_style=score_colour,
        )
    )


# ===========================================================================
# scan-all - MSP portfolio mode
# ===========================================================================


@app.command(name="scan-all")
def scan_all(
    tenants_file: str = typer.Option(..., "--tenants", "-t", help="Path to tenants YAML file."),
    out: str = typer.Option("./snapshot", "--out", "-o", help="Base directory for snapshots."),
    no_redact: bool = typer.Option(False, "--no-redact", help="Disable UPN hashing in snapshots."),
    concurrency: int = typer.Option(
        5, "--concurrency", help="Max parallel Graph requests per tenant."
    ),
    owners: str = typer.Option(
        "",
        "--owners",
        help="Path to owner mapping YAML file.",
    ),
    exceptions: str = typer.Option(
        "",
        "--exceptions",
        help="Path to exception tracking YAML file.",
    ),
) -> None:
    """Scan multiple tenants from a YAML file (MSP portfolio mode).

    Tenants are scanned sequentially.  After all tenants complete, a
    portfolio.html summary report is written to the snapshot base directory.

    Example tenants.yaml::

        tenants:
          - id: contoso.onmicrosoft.com
            name: Contoso Ltd
            auth_mode: delegated
            client_id: "00000000-0000-0000-0000-000000000000"

          - id: fabrikam.onmicrosoft.com
            name: Fabrikam Inc
            auth_mode: app
            client_id: "00000000-0000-0000-0000-000000000000"
            cert_path: "/path/to/cert.pem"
    """
    try:
        from ca_radar.tenants.models import TenantsFile

        tenants = TenantsFile.from_yaml(tenants_file)
    except FileNotFoundError as exc:
        console.print(f"[bold red]Error:[/bold red] {exc}")
        raise typer.Exit(1) from exc
    except ValueError as exc:
        console.print(f"[bold red]Invalid tenants file:[/bold red] {exc}")
        raise typer.Exit(1) from exc

    if not tenants.tenants:
        console.print("[yellow]No tenants found in file - nothing to do.[/yellow]")
        raise typer.Exit(0)

    console.print(
        Panel.fit(
            f"[bold cyan]ca-radar[/bold cyan] [dim]v{__version__}[/dim]  {_BRANDING}\n"
            f"Tenants file : [bold]{tenants_file}[/bold]\n"
            f"Tenants      : [bold]{len(tenants.tenants)}[/bold]\n"
            f"Output       : [bold]{out}[/bold]",
            title="Portfolio scan starting",
            border_style="cyan",
        )
    )

    completed: list[dict] = []
    failed: list[str] = []

    for i, tc in enumerate(tenants.tenants, 1):
        console.rule(f"[bold cyan]Tenant {i}/{len(tenants.tenants)}: {tc.display_name}[/bold cyan]")
        try:
            result = asyncio.run(
                _run_scan(
                    tenant=tc.id,
                    out=out,
                    auth_mode=tc.auth_mode,
                    client_id=tc.client_id,
                    cert_path=tc.cert_path,
                    client_secret=tc.client_secret,
                    redact=not no_redact,
                    concurrency=concurrency,
                    owners=owners,
                    exceptions=exceptions,
                )
            )
            completed.append(result)
        except KeyboardInterrupt:
            console.print("\n[yellow]Portfolio scan cancelled.[/yellow]")
            raise typer.Exit(1) from None
        except Exception as exc:
            console.print(f"[bold red]  Tenant {tc.id} failed:[/bold red] {exc}")
            failed.append(tc.id)

    # Portfolio report
    _render_portfolio(out, completed)

    # Final summary
    console.print(
        Panel.fit(
            f"[bold]Portfolio scan complete[/bold]\n"
            f"Succeeded : [bold green]{len(completed)}[/bold green]  "
            f"Failed : [bold {'red' if failed else 'green'}]{len(failed)}[/bold {'red' if failed else 'green'}]",
            border_style="green" if not failed else "yellow",
        )
    )
    if failed:
        raise typer.Exit(1)


def _render_portfolio(out: str, completed: list[dict]) -> None:
    """Render portfolio.html from trend data and print the path."""
    try:
        from datetime import UTC, datetime

        from ca_radar import __version__
        from ca_radar.render.html.portfolio_renderer import render_portfolio_report
        from ca_radar.trend.store import TrendStore

        trend = TrendStore(base_dir=out)
        rows = trend.load_portfolio_summary()

        # Wire in the relative report paths from this run
        report_map = {r["tenant_id"]: r["report_path"] for r in completed}
        for row in rows:
            row.report_path = report_map.get(row.tenant_id, "")

        html = render_portfolio_report(
            rows,
            captured_at=datetime.now(UTC),
            tool_version=__version__,
        )
        portfolio_path = Path(out) / "portfolio.html"
        portfolio_path.write_text(html, encoding="utf-8")
        console.print(f"\n[bold green]OK Portfolio report[/bold green]  {portfolio_path}")
    except Exception as exc:
        console.print(f"[yellow]  Portfolio render skipped: {exc}[/yellow]")


if __name__ == "__main__":
    app()
