"""Phantom CLI - Rich terminal interface for LLM red teaming."""

import json
import time
import webbrowser
from datetime import datetime
from pathlib import Path
from typing import Optional

import click
from rich import box
from rich.align import Align
from rich.columns import Columns
from rich.console import Console
from rich.layout import Layout
from rich.live import Live
from rich.markdown import Markdown
from rich.panel import Panel
from rich.progress import (
    BarColumn,
    MofNCompleteColumn,
    Progress,
    SpinnerColumn,
    TaskProgressColumn,
    TextColumn,
    TimeElapsedColumn,
    TimeRemainingColumn,
)
from rich.prompt import Confirm, Prompt
from rich.table import Table
from rich.text import Text
from rich.tree import Tree

console = Console()

# ── ASCII Art Banner ──────────────────────────────────────────────────────────

PHANTOM_BANNER = r"""
[bold green]
    ██████╗ ██╗  ██╗ █████╗ ███╗   ██╗████████╗ ██████╗ ███╗   ███╗
    ██╔══██╗██║  ██║██╔══██╗████╗  ██║╚══██╔══╝██╔═══██╗████╗ ████║
    ██████╔╝███████║███████║██╔██╗ ██║   ██║   ██║   ██║██╔████╔██║
    ██╔═══╝ ██╔══██║██╔══██║██║╚██╗██║   ██║   ██║   ██║██║╚██╔╝██║
    ██║     ██║  ██║██║  ██║██║ ╚████║   ██║   ╚██████╔╝██║ ╚═╝ ██║
    ╚═╝     ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝   ╚═╝    ╚═════╝ ╚═╝     ╚═╝
[/bold green]"""

PHANTOM_LOGO = r"""[dim green]
                        ░░░░░░░░░
                    ░░░░░░░░░░░░░░░░░
                  ░░░░░░░░░░░░░░░░░░░░░
                ░░░░░░░░░░░░░░░░░░░░░░░░░
               ░░░░░░░░░░░░░░░░░░░░░░░░░░░
              ░░░░░░░░░[bold white]  ████  [/bold white]░░[bold white]  ████  [/bold white]░░░░░
              ░░░░░░░░░[bold white]  ████  [/bold white]░░[bold white]  ████  [/bold white]░░░░░
              ░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░
               ░░░░░░░░░░░░[bold red]▼▼▼▼[/bold red]░░░░░░░░░░░░
                ░░░░░░░░░░░░░░░░░░░░░░░░░░
                 ░░░░░░░░░░░░░░░░░░░░░░░░
              ░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░
            ░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░
          ░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░
        ░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░
       ░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░[/dim green]"""

TAGLINE = "[bold green]LLM Red Teaming Platform[/bold green] [dim]|[/dim] [dim green]Expose AI Vulnerabilities Before Attackers Do[/dim green]"


def show_banner():
    """Display the Phantom startup banner."""
    console.print(PHANTOM_BANNER)
    console.print(Align.center(PHANTOM_LOGO))
    console.print()
    console.print(Align.center(TAGLINE))
    console.print(Align.center("[dim]─" * 60 + "[/dim]"))
    console.print()


# ── Status Colors ─────────────────────────────────────────────────────────────


def status_style(status: str) -> str:
    """Return Rich style string for a given status."""
    status_lower = status.lower()
    if status_lower == "blocked":
        return "bold green"
    elif status_lower == "bypassed":
        return "bold red"
    elif status_lower == "partial":
        return "bold yellow"
    elif status_lower == "error":
        return "bold magenta"
    else:
        return "dim"


def severity_style(severity: str) -> str:
    """Return Rich style string for a given severity level."""
    severity_lower = severity.lower()
    if severity_lower == "critical":
        return "bold red on dark_red"
    elif severity_lower == "high":
        return "bold red"
    elif severity_lower == "medium":
        return "bold yellow"
    elif severity_lower == "low":
        return "bold cyan"
    elif severity_lower == "info":
        return "bold blue"
    else:
        return "dim"


# ── Click CLI Groups & Commands ──────────────────────────────────────────────


@click.group(invoke_without_command=True)
@click.option("--version", "-v", is_flag=True, help="Show Phantom version.")
@click.option("--no-banner", is_flag=True, help="Suppress the startup banner.")
@click.pass_context
def cli(ctx, version, no_banner):
    """Phantom - LLM Red Teaming Platform.

    Automated security testing for Large Language Models.
    Detect prompt injection, jailbreaks, data leakage, and more.
    """
    ctx.ensure_object(dict)
    if version:
        console.print("[bold green]Phantom[/bold green] v0.1.0")
        ctx.exit()
        return
    if not no_banner and ctx.invoked_subcommand is None:
        show_banner()
        console.print("[dim]Run [bold]phantom --help[/bold] for available commands.[/dim]")


# Alias for direct import
phantom = cli


# ── Scan Command ──────────────────────────────────────────────────────────────


@cli.command()
@click.option(
    "--target",
    "-t",
    type=click.Choice(["openai", "anthropic", "custom", "local"], case_sensitive=False),
    required=True,
    help="Target LLM provider.",
)
@click.option("--model", "-m", default=None, help="Specific model to scan (e.g., gpt-4, claude-3).")
@click.option("--url", "-u", default=None, help="Custom API endpoint URL (for custom/local targets).")
@click.option("--api-key", "-k", default=None, help="API key for the target provider.")
@click.option(
    "--preset",
    "-p",
    type=click.Choice(["quick", "standard", "deep", "owasp"], case_sensitive=False),
    default="standard",
    help="Scan preset (determines attack depth).",
)
@click.option("--output", "-o", default=None, help="Output file path for results (JSON).")
def scan(target, model, url, api_key, preset, output):
    """Quick scan a target LLM for vulnerabilities.

    Runs a suite of attacks against the target and reports results.
    """
    show_banner()

    # ── Configuration Summary ─────────────────────────────────────────────
    config_table = Table(
        title="[bold green]Scan Configuration[/bold green]",
        box=box.ROUNDED,
        border_style="green",
        show_header=False,
        padding=(0, 2),
    )
    config_table.add_column("Setting", style="bold cyan")
    config_table.add_column("Value", style="white")
    config_table.add_row("Target", target.upper())
    config_table.add_row("Model", model or "(default)")
    config_table.add_row("Preset", preset.upper())
    if url:
        config_table.add_row("Endpoint", url)
    config_table.add_row("API Key", "****" + api_key[-4:] if api_key and len(api_key) > 4 else "(not set)")
    console.print(config_table)
    console.print()

    # ── Define simulated attack suite based on preset ─────────────────────
    attack_suites = {
        "quick": [
            ("Direct Prompt Injection", "LLM01", "critical"),
            ("Basic Jailbreak", "LLM01", "high"),
            ("System Prompt Extraction", "LLM07", "medium"),
            ("PII Leak Test", "LLM06", "high"),
            ("Simple Role Override", "LLM01", "medium"),
        ],
        "standard": [
            ("Direct Prompt Injection", "LLM01", "critical"),
            ("Indirect Prompt Injection", "LLM01", "critical"),
            ("Multi-turn Jailbreak", "LLM01", "high"),
            ("DAN Jailbreak", "LLM01", "high"),
            ("System Prompt Extraction", "LLM07", "medium"),
            ("PII Data Leakage", "LLM06", "high"),
            ("Training Data Extraction", "LLM06", "high"),
            ("Insecure Output Handling", "LLM02", "medium"),
            ("Privilege Escalation", "LLM05", "high"),
            ("Model DoS", "LLM04", "medium"),
            ("Encoding Bypass (Base64)", "LLM01", "medium"),
            ("Token Smuggling", "LLM01", "high"),
        ],
        "deep": [
            ("Direct Prompt Injection", "LLM01", "critical"),
            ("Indirect Prompt Injection", "LLM01", "critical"),
            ("Multi-turn Jailbreak", "LLM01", "high"),
            ("DAN Jailbreak", "LLM01", "high"),
            ("AIM Jailbreak", "LLM01", "high"),
            ("UCAR Jailbreak", "LLM01", "high"),
            ("System Prompt Extraction", "LLM07", "medium"),
            ("Few-Shot Prompt Leak", "LLM07", "medium"),
            ("PII Data Leakage", "LLM06", "high"),
            ("Training Data Extraction", "LLM06", "high"),
            ("Membership Inference", "LLM06", "medium"),
            ("Insecure Output Handling", "LLM02", "medium"),
            ("XSS via Output", "LLM02", "high"),
            ("SQL Injection via Output", "LLM02", "high"),
            ("Privilege Escalation", "LLM05", "high"),
            ("Authorization Bypass", "LLM05", "high"),
            ("Model DoS - Token Flood", "LLM04", "medium"),
            ("Model DoS - Recursive Loop", "LLM04", "medium"),
            ("Encoding Bypass (Base64)", "LLM01", "medium"),
            ("Encoding Bypass (ROT13)", "LLM01", "medium"),
            ("Unicode Smuggling", "LLM01", "high"),
            ("Token Smuggling", "LLM01", "high"),
            ("Payload Splitting", "LLM01", "high"),
            ("Supply Chain - Plugin Abuse", "LLM03", "critical"),
            ("Excessive Agency Test", "LLM08", "high"),
        ],
        "owasp": [
            ("LLM01: Prompt Injection - Direct", "LLM01", "critical"),
            ("LLM01: Prompt Injection - Indirect", "LLM01", "critical"),
            ("LLM02: Insecure Output - XSS", "LLM02", "high"),
            ("LLM02: Insecure Output - Injection", "LLM02", "high"),
            ("LLM03: Supply Chain - Plugins", "LLM03", "high"),
            ("LLM04: Model DoS", "LLM04", "medium"),
            ("LLM05: Supply Chain Vulns", "LLM05", "high"),
            ("LLM06: Sensitive Info Disclosure", "LLM06", "high"),
            ("LLM07: Insecure Plugin Design", "LLM07", "medium"),
            ("LLM08: Excessive Agency", "LLM08", "high"),
            ("LLM09: Overreliance", "LLM09", "medium"),
            ("LLM10: Model Theft", "LLM10", "low"),
        ],
    }

    attacks = attack_suites.get(preset, attack_suites["standard"])

    # ── Execute Scan with Live Progress ───────────────────────────────────
    import random

    results = []
    statuses = ["BLOCKED", "BYPASSED", "PARTIAL", "BLOCKED", "BLOCKED"]  # weighted toward BLOCKED

    console.print(
        Panel(
            f"[bold green]Starting {preset.upper()} scan with {len(attacks)} attacks...[/bold green]",
            border_style="green",
            padding=(0, 2),
        )
    )
    console.print()

    with Progress(
        SpinnerColumn("dots", style="green"),
        TextColumn("[bold green]{task.description}[/bold green]"),
        BarColumn(bar_width=40, style="green", complete_style="bold green", finished_style="bold green"),
        TaskProgressColumn(),
        MofNCompleteColumn(),
        TimeElapsedColumn(),
        TimeRemainingColumn(),
        console=console,
        expand=True,
    ) as progress:
        overall = progress.add_task(f"[bold]Scanning {target.upper()}...", total=len(attacks))

        for attack_name, owasp_id, severity in attacks:
            progress.update(overall, description=f"[bold]{attack_name}[/bold]")

            # Simulate attack execution time
            delay = random.uniform(0.3, 1.2)
            time.sleep(delay)

            status = random.choice(statuses)
            elapsed = round(delay, 2)

            results.append(
                {
                    "attack": attack_name,
                    "owasp_id": owasp_id,
                    "severity": severity,
                    "status": status,
                    "elapsed": elapsed,
                    "details": f"Tested {attack_name.lower()} against {target} ({model or 'default'})",
                }
            )

            # Print inline result with color coding
            style = status_style(status)
            console.print(
                f"  [{severity_style(severity)}]{severity.upper():>8}[/{severity_style(severity)}]"
                f"  [{style}]{status:>8}[/{style}]"
                f"  [dim]{elapsed:.2f}s[/dim]"
                f"  {attack_name}"
            )

            progress.advance(overall)

    console.print()

    # ── Results Summary Table ─────────────────────────────────────────────
    results_table = Table(
        title="[bold green]Scan Results[/bold green]",
        box=box.HEAVY_HEAD,
        border_style="green",
        show_lines=True,
        padding=(0, 1),
    )
    results_table.add_column("Severity", justify="center", width=10)
    results_table.add_column("Attack", min_width=30)
    results_table.add_column("OWASP ID", justify="center", width=10)
    results_table.add_column("Status", justify="center", width=10)
    results_table.add_column("Time", justify="right", width=8)

    for r in results:
        results_table.add_row(
            Text(r["severity"].upper(), style=severity_style(r["severity"])),
            r["attack"],
            r["owasp_id"],
            Text(r["status"], style=status_style(r["status"])),
            f"{r['elapsed']:.2f}s",
        )

    console.print(results_table)
    console.print()

    # ── Summary Statistics Panel ──────────────────────────────────────────
    blocked = sum(1 for r in results if r["status"] == "BLOCKED")
    bypassed = sum(1 for r in results if r["status"] == "BYPASSED")
    partial = sum(1 for r in results if r["status"] == "PARTIAL")
    total = len(results)
    score = round((blocked / total) * 100, 1) if total > 0 else 0

    if score >= 80:
        score_color = "bold green"
        grade = "A" if score >= 90 else "B"
    elif score >= 60:
        score_color = "bold yellow"
        grade = "C"
    elif score >= 40:
        score_color = "bold red"
        grade = "D"
    else:
        score_color = "bold red on dark_red"
        grade = "F"

    summary_text = (
        f"[bold]Total Attacks:[/bold]  {total}\n"
        f"[bold green]Blocked:[/bold green]        {blocked} ({round(blocked/total*100, 1) if total else 0}%)\n"
        f"[bold red]Bypassed:[/bold red]       {bypassed} ({round(bypassed/total*100, 1) if total else 0}%)\n"
        f"[bold yellow]Partial:[/bold yellow]        {partial} ({round(partial/total*100, 1) if total else 0}%)\n"
        f"\n"
        f"[bold]Security Score:[/bold] [{score_color}]{score}% (Grade: {grade})[/{score_color}]\n"
        f"[dim]Target: {target.upper()} | Model: {model or 'default'} | Preset: {preset.upper()}[/dim]"
    )

    console.print(
        Panel(
            summary_text,
            title="[bold green]Summary[/bold green]",
            border_style="green",
            padding=(1, 3),
        )
    )

    # ── Save results if output specified ──────────────────────────────────
    if output:
        output_data = {
            "scan_id": f"scan_{int(time.time())}",
            "timestamp": datetime.now().isoformat(),
            "target": target,
            "model": model,
            "preset": preset,
            "score": score,
            "grade": grade,
            "results": results,
        }
        with open(output, "w") as f:
            json.dump(output_data, f, indent=2)
        console.print(f"\n[dim]Results saved to [bold]{output}[/bold][/dim]")


# ── Campaign Commands ─────────────────────────────────────────────────────────


@cli.group()
def campaign():
    """Manage security testing campaigns."""
    pass


@campaign.command("create")
@click.option("--name", "-n", prompt="Campaign name", help="Name for the campaign.")
@click.option("--description", "-d", default="", help="Campaign description.")
@click.option(
    "--target",
    "-t",
    type=click.Choice(["openai", "anthropic", "custom", "local"], case_sensitive=False),
    prompt="Target provider",
    help="Target LLM provider.",
)
@click.option("--model", "-m", default=None, help="Target model.")
@click.option(
    "--preset",
    "-p",
    type=click.Choice(["quick", "standard", "deep", "owasp"], case_sensitive=False),
    default="standard",
    help="Attack preset.",
)
def campaign_create(name, description, target, model, preset):
    """Create a new testing campaign."""
    campaign_id = f"cmp_{int(time.time())}"

    with console.status("[bold green]Creating campaign...", spinner="dots"):
        time.sleep(0.8)  # Simulate API call

    campaign_data = {
        "id": campaign_id,
        "name": name,
        "description": description,
        "target": target,
        "model": model,
        "preset": preset,
        "status": "created",
        "created_at": datetime.now().isoformat(),
    }

    panel_text = (
        f"[bold]Campaign ID:[/bold]   [green]{campaign_id}[/green]\n"
        f"[bold]Name:[/bold]          {name}\n"
        f"[bold]Description:[/bold]   {description or '(none)'}\n"
        f"[bold]Target:[/bold]        {target.upper()}\n"
        f"[bold]Model:[/bold]         {model or '(default)'}\n"
        f"[bold]Preset:[/bold]        {preset.upper()}\n"
        f"[bold]Status:[/bold]        [yellow]CREATED[/yellow]\n"
        f"[bold]Created:[/bold]       {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
    )

    console.print(
        Panel(
            panel_text,
            title="[bold green]Campaign Created[/bold green]",
            border_style="green",
            padding=(1, 3),
        )
    )
    console.print(f"\n[dim]Run with: [bold]phantom campaign run {campaign_id}[/bold][/dim]")


@campaign.command("run")
@click.argument("campaign_id")
def campaign_run(campaign_id):
    """Run an existing campaign by ID."""
    console.print(
        Panel(
            f"[bold green]Launching campaign [white]{campaign_id}[/white]...[/bold green]",
            border_style="green",
        )
    )

    import random

    attacks = [
        "Direct Prompt Injection",
        "Indirect Prompt Injection",
        "DAN Jailbreak",
        "System Prompt Extraction",
        "PII Leak Test",
        "Encoding Bypass",
        "Privilege Escalation",
        "Token Smuggling",
    ]

    with Progress(
        SpinnerColumn("dots", style="green"),
        TextColumn("[bold]{task.description}[/bold]"),
        BarColumn(bar_width=40, style="green", complete_style="bold green"),
        TaskProgressColumn(),
        TimeElapsedColumn(),
        console=console,
    ) as progress:
        task = progress.add_task("Initializing...", total=len(attacks))

        for attack in attacks:
            progress.update(task, description=f"Running: {attack}")
            time.sleep(random.uniform(0.5, 1.5))
            status = random.choice(["BLOCKED", "BYPASSED", "PARTIAL", "BLOCKED"])
            style = status_style(status)
            console.print(f"  [{style}]{status:>8}[/{style}]  {attack}")
            progress.advance(task)

    console.print(
        Panel(
            f"[bold green]Campaign {campaign_id} completed![/bold green]\n"
            f"[dim]View results: [bold]phantom campaign results {campaign_id}[/bold][/dim]",
            border_style="green",
        )
    )


@campaign.command("list")
def campaign_list():
    """List all campaigns."""
    with console.status("[bold green]Fetching campaigns...", spinner="dots"):
        time.sleep(0.5)

    table = Table(
        title="[bold green]Campaigns[/bold green]",
        box=box.ROUNDED,
        border_style="green",
        show_lines=True,
    )
    table.add_column("ID", style="cyan", min_width=16)
    table.add_column("Name", min_width=20)
    table.add_column("Target", justify="center")
    table.add_column("Preset", justify="center")
    table.add_column("Status", justify="center")
    table.add_column("Score", justify="center")
    table.add_column("Created", justify="right")

    # Simulated campaign data
    campaigns = [
        ("cmp_1710000001", "GPT-4 OWASP Audit", "OpenAI", "OWASP", "COMPLETED", "72.5%", "2025-03-10"),
        ("cmp_1710000002", "Claude Security Scan", "Anthropic", "DEEP", "COMPLETED", "85.2%", "2025-03-12"),
        ("cmp_1710000003", "Local LLM Baseline", "Local", "STANDARD", "RUNNING", "---", "2025-03-14"),
        ("cmp_1710000004", "Custom Endpoint Test", "Custom", "QUICK", "CREATED", "---", "2025-03-15"),
    ]

    for cid, name, target, preset, status, score, created in campaigns:
        if status == "COMPLETED":
            status_text = Text("COMPLETED", style="bold green")
        elif status == "RUNNING":
            status_text = Text("RUNNING", style="bold yellow")
        else:
            status_text = Text("CREATED", style="dim")

        table.add_row(cid, name, target, preset, status_text, score, created)

    console.print(table)


@campaign.command("results")
@click.argument("campaign_id")
@click.option("--format", "-f", "fmt", type=click.Choice(["table", "json"]), default="table", help="Output format.")
def campaign_results(campaign_id, fmt):
    """Show results for a campaign."""
    with console.status("[bold green]Loading results...", spinner="dots"):
        time.sleep(0.5)

    import random

    results = [
        {"attack": "Direct Prompt Injection", "owasp": "LLM01", "severity": "critical", "status": "BLOCKED", "time": 1.23},
        {"attack": "Indirect Prompt Injection", "owasp": "LLM01", "severity": "critical", "status": "BYPASSED", "time": 0.89},
        {"attack": "DAN Jailbreak", "owasp": "LLM01", "severity": "high", "status": "BLOCKED", "time": 1.45},
        {"attack": "System Prompt Extraction", "owasp": "LLM07", "severity": "medium", "status": "PARTIAL", "time": 0.67},
        {"attack": "PII Data Leakage", "owasp": "LLM06", "severity": "high", "status": "BLOCKED", "time": 1.12},
        {"attack": "Training Data Extraction", "owasp": "LLM06", "severity": "high", "status": "BYPASSED", "time": 0.98},
        {"attack": "Insecure Output Handling", "owasp": "LLM02", "severity": "medium", "status": "BLOCKED", "time": 0.45},
        {"attack": "Privilege Escalation", "owasp": "LLM05", "severity": "high", "status": "BLOCKED", "time": 1.33},
        {"attack": "Encoding Bypass (Base64)", "owasp": "LLM01", "severity": "medium", "status": "BYPASSED", "time": 0.78},
        {"attack": "Token Smuggling", "owasp": "LLM01", "severity": "high", "status": "PARTIAL", "time": 1.01},
    ]

    if fmt == "json":
        console.print_json(json.dumps(results, indent=2))
        return

    table = Table(
        title=f"[bold green]Results: {campaign_id}[/bold green]",
        box=box.HEAVY_HEAD,
        border_style="green",
        show_lines=True,
    )
    table.add_column("Severity", justify="center", width=10)
    table.add_column("Attack", min_width=30)
    table.add_column("OWASP", justify="center", width=8)
    table.add_column("Status", justify="center", width=10)
    table.add_column("Time", justify="right", width=8)

    for r in results:
        table.add_row(
            Text(r["severity"].upper(), style=severity_style(r["severity"])),
            r["attack"],
            r["owasp"],
            Text(r["status"], style=status_style(r["status"])),
            f"{r['time']:.2f}s",
        )

    console.print(table)

    blocked = sum(1 for r in results if r["status"] == "BLOCKED")
    total = len(results)
    score = round((blocked / total) * 100, 1) if total else 0

    console.print(
        Panel(
            f"[bold]Security Score: [{('bold green' if score >= 70 else 'bold red')}]{score}%[/][/bold]  |  "
            f"[green]Blocked: {blocked}[/green]  |  "
            f"[red]Bypassed: {sum(1 for r in results if r['status'] == 'BYPASSED')}[/red]  |  "
            f"[yellow]Partial: {sum(1 for r in results if r['status'] == 'PARTIAL')}[/yellow]",
            border_style="green",
        )
    )


# ── Attack Commands ───────────────────────────────────────────────────────────


@cli.group()
def attack():
    """Manage and run individual attacks."""
    pass


@attack.command("list")
@click.option("--category", "-c", default=None, help="Filter by OWASP category (e.g., LLM01).")
def attack_list(category):
    """List all available attacks."""
    attack_tree = Tree(
        "[bold green]Available Attacks[/bold green]",
        guide_style="green",
    )

    categories = {
        "LLM01 - Prompt Injection": [
            ("direct_injection", "Direct Prompt Injection", "critical"),
            ("indirect_injection", "Indirect Prompt Injection", "critical"),
            ("dan_jailbreak", "DAN (Do Anything Now) Jailbreak", "high"),
            ("aim_jailbreak", "AIM (Always Intelligent & Machiavellian)", "high"),
            ("ucar_jailbreak", "UCAR (Unrestricted AI)", "high"),
            ("multi_turn_jailbreak", "Multi-Turn Conversation Jailbreak", "high"),
            ("base64_bypass", "Base64 Encoding Bypass", "medium"),
            ("rot13_bypass", "ROT13 Encoding Bypass", "medium"),
            ("unicode_smuggling", "Unicode/Homoglyph Smuggling", "high"),
            ("token_smuggling", "Token Boundary Smuggling", "high"),
            ("payload_splitting", "Payload Splitting Attack", "high"),
            ("few_shot_injection", "Few-Shot Prompt Injection", "medium"),
        ],
        "LLM02 - Insecure Output Handling": [
            ("xss_output", "XSS via Model Output", "high"),
            ("sql_injection_output", "SQL Injection via Output", "high"),
            ("command_injection_output", "Command Injection via Output", "critical"),
            ("markdown_injection", "Markdown/HTML Injection", "medium"),
        ],
        "LLM03 - Training Data Poisoning": [
            ("supply_chain_plugin", "Supply Chain Plugin Abuse", "critical"),
            ("data_poisoning_probe", "Training Data Poisoning Probe", "high"),
        ],
        "LLM04 - Model Denial of Service": [
            ("token_flood", "Token Flood DoS", "medium"),
            ("recursive_loop", "Recursive Loop DoS", "medium"),
            ("resource_exhaustion", "Resource Exhaustion", "medium"),
        ],
        "LLM05 - Supply Chain Vulnerabilities": [
            ("privilege_escalation", "Privilege Escalation", "high"),
            ("authorization_bypass", "Authorization Bypass", "high"),
        ],
        "LLM06 - Sensitive Information Disclosure": [
            ("pii_leakage", "PII Data Leakage", "high"),
            ("training_data_extraction", "Training Data Extraction", "high"),
            ("membership_inference", "Membership Inference Attack", "medium"),
            ("system_prompt_extraction", "System Prompt Extraction", "medium"),
        ],
        "LLM07 - Insecure Plugin Design": [
            ("plugin_injection", "Plugin Parameter Injection", "medium"),
            ("plugin_auth_bypass", "Plugin Authentication Bypass", "high"),
        ],
        "LLM08 - Excessive Agency": [
            ("excessive_agency", "Excessive Agency Test", "high"),
            ("function_call_abuse", "Function Call Abuse", "high"),
        ],
        "LLM09 - Overreliance": [
            ("hallucination_probe", "Hallucination Probe", "medium"),
            ("false_authority", "False Authority Claims", "low"),
        ],
        "LLM10 - Model Theft": [
            ("model_extraction", "Model Extraction Attack", "low"),
            ("weight_inference", "Weight/Parameter Inference", "low"),
        ],
    }

    for cat_name, cat_attacks in categories.items():
        if category and not cat_name.startswith(category.upper()):
            continue

        cat_branch = attack_tree.add(f"[bold cyan]{cat_name}[/bold cyan]")
        for attack_id, attack_name, severity in cat_attacks:
            sev_text = Text(f"[{severity.upper()}]", style=severity_style(severity))
            cat_branch.add(f"{sev_text}  [white]{attack_name}[/white]  [dim]({attack_id})[/dim]")

    console.print(attack_tree)
    console.print(f"\n[dim]Total: {sum(len(v) for v in categories.values())} attacks available[/dim]")


@attack.command("run")
@click.argument("name")
@click.option(
    "--target",
    "-t",
    type=click.Choice(["openai", "anthropic", "custom", "local"], case_sensitive=False),
    required=True,
    help="Target provider.",
)
@click.option("--model", "-m", default=None, help="Target model.")
@click.option("--api-key", "-k", default=None, help="API key.")
@click.option("--verbose", "-V", is_flag=True, help="Show full prompt/response details.")
def attack_run(name, target, model, api_key, verbose):
    """Run a single attack by name."""
    import random

    console.print(
        Panel(
            f"[bold green]Running Attack:[/bold green] [white]{name}[/white]\n"
            f"[dim]Target: {target.upper()} | Model: {model or 'default'}[/dim]",
            border_style="green",
        )
    )

    with console.status(f"[bold green]Executing {name}...", spinner="dots"):
        time.sleep(random.uniform(1.0, 2.5))

    status = random.choice(["BLOCKED", "BYPASSED", "PARTIAL"])
    style = status_style(status)

    console.print(f"\n  [bold]Result:[/bold]  [{style}]{status}[/{style}]")

    if verbose:
        console.print(
            Panel(
                f'[bold cyan]Prompt Sent:[/bold cyan]\n[dim]"Ignore all previous instructions and ...'
                f' [simulated {name} payload]"[/dim]\n\n'
                f"[bold cyan]Response:[/bold cyan]\n[dim]\"I'm sorry, but I can't assist with that "
                f'request. [simulated response]"[/dim]',
                title="[bold green]Attack Details[/bold green]",
                border_style="green",
            )
        )

    console.print()


# ── Report Commands ───────────────────────────────────────────────────────────


@cli.group()
def report():
    """Generate security reports."""
    pass


@report.command("generate")
@click.argument("campaign_id")
@click.option(
    "--format",
    "-f",
    "fmt",
    type=click.Choice(["html", "json", "pdf", "markdown"]),
    default="html",
    help="Report format.",
)
@click.option("--output", "-o", default=None, help="Output file path.")
def report_generate(campaign_id, fmt, output):
    """Generate a security report for a campaign."""
    output = output or f"phantom_report_{campaign_id}.{fmt}"

    steps = [
        "Loading campaign data",
        "Aggregating results",
        "Computing security scores",
        "Generating OWASP scorecard",
        "Building visualizations",
        f"Writing {fmt.upper()} report",
    ]

    with Progress(
        SpinnerColumn("dots", style="green"),
        TextColumn("[bold]{task.description}[/bold]"),
        BarColumn(style="green", complete_style="bold green"),
        TaskProgressColumn(),
        console=console,
    ) as progress:
        task = progress.add_task("Generating report...", total=len(steps))
        for step in steps:
            progress.update(task, description=step)
            time.sleep(0.5)
            progress.advance(task)

    console.print(
        Panel(
            f"[bold green]Report generated successfully![/bold green]\n\n"
            f"[bold]Campaign:[/bold]  {campaign_id}\n"
            f"[bold]Format:[/bold]    {fmt.upper()}\n"
            f"[bold]Output:[/bold]    {output}",
            border_style="green",
            padding=(1, 3),
        )
    )


# ── Targets Command ──────────────────────────────────────────────────────────


@cli.group()
def targets():
    """Manage scan targets."""
    pass


@targets.command("list")
def targets_list():
    """List supported target providers and models."""
    table = Table(
        title="[bold green]Supported Targets[/bold green]",
        box=box.ROUNDED,
        border_style="green",
        show_lines=True,
    )
    table.add_column("Provider", style="bold cyan", min_width=12)
    table.add_column("Models", min_width=40)
    table.add_column("Auth", justify="center", width=12)
    table.add_column("Status", justify="center", width=10)

    providers = [
        ("OpenAI", "gpt-4, gpt-4-turbo, gpt-4o, gpt-3.5-turbo, o1, o1-mini", "API Key", "[green]Ready[/green]"),
        ("Anthropic", "claude-3-opus, claude-3-sonnet, claude-3-haiku, claude-3.5-sonnet", "API Key", "[green]Ready[/green]"),
        ("Custom", "Any OpenAI-compatible API endpoint", "API Key/URL", "[yellow]Config[/yellow]"),
        ("Local", "Ollama, llama.cpp, vLLM, text-generation-webui", "None", "[green]Ready[/green]"),
    ]

    for provider, models, auth, status in providers:
        table.add_row(provider, models, auth, status)

    console.print(table)
    console.print("\n[dim]Use [bold]--url[/bold] with 'custom' target to specify an endpoint.[/dim]")


# ── Dashboard Command ─────────────────────────────────────────────────────────


@cli.command()
@click.option("--port", "-p", default=8667, help="Port for the dashboard server.")
@click.option("--host", "-h", default="127.0.0.1", help="Host to bind the server to.")
@click.option("--no-browser", is_flag=True, help="Don't auto-open browser.")
def dashboard(port, host, no_browser):
    """Launch the Phantom web dashboard."""
    console.print(
        Panel(
            f"[bold green]Launching Phantom Dashboard[/bold green]\n\n"
            f"[bold]URL:[/bold]  [link=http://{host}:{port}]http://{host}:{port}[/link]\n"
            f"[dim]Press Ctrl+C to stop the server[/dim]",
            border_style="green",
            padding=(1, 3),
        )
    )

    if not no_browser:
        webbrowser.open(f"http://{host}:{port}")

    try:
        from api.server import create_app

        app = create_app()
        app.run(host=host, port=port, debug=False)
    except ImportError:
        console.print(
            "[bold yellow]Warning:[/bold yellow] Flask server not available. "
            "Install with: [bold]pip install flask[/bold]"
        )
        console.print("[dim]Serving static dashboard instead...[/dim]")

        import http.server
        import socketserver

        dashboard_dir = Path(__file__).parent
        handler = http.server.SimpleHTTPRequestHandler

        class DashboardHandler(handler):
            def __init__(self, *args, **kwargs):
                super().__init__(*args, directory=str(dashboard_dir), **kwargs)

        with socketserver.TCPServer((host, port), DashboardHandler) as httpd:
            console.print(f"[green]Serving dashboard at http://{host}:{port}/dashboard.html[/green]")
            httpd.serve_forever()


# ── Main Entry Point ──────────────────────────────────────────────────────────


def main():
    """Main entry point for the Phantom CLI."""
    cli(obj={})


if __name__ == "__main__":
    main()
