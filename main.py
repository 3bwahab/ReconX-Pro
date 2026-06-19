# main.py
#!/usr/bin/env python3
"""
ReconX-Pro - Elite Reconnaissance Framework
Main entry point for the application.
"""

import sys
import argparse
import signal
from pathlib import Path

from rich.console import Console
from rich.panel import Panel
from rich.text import Text
from rich.prompt import Prompt, IntPrompt
from rich.table import Table
from rich import box

from core.config import ConfigManager
from core.runner import ReconRunner
from utils.logger import setup_logger

console = Console()
logger = setup_logger("reconx.main")

BANNER = r"""
____________________________________________________________________
║                                                                  ║
║                         3bwahab                                  ║
║                                                                  ║
║          Elite Reconnaissance Framework v2.0                     ║
║          Professional Bug Bounty & Pentest Toolkit               ║
║                                                                  ║
╚══════════════════════════════════════════════════════════════════╝
"""


def signal_handler(sig, frame):
    """Handle graceful shutdown on CTRL+C."""
    console.print("\n[bold yellow]⚠ Scan interrupted by user. Cleaning up...[/]")
    sys.exit(0)


signal.signal(signal.SIGINT, signal_handler)


def display_banner():
    """Display the application banner."""
    console.print(BANNER, style="bold cyan")


def display_api_status(config: ConfigManager):
    """Show which API keys are configured."""
    table = Table(
        title="🔑 API Key Status",
        box=box.SIMPLE,
        border_style="dim",
        title_style="bold cyan",
        show_header=True,
        header_style="bold white",
    )
    table.add_column("Service", style="white", width=20)
    table.add_column("Status", width=15)

    display_names = {
        "shodan": "Shodan",
        "censys_token": "Censys",
        "virustotal": "VirusTotal",
        "securitytrails": "SecurityTrails",
        "chaos": "Chaos (PD)",
        "github_token": "GitHub",
        "builtwith": "BuiltWith",
    }

    key_status = config.get_all_api_keys_status()
    for key, configured in key_status.items():
        name = display_names.get(key, key)
        if configured:
            table.add_row(name, "[bold green]✓ Active[/]")
        else:
            table.add_row(name, "[dim red]✗ Missing[/]")

    console.print(table)


def display_menu():
    """Display the main reconnaissance menu."""
    table = Table(
        title="Reconnaissance Modes",
        box=box.ROUNDED,
        title_style="bold magenta",
        border_style="cyan",
        show_header=True,
        header_style="bold white",
    )
    table.add_column("Option", style="bold yellow", justify="center", width=8)
    table.add_column("Mode", style="bold white", width=25)
    table.add_column("Description", style="dim white", width=55)

    table.add_row(
        "1",
        "🔍 Passive Reconnaissance",
        "WHOIS, DNS, Subdomains, CT, Shodan, Censys, VT, "
        "SecurityTrails, Chaos, GitHub, BuiltWith, Wayback, ASN",
    )
    table.add_row(
        "2",
        "⚔️  Active Reconnaissance",
        "Live hosts, Ports, Dir fuzzing, Headers, Tech detection, Screenshots",
    )
    table.add_row(
        "3",
        "🚀 Full Reconnaissance",
        "Run both passive and active recon sequentially",
    )
    table.add_row("0", "❌ Exit", "Quit the application")

    console.print(table)


def validate_domain(domain: str) -> str:
    """Validate and clean the target domain."""
    domain = domain.strip().lower()
    domain = domain.replace("http://", "").replace("https://", "")
    domain = domain.rstrip("/")

    if not domain or "." not in domain:
        raise ValueError(f"Invalid domain format: {domain}")

    return domain


def parse_arguments() -> argparse.Namespace:
    """Parse command-line arguments for non-interactive mode."""
    parser = argparse.ArgumentParser(
        description="ReconX-Pro - Elite Reconnaissance Framework",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "-d", "--domain", type=str, help="Target domain (e.g., example.com)"
    )
    parser.add_argument(
        "-m",
        "--mode",
        type=int,
        choices=[1, 2, 3],
        help="Recon mode: 1=Passive, 2=Active, 3=Full",
    )
    parser.add_argument(
        "-c",
        "--config",
        type=str,
        default="config.yaml",
        help="Path to config file (default: config.yaml)",
    )
    parser.add_argument(
        "-o",
        "--output",
        type=str,
        default="reports",
        help="Output directory for reports (default: reports/)",
    )
    parser.add_argument(
        "-t",
        "--threads",
        type=int,
        default=10,
        help="Number of concurrent threads (default: 10)",
    )
    parser.add_argument(
        "--json-only",
        action="store_true",
        help="Generate only JSON report (skip HTML)",
    )
    parser.add_argument(
        "--passive-only",
        action="store_true",
        help="Alias for -m 1",
    )
    parser.add_argument(
        "--active-only",
        action="store_true",
        help="Alias for -m 2",
    )

    return parser.parse_args()


def interactive_mode(config: ConfigManager):
    """Run the tool in interactive mode."""
    display_banner()
    display_api_status(config)
    console.print()

    target = Prompt.ask(
        "[bold green]🎯 Enter target domain[/]",
        default="example.com",
    )

    try:
        target = validate_domain(target)
    except ValueError as e:
        console.print(f"[bold red]✗ {e}[/]")
        sys.exit(1)

    console.print(
        f"\n[bold green]✓ Target validated:[/] [bold white]{target}[/]\n"
    )

    display_menu()

    mode = IntPrompt.ask(
        "\n[bold green]Select reconnaissance mode[/]",
        choices=["0", "1", "2", "3"],
        default=1,
    )

    if mode == 0:
        console.print("[bold yellow]Goodbye! 👋[/]")
        sys.exit(0)

    return target, mode


def main():
    """Main entry point for ReconX-Pro."""
    args = parse_arguments()

    config = ConfigManager(args.config)

    if args.threads:
        config.set("general.threads", args.threads)
    if args.output:
        config.set("general.output_dir", args.output)
    if args.json_only:
        config.set("general.json_only", True)

    if args.domain and (args.mode or args.passive_only or args.active_only):
        target = validate_domain(args.domain)
        if args.passive_only:
            mode = 1
        elif args.active_only:
            mode = 2
        else:
            mode = args.mode
        display_banner()
        display_api_status(config)
        console.print(
            f"\n[bold green]✓ Target:[/] [bold white]{target}[/]"
        )
        mode_names = {1: "Passive", 2: "Active", 3: "Full"}
        console.print(
            f"[bold green]✓ Mode:[/] [bold white]{mode_names[mode]}[/]\n"
        )
    else:
        target, mode = interactive_mode(config)

    Path(config.get("general.output_dir", "reports")).mkdir(
        parents=True, exist_ok=True
    )

    runner = ReconRunner(target=target, mode=mode, config=config)
    runner.execute()


if __name__ == "__main__":
    main()