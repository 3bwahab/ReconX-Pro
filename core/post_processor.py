# core/post_processor.py
"""
Post-processing engine for ReconX-Pro.
Extracts subdomains and URLs from report.json,
probes them with httpx, and writes 4 clean output files.
"""

import json
import os
import subprocess
import tempfile
import urllib.parse
from pathlib import Path
from typing import List, Set, Dict

from rich.console import Console
from rich.table import Table
from rich import box

from utils.logger import setup_logger

console = Console()
logger = setup_logger("reconx.postprocessor")


class PostProcessor:
    """
    Reads report.json and produces 4 files:
      - all_subdomains.txt
      - alive_subdomains.txt
      - all_urls.txt
      - alive_urls.txt
    """

    def __init__(
        self,
        report_json_path: str,
        output_dir: str,
        config=None,
    ):
        self.report_json_path = Path(report_json_path)
        self.output_dir = Path(output_dir)
        self.config = config
        self.report_data: dict = {}

    # ══════════════════════════════════════════════════════════
    #  Load
    # ══════════════════════════════════════════════════════════

    def load_report(self) -> bool:
        try:
            with open(self.report_json_path, "r", encoding="utf-8") as f:
                self.report_data = json.load(f)
            logger.info(f"Loaded report: {self.report_json_path}")
            return True
        except Exception as e:
            logger.error(f"Failed to load report: {e}")
            console.print(f"[red]  ✗ Cannot load report.json: {e}[/]")
            return False

    # ══════════════════════════════════════════════════════════
    #  Extract subdomains
    # ══════════════════════════════════════════════════════════

    def extract_subdomains(self) -> List[str]:
        subs: Set[str] = set()
        summary = self.report_data.get("summary", {})

        # From summary.subdomains
        for s in summary.get("subdomains", []):
            if isinstance(s, str) and s.strip():
                subs.add(s.strip().lower())

        # From summary.live_hosts
        for host in summary.get("live_hosts", []):
            h = ""
            if isinstance(host, dict):
                h = host.get("host", "") or host.get("url", "")
            elif isinstance(host, str):
                h = host
            if h:
                extracted = self._host_from_url(h)
                if extracted:
                    subs.add(extracted)

        # Walk every module's data
        for mod_data in self.report_data.get("modules", {}).values():
            data = mod_data.get("data", {})
            if not data:
                continue

            for s in data.get("subdomains", []):
                if isinstance(s, str) and s.strip():
                    subs.add(s.strip().lower())

            for s in data.get("associated_domains", []):
                if isinstance(s, str) and s.strip():
                    subs.add(s.strip().lower())

            for host in data.get("hosts", []):
                if isinstance(host, dict):
                    for hn in host.get("hostnames", []):
                        if isinstance(hn, str) and hn.strip():
                            subs.add(hn.strip().lower())

        # Keep only valid hostnames
        cleaned = sorted(
            s for s in subs
            if s and "." in s and not s.startswith(".")
        )
        logger.info(f"Extracted {len(cleaned)} unique subdomains")
        return cleaned

    # ══════════════════════════════════════════════════════════
    #  Extract URLs
    # ══════════════════════════════════════════════════════════

    def extract_urls(self) -> List[str]:
        urls: Set[str] = set()
        summary = self.report_data.get("summary", {})

        # From summary.endpoints
        for ep in summary.get("endpoints", []):
            if isinstance(ep, str) and ep.strip().startswith("http"):
                urls.add(ep.strip())

        # From summary.live_hosts
        for host in summary.get("live_hosts", []):
            if isinstance(host, dict):
                u = host.get("url", "")
            else:
                u = str(host)
            if u and u.strip().startswith("http"):
                urls.add(u.strip())

        # Walk every module's data
        for mod_data in self.report_data.get("modules", {}).values():
            data = mod_data.get("data", {})
            if not data:
                continue

            # Direct url/endpoint lists
            for key in ("urls", "endpoints"):
                val = data.get(key, [])
                if isinstance(val, list):
                    for u in val:
                        if isinstance(u, str) and u.strip().startswith("http"):
                            urls.add(u.strip())

            # Directories (dir fuzzing results)
            for d in data.get("directories", []):
                if isinstance(d, dict):
                    u = d.get("url", "")
                elif isinstance(d, str):
                    u = d
                else:
                    u = ""
                if u and u.strip().startswith("http"):
                    urls.add(u.strip())

            # Wayback categories — can be dict OR list depending on module version
            categories = data.get("categories", {})
            if isinstance(categories, dict):
                # Expected format: {"js_files": [...], "api_endpoints": [...]}
                for cat_urls in categories.values():
                    if isinstance(cat_urls, list):
                        for u in cat_urls:
                            if isinstance(u, str) and u.strip().startswith("http"):
                                urls.add(u.strip())
            elif isinstance(categories, list):
                # Flat list format: ["https://...", "https://..."]
                for u in categories:
                    if isinstance(u, str) and u.strip().startswith("http"):
                        urls.add(u.strip())

        cleaned = sorted(urls)
        logger.info(f"Extracted {len(cleaned)} unique URLs")
        return cleaned

    # ══════════════════════════════════════════════════════════
    #  httpx probing
    # ══════════════════════════════════════════════════════════

    def _find_httpx(self) -> str:
        """Find httpx binary — check PATH and common Go install locations."""
        import shutil

        # 1. Already in PATH
        path = shutil.which("httpx")
        if path:
            return path

        # 2. Common Go binary locations
        home = Path.home()
        candidates = [
            home / "go" / "bin" / "httpx",
            home / "go" / "bin" / "httpx.exe",
            Path("C:/Users") / os.environ.get("USERNAME", "") / "go" / "bin" / "httpx.exe",
            Path("/usr/local/bin/httpx"),
            Path("/usr/bin/httpx"),
            Path("/home") / os.environ.get("USER", "") / "go" / "bin" / "httpx",
        ]
        for c in candidates:
            if c.exists():
                return str(c)

        return ""

    def probe_with_httpx(self, targets: List[str], label: str = "targets") -> List[str]:
        """
        Probe targets with httpx.
        Returns list of alive URLs (plain strings).
        """
        if not targets:
            return []

        httpx_bin = self._find_httpx()
        if not httpx_bin:
            console.print(
                "  [red]✗ httpx not found.[/] "
                "[dim]Install: go install github.com/projectdiscovery/httpx/cmd/httpx@latest[/]"
            )
            console.print(
                "  [dim]Add Go bin to PATH: "
                r"setx PATH '%PATH%;%USERPROFILE%\go\bin' (Windows)[/]"
            )
            return []

        # Write targets to temp file
        tmp = tempfile.NamedTemporaryFile(
            mode="w",
            suffix=".txt",
            delete=False,
            encoding="utf-8",
        )
        try:
            tmp.write("\n".join(targets))
            tmp.flush()
            tmp.close()

            rate = 150
            threads = 50
            timeout_sec = 10
            proc_timeout = max(600, len(targets) * 2)

            if self.config:
                rate = self.config.get("tools.httpx.rate_limit", 150)
                threads = min(self.config.threads * 5, 100)

            cmd = [
                httpx_bin,
                "-l", tmp.name,
                "-silent",
                "-no-color",
                "-timeout", str(timeout_sec),
                "-rate-limit", str(rate),
                "-threads", str(threads),
                "-retries", "1",
                "-follow-redirects",
            ]

            logger.info(
                f"Running httpx: {httpx_bin} on {len(targets)} {label}"
            )
            logger.debug(f"Command: {' '.join(cmd)}")

            try:
                proc = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=proc_timeout,
                    encoding="utf-8",
                    errors="replace",
                )

                logger.debug(f"httpx returncode: {proc.returncode}")
                logger.debug(f"httpx stderr: {proc.stderr[:500] if proc.stderr else 'none'}")

                alive = []
                if proc.stdout:
                    for line in proc.stdout.strip().split("\n"):
                        line = line.strip()
                        if line and (
                            line.startswith("http://") or
                            line.startswith("https://")
                        ):
                            alive.append(line)

                logger.info(
                    f"httpx found {len(alive)} alive from {len(targets)} {label}"
                )
                return alive

            except subprocess.TimeoutExpired:
                logger.warning(f"httpx timed out after {proc_timeout}s")
                console.print(f"  [yellow]⚠ httpx timed out for {label}[/]")
                return []
            except Exception as e:
                logger.error(f"httpx subprocess error: {e}")
                console.print(f"  [red]✗ httpx error: {e}[/]")
                return []

        finally:
            try:
                os.unlink(tmp.name)
            except OSError:
                pass

    # ══════════════════════════════════════════════════════════
    #  Write files
    # ══════════════════════════════════════════════════════════

    def _write_txt(self, path: Path, lines: List[str]):
        """Write a list of strings to a UTF-8 text file."""
        with open(path, "w", encoding="utf-8") as f:
            for line in lines:
                f.write(line + "\n")
        logger.info(f"Wrote {len(lines)} lines to {path.name}")

    # ══════════════════════════════════════════════════════════
    #  Main
    # ══════════════════════════════════════════════════════════

    def run(self):
        """Full pipeline: extract → probe → write 4 files."""
        console.print(
            "\n[bold cyan]>> Post-Processing: Probing alive targets...[/]\n"
        )

        if not self.load_report():
            return

        # ── Extract ──────────────────────────────────────────
        all_subs = self.extract_subdomains()
        all_urls = self.extract_urls()

        console.print(
            f"  [dim]>[/] Extracted [bold cyan]{len(all_subs)}[/] subdomains "
            f"and [bold cyan]{len(all_urls)}[/] URLs from report"
        )

        # ── Write all_*.txt immediately ───────────────────────
        subs_all_path = self.output_dir / "all_subdomains.txt"
        urls_all_path = self.output_dir / "all_urls.txt"
        self._write_txt(subs_all_path, all_subs)
        self._write_txt(urls_all_path, all_urls)

        # ── Probe subdomains ──────────────────────────────────
        console.print(
            f"\n  [yellow]Probing {len(all_subs)} subdomains with httpx...[/]"
        )
        alive_subs = self.probe_with_httpx(all_subs, "subdomains")
        console.print(
            f"  [green]>[/] Alive: [bold green]{len(alive_subs)}[/] "
            f"/ {len(all_subs)}"
        )

        # ── Deduplicate URLs before probing ───────────────────
        deduped_urls = self._dedupe_urls(all_urls, max_count=5000)
        console.print(
            f"\n  [yellow]Probing {len(deduped_urls)} URLs with httpx "
            f"(deduped from {len(all_urls)})...[/]"
        )
        alive_urls = self.probe_with_httpx(deduped_urls, "URLs")
        console.print(
            f"  [green]>[/] Alive: [bold green]{len(alive_urls)}[/] "
            f"/ {len(deduped_urls)}"
        )

        # ── Write alive_*.txt ─────────────────────────────────
        subs_alive_path = self.output_dir / "alive_subdomains.txt"
        urls_alive_path = self.output_dir / "alive_urls.txt"
        self._write_txt(subs_alive_path, sorted(alive_subs))
        self._write_txt(urls_alive_path, sorted(alive_urls))

        # ── Print results table ───────────────────────────────
        console.print()
        table = Table(
            title="Filtered Output Files",
            box=box.ROUNDED,
            border_style="green",
            title_style="bold green",
            show_header=True,
            header_style="bold white",
        )
        table.add_column("File", style="bold white", min_width=25)
        table.add_column("Description", style="dim white", min_width=38)
        table.add_column("Lines", style="bold cyan", width=8, justify="right")

        rows = [
            (
                "all_subdomains.txt",
                "Every subdomain discovered",
                str(len(all_subs)),
            ),
            (
                "alive_subdomains.txt",
                "Alive subdomains (httpx verified)",
                f"[green]{len(alive_subs)}[/]",
            ),
            (
                "all_urls.txt",
                "Every URL / endpoint discovered",
                str(len(all_urls)),
            ),
            (
                "alive_urls.txt",
                "Alive URLs (httpx verified)",
                f"[green]{len(alive_urls)}[/]",
            ),
        ]

        for name, desc, count in rows:
            table.add_row(name, desc, count)

        console.print(table)

        # ── Paths summary ─────────────────────────────────────
        console.print(
            f"\n  [dim]Location:[/] [bold]{self.output_dir}[/]"
        )

    # ══════════════════════════════════════════════════════════
    #  Helpers
    # ══════════════════════════════════════════════════════════

    @staticmethod
    def _host_from_url(url: str) -> str:
        """Strip scheme/path/port from a URL and return bare hostname."""
        url = url.strip()
        for prefix in ("https://", "http://", "ftp://"):
            if url.lower().startswith(prefix):
                url = url[len(prefix):]
                break
        return url.split("/")[0].split(":")[0].split("?")[0].lower().strip()

    @staticmethod
    def _dedupe_urls(urls: List[str], max_count: int = 5000) -> List[str]:
        """
        Keep one URL per unique (scheme, host, path) combination.
        Strips query strings to avoid probing thousands of param variants.
        """
        seen: Set[str] = set()
        result: List[str] = []

        for url in urls:
            try:
                p = urllib.parse.urlparse(url)
                key = f"{p.scheme}://{p.netloc}{p.path}".rstrip("/").lower()
                if key not in seen:
                    seen.add(key)
                    # Probe the clean URL (no query params)
                    result.append(
                        f"{p.scheme}://{p.netloc}{p.path}"
                    )
            except Exception:
                if url not in seen:
                    seen.add(url)
                    result.append(url)

        if len(result) > max_count:
            logger.warning(
                f"URL list capped at {max_count} (was {len(result)})"
            )
            result = result[:max_count]

        return result