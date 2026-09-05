#!/usr/bin/env python3
"""Command-line interface for the multi-scanner vulnerability assessment engine.

Two modes:
  - local (default): runs the Nuclei/ZAP/Nikto wrappers directly in-process -
    no server required. Same wrappers the API uses (real binary if installed,
    simulated findings otherwise).
  - --api URL: talks to a running FastAPI backend instead (POST /scan/start,
    poll /scan/status, GET /scan/results) - useful when hitting the
    docker-compose stack instead of running scanners on this machine.

Examples:
  python cli.py scan scanme.nmap.org
  python cli.py scan scanme.nmap.org --scanners nuclei,zap --json
  python cli.py scan demo-target.local --api http://localhost:8000
  python cli.py status scan-abc123 --api http://localhost:8000
  python cli.py results scan-abc123 --api http://localhost:8000 --json
"""

import argparse
import asyncio
import json
import sys
import time

import requests
from rich import box
from rich.console import Console
from rich.table import Table

from correlation import correlate_findings, duplicate_group_count, severity_distribution
from scanners import REGISTRY
from schemas import ScannerName

console = Console()

SEVERITY_STYLE = {
    "critical": "bold red",
    "high": "red",
    "medium": "yellow",
    "low": "green",
    "info": "dim",
}

ALL_SCANNERS = [s.value for s in ScannerName]


def _sev(text: str) -> str:
    return f"[{SEVERITY_STYLE.get(text, 'white')}]{text.upper()}[/]"


def print_report(target: str, raw_findings: list[dict], correlated: list[dict], dist: dict, dup_groups: int) -> None:
    console.rule(f"[bold]{target}")

    summary = Table(box=box.SIMPLE, show_header=False, pad_edge=False)
    summary.add_row("Total findings", str(len(raw_findings)))
    summary.add_row(
        "Severity",
        "  ".join(f"{_sev(k)} {v}" for k, v in dist.items() if v),
    )
    summary.add_row("Corroborated groups", str(dup_groups))
    console.print(summary)

    if correlated:
        table = Table(title="Consolidated Findings", box=box.SIMPLE_HEAVY, header_style="bold")
        table.add_column("Severity", no_wrap=True)
        table.add_column("Vulnerability")
        table.add_column("Tools")
        table.add_column("Confidence", justify="right", no_wrap=True)
        table.add_column("Flags")
        for c in sorted(correlated, key=lambda c: c["confidence"], reverse=True):
            flags = []
            if len(c["contributing_tools"]) > 1:
                flags.append(f"{len(c['contributing_tools'])}x corroborated")
            if c["conflicting_severity"]:
                flags.append("conflicting severity")
            table.add_row(
                _sev(c["severity"]),
                c["vulnerability"],
                ", ".join(c["contributing_tools"]),
                f"{c['confidence']}%",
                ", ".join(flags),
            )
        console.print(table)
    else:
        console.print("[dim]No findings.[/]")


async def run_local_scan(target: str, scanner_names: list[str], profile: str, as_json: bool) -> None:
    tools = [ScannerName(s) for s in scanner_names]
    if not as_json:
        console.print(f"[bold]Scanning[/] {target} with {', '.join(t.value for t in tools)} (local, no server)...\n")

    results_by_tool: dict[ScannerName, list] = {}

    async def run_one(tool: ScannerName) -> None:
        findings = await REGISTRY[tool].run(target, profile)
        results_by_tool[tool] = findings
        if not as_json:
            console.print(f"  [green]done[/]  {tool.value}: {len(findings)} findings")

    await asyncio.gather(*(run_one(t) for t in tools))

    raw_findings = [f.model_dump(mode="json") for findings in results_by_tool.values() for f in findings]
    all_findings = [f for findings in results_by_tool.values() for f in findings]
    correlated_models = correlate_findings(all_findings)
    correlated = [c.model_dump(mode="json") for c in correlated_models]
    dist = severity_distribution(all_findings).model_dump()
    dup_groups = duplicate_group_count(correlated_models)

    if as_json:
        print(json.dumps({
            "target": target,
            "raw_findings": raw_findings,
            "correlated_findings": correlated,
            "severity_distribution": dist,
            "duplicate_groups": dup_groups,
        }, indent=2))
        return

    print_report(target, raw_findings, correlated, dist, dup_groups)


def run_api_scan(api_url: str, target: str, scanner_names: list[str], profile: str, as_json: bool, poll_interval: float = 1.0) -> None:
    resp = requests.post(f"{api_url}/scan/start", json={"target": target, "scanners": scanner_names, "profile": profile})
    resp.raise_for_status()
    scan_id = resp.json()["scan_id"]
    if not as_json:
        console.print(f"[bold]Started scan[/] {scan_id} via {api_url}\n")

    with console.status("Waiting for scanners...", spinner="dots") if not as_json else _noop_status():
        while True:
            status = requests.get(f"{api_url}/scan/status/{scan_id}").json()
            if status["overall_status"] in ("completed", "error"):
                break
            time.sleep(poll_interval)

    results = requests.get(f"{api_url}/scan/results/{scan_id}").json()
    if as_json:
        print(json.dumps(results, indent=2))
        return
    print_report(
        target,
        results["raw_findings"],
        results["correlated_findings"],
        results["severity_distribution"],
        results["duplicate_groups"],
    )


class _noop_status:
    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


def cmd_scan(args: argparse.Namespace) -> None:
    scanner_names = [s.strip() for s in args.scanners.split(",")] if args.scanners else ALL_SCANNERS
    invalid = set(scanner_names) - set(ALL_SCANNERS)
    if invalid:
        console.print(f"[red]Unknown scanner(s): {', '.join(invalid)}. Choose from {', '.join(ALL_SCANNERS)}[/]")
        sys.exit(1)

    if args.api:
        run_api_scan(args.api.rstrip("/"), args.target, scanner_names, args.profile, args.json)
    else:
        asyncio.run(run_local_scan(args.target, scanner_names, args.profile, args.json))


def cmd_status(args: argparse.Namespace) -> None:
    resp = requests.get(f"{args.api.rstrip('/')}/scan/status/{args.scan_id}")
    if resp.status_code == 404:
        console.print(f"[red]Scan not found: {args.scan_id}[/]")
        sys.exit(1)
    resp.raise_for_status()
    data = resp.json()
    if args.json:
        print(json.dumps(data, indent=2))
        return

    table = Table(title=f"Scan {data['scan_id']} - {data['target']}", box=box.SIMPLE_HEAVY, header_style="bold")
    table.add_column("Scanner")
    table.add_column("Status")
    table.add_column("Findings", justify="right")
    for s in data["scanners"]:
        table.add_row(s["tool"], s["status"], str(s["findings_count"]))
    console.print(table)
    console.print(f"Overall: [bold]{data['overall_status']}[/]")


def cmd_results(args: argparse.Namespace) -> None:
    resp = requests.get(f"{args.api.rstrip('/')}/scan/results/{args.scan_id}")
    if resp.status_code == 404:
        console.print(f"[red]Scan not found: {args.scan_id}[/]")
        sys.exit(1)
    resp.raise_for_status()
    data = resp.json()
    if args.json:
        print(json.dumps(data, indent=2))
        return
    print_report(
        data["target"],
        data["raw_findings"],
        data["correlated_findings"],
        data["severity_distribution"],
        data["duplicate_groups"],
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="cli.py",
        description="Multi-scanner vulnerability assessment CLI (Nuclei/ZAP/Nikto + correlation engine).",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    scan_p = sub.add_parser("scan", help="Run a scan and print the consolidated report")
    scan_p.add_argument("target", help="Hostname, IP, or URL to assess")
    scan_p.add_argument("--scanners", help=f"Comma-separated list from {', '.join(ALL_SCANNERS)} (default: all)")
    scan_p.add_argument("--profile", default="web", choices=["recon", "web", "full"])
    scan_p.add_argument("--api", help="Backend URL (e.g. http://localhost:8000) - omit to run scanners locally")
    scan_p.add_argument("--json", action="store_true", help="Print raw JSON instead of a formatted report")
    scan_p.set_defaults(func=cmd_scan)

    status_p = sub.add_parser("status", help="Check a scan's progress (requires --api)")
    status_p.add_argument("scan_id")
    status_p.add_argument("--api", required=True, help="Backend URL (e.g. http://localhost:8000)")
    status_p.add_argument("--json", action="store_true")
    status_p.set_defaults(func=cmd_status)

    results_p = sub.add_parser("results", help="Fetch a completed scan's results (requires --api)")
    results_p.add_argument("scan_id")
    results_p.add_argument("--api", required=True, help="Backend URL (e.g. http://localhost:8000)")
    results_p.add_argument("--json", action="store_true")
    results_p.set_defaults(func=cmd_results)

    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
