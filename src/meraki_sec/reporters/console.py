from __future__ import annotations

from collections import defaultdict

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text

from meraki_sec.models import Finding, Severity, Status
from meraki_sec.reporters.summary import compute_summary


_SEVERITY_STYLE = {
    Severity.CRITICAL: "bold red",
    Severity.HIGH: "red",
    Severity.MEDIUM: "yellow",
    Severity.LOW: "cyan",
    Severity.INFO: "dim",
}

_STATUS_STYLE = {
    Status.PASS: "green",
    Status.FAIL: "bold red",
    Status.WARN: "yellow",
    Status.ERROR: "magenta",
    Status.SKIP: "dim",
    Status.NOT_APPLICABLE: "dim",
}


def render(findings: list[Finding]) -> None:
    console = Console()
    summary = compute_summary(findings)

    header = Text()
    header.append("Meraki Security Posture\n", style="bold")
    header.append(f"Posture score: ", style="dim")
    score = summary["posture_score"]
    score_color = "green" if score >= 85 else "yellow" if score >= 60 else "red"
    header.append(f"{score}/100\n", style=f"bold {score_color}")
    header.append(f"Total findings: {summary['total_findings']}\n", style="dim")
    header.append(f"By status: {summary['status_counts']}\n", style="dim")
    header.append(f"By severity (fail+warn): {summary['severity_counts']}", style="dim")
    console.print(Panel(header, title="Summary", border_style="blue"))

    # Per-framework coverage roll-up.
    rollup = summary.get("framework_rollup") or {}
    if rollup:
        fw_table = Table(title="Framework coverage (distinct controls)", header_style="bold")
        fw_table.add_column("Framework")
        fw_table.add_column("Pass", justify="right")
        fw_table.add_column("Fail/Warn", justify="right")
        for fw in sorted(rollup):
            vals = rollup[fw]
            fw_table.add_row(
                fw,
                Text(str(vals.get("pass", 0)), style="green"),
                Text(str(vals.get("fail", 0)), style="red" if vals.get("fail", 0) else "dim"),
            )
        console.print(fw_table)

    # Group findings: only show FAIL/WARN in the main table.
    actionable = [f for f in findings if f.status in (Status.FAIL, Status.WARN)]
    if actionable:
        table = Table(title="Findings", header_style="bold")
        table.add_column("ID", no_wrap=True)
        table.add_column("Sev", no_wrap=True)
        table.add_column("Status", no_wrap=True)
        table.add_column("Target")
        table.add_column("Finding")
        for f in sorted(
            actionable,
            key=lambda x: (-_priority(x), x.check_id, x.target.label()),
        ):
            table.add_row(
                f.check_id,
                Text(f.severity.value, style=_SEVERITY_STYLE[f.severity]),
                Text(f.status.value, style=_STATUS_STYLE[f.status]),
                f.target.label(),
                f.message,
            )
        console.print(table)
    else:
        console.print("[green]No failing or warning findings.[/green]")

    # Short stats by check id (so pass/error/skip are visible aggregate-wise).
    by_id: dict[str, dict[str, int]] = defaultdict(lambda: defaultdict(int))
    for f in findings:
        by_id[f.check_id][f.status.value] += 1
    stats = Table(title="Check coverage", header_style="bold")
    stats.add_column("Check")
    for col in ("pass", "fail", "warn", "error", "n/a"):
        stats.add_column(col)
    for check_id in sorted(by_id):
        row = [check_id] + [str(by_id[check_id].get(c, 0)) for c in ("pass", "fail", "warn", "error", "n/a")]
        stats.add_row(*row)
    console.print(stats)


def _priority(f: Finding) -> int:
    sev = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}.get(f.severity.value, 0)
    status_bump = 1 if f.status == Status.FAIL else 0
    return sev * 2 + status_bump
