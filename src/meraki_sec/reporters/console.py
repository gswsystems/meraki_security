from __future__ import annotations

from collections import defaultdict

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text

from meraki_sec.models import Finding, Scope, Severity, Status
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


def render(findings: list[Finding], *, console: Console | None = None) -> None:
    console = console or Console()
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

    # Group findings by target (org → network → device); only FAIL/WARN.
    actionable = [f for f in findings if f.status in (Status.FAIL, Status.WARN)]
    if actionable:
        table = Table(title="Findings (grouped by target)", header_style="bold")
        table.add_column("ID", no_wrap=True)
        table.add_column("Sev", no_wrap=True)
        table.add_column("Status", no_wrap=True)
        table.add_column("Target")
        table.add_column("Finding")
        table.add_column("Controls")
        scope_order = {Scope.ORG: 0, Scope.NETWORK: 1, Scope.DEVICE: 2}

        def _target_sort_key(f: Finding):
            t = f.target
            return (
                t.org_name or "",
                scope_order.get(t.scope, 99),
                t.network_name or "",
                t.device_name or t.device_serial or "",
                -_priority(f),
                f.check_id,
            )

        def _target_group(f: Finding):
            t = f.target
            return (t.org_name, t.network_name, t.device_name or t.device_serial)

        prev_group = None
        for f in sorted(actionable, key=_target_sort_key):
            cur = _target_group(f)
            if prev_group is not None and cur != prev_group:
                table.add_section()
            table.add_row(
                f.check_id,
                Text(f.severity.value, style=_SEVERITY_STYLE[f.severity]),
                Text(f.status.value, style=_STATUS_STYLE[f.status]),
                f.target.label(),
                f.message,
                _format_controls(f),
            )
            prev_group = cur
        console.print(table)
    else:
        console.print("[green]No failing or warning findings.[/green]")

    # Short stats by check id (so pass/error/skip are visible aggregate-wise).
    by_id: dict[str, dict[str, int]] = defaultdict(lambda: defaultdict(int))
    for f in findings:
        by_id[f.check_id][f.status.value] += 1
    stats = Table(title="Check coverage (per check ID)", header_style="bold")
    stats.add_column("Check")
    for col in ("pass", "fail", "warn", "error", "n/a"):
        stats.add_column(col)
    for check_id in sorted(by_id):
        row = [check_id] + [str(by_id[check_id].get(c, 0)) for c in ("pass", "fail", "warn", "error", "n/a")]
        stats.add_row(*row)
    console.print(stats)

    # Per-device coverage: only findings whose target is a specific device.
    by_dev: dict[tuple[str, str], dict[str, int]] = defaultdict(lambda: defaultdict(int))
    for f in findings:
        if f.target.scope != Scope.DEVICE:
            continue
        key = (f.target.device_serial or "", f.target.device_name or "")
        by_dev[key][f.status.value] += 1
    if by_dev:
        dev_table = Table(title="Device coverage (per device)", header_style="bold")
        dev_table.add_column("Device")
        dev_table.add_column("Serial", no_wrap=True)
        for col in ("pass", "fail", "warn", "error", "n/a"):
            dev_table.add_column(col, justify="right")
        # Sort: most fail/warn first, then by name.
        def _dev_key(item):
            (serial, name), counts = item
            severity_total = counts.get("fail", 0) + counts.get("warn", 0)
            return (-severity_total, name or serial)
        for (serial, name), counts in sorted(by_dev.items(), key=_dev_key):
            row = [name or "-", serial or "-"] + [
                str(counts.get(c, 0)) for c in ("pass", "fail", "warn", "error", "n/a")
            ]
            dev_table.add_row(*row)
        console.print(dev_table)
    else:
        console.print(
            "[dim]No device-scope findings — only switches (MS-003/005) "
            "and cameras (MV-001/002) currently have per-device checks.[/dim]"
        )


def _priority(f: Finding) -> int:
    sev = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}.get(f.severity.value, 0)
    status_bump = 1 if f.status == Status.FAIL else 0
    return sev * 2 + status_bump


# Compact framework labels for the Controls column.
_FRAMEWORK_SHORT = {
    "CIS": "CIS",
    "CIS_CSC": "CSC",
    "NIST_CSF": "NIST",
    "Cisco": "Cisco",
    "E8": "E8",
    "ISM": "ISM",
}


def _format_controls(f: Finding) -> str:
    if not f.mappings:
        return "-"
    parts: list[str] = []
    for fw in ("CIS", "CIS_CSC", "NIST_CSF", "Cisco", "E8", "ISM"):
        refs = f.mappings.get(fw)
        if not refs:
            continue
        label = _FRAMEWORK_SHORT.get(fw, fw)
        parts.append(f"{label}:{', '.join(refs)}")
    return "\n".join(parts) if parts else "-"
