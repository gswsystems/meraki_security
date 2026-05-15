"""Re-render saved JSON reports into the same text layout as the live console.

Useful when reports were generated per-network (or per-org) and you want a
single combined readout without re-scanning the API.

    meraki-sec-render reports/                       # all *.json in a directory
    meraki-sec-render report-a.json report-b.json
    meraki-sec-render reports/ --output combined.txt
    meraki-sec-render reports/ --ansi > combined.ansi
    meraki-sec-render reports/ --html -o combined.html
"""
from __future__ import annotations

import argparse
import io
import json
import sys
from pathlib import Path

from rich.console import Console

from meraki_sec.models import Finding, Scope, Severity, Status, Target
from meraki_sec.reporters import console as console_reporter


def _expand(paths: list[str]) -> list[Path]:
    out: list[Path] = []
    for raw in paths:
        p = Path(raw)
        if p.is_dir():
            out.extend(sorted(p.glob("*.json")))
        else:
            out.append(p)
    return out


def _load_finding(d: dict) -> Finding:
    t = d.get("target") or {}
    target = Target(
        scope=Scope(t.get("scope")),
        org_id=t.get("org_id"),
        org_name=t.get("org_name"),
        network_id=t.get("network_id"),
        network_name=t.get("network_name"),
        device_serial=t.get("device_serial"),
        device_name=t.get("device_name"),
    )
    return Finding(
        check_id=d["check_id"],
        title=d.get("title", ""),
        severity=Severity(d["severity"]),
        status=Status(d["status"]),
        target=target,
        message=d.get("message", ""),
        remediation=d.get("remediation", ""),
        sources=list(d.get("sources") or []),
        mappings={k: list(v) for k, v in (d.get("mappings") or {}).items()},
        evidence=dict(d.get("evidence") or {}),
    )


def _load_findings(paths: list[Path]) -> list[Finding]:
    findings: list[Finding] = []
    for p in paths:
        try:
            payload = json.loads(p.read_text())
        except (OSError, json.JSONDecodeError) as e:
            print(f"warning: skipping {p}: {e}", file=sys.stderr)
            continue
        for f in payload.get("findings") or []:
            try:
                findings.append(_load_finding(f))
            except (KeyError, ValueError) as e:
                print(f"warning: bad finding in {p}: {e}", file=sys.stderr)
    return findings


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="meraki-sec-render",
        description=(
            "Re-render saved JSON reports into the console-style text layout. "
            "Pass one or more JSON files or directories; all findings are merged."
        ),
    )
    p.add_argument("paths", nargs="+", help="JSON report files or directories containing them.")
    p.add_argument("--output", "-o", default=None,
                   help="Write text to FILE instead of stdout.")
    fmt = p.add_mutually_exclusive_group()
    fmt.add_argument("--ansi", action="store_true",
                     help="Preserve ANSI color codes (best in a terminal; raw in text editors).")
    fmt.add_argument("--html", action="store_true",
                     help="Render as a self-contained HTML page (portable; opens in any browser).")
    p.add_argument("--width", type=int, default=None,
                   help="Wrap width for the rendered output (default: terminal width or 200).")
    return p


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)

    paths = _expand(args.paths)
    if not paths:
        print("error: no JSON files found in the given paths.", file=sys.stderr)
        return 2

    findings = _load_findings(paths)
    if not findings:
        print("error: no findings parsed from the given files.", file=sys.stderr)
        return 2

    # Render into a recording Console so we can grab the output verbatim.
    width = args.width or (200 if (args.output or args.html) else None)
    console = Console(record=True, width=width, file=io.StringIO())
    console_reporter.render(findings, console=console)

    if args.html:
        out = console.export_html(clear=False, inline_styles=True)
    elif args.ansi:
        out = console.export_text(clear=False, styles=True)
    else:
        out = console.export_text(clear=False)

    if args.output:
        Path(args.output).write_text(out)
        print(f"wrote {args.output}", file=sys.stderr)
    else:
        sys.stdout.write(out)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
