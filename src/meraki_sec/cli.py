from __future__ import annotations

import argparse
import logging
import sys
from collections import defaultdict
from pathlib import Path

from meraki_sec import __version__
from meraki_sec import checks  # noqa: F401 — populates the registry
from meraki_sec.client import MerakiClient
from meraki_sec.config import Config
from meraki_sec.engine import Engine, device_product_type
from meraki_sec.reporters import console as console_reporter
from meraki_sec.reporters import csv_report, json_report


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="meraki-sec",
        description="Evaluate a Meraki organization against Cisco and CIS security best practices.",
    )
    p.add_argument("--config", "-c", default="config.yaml", help="Path to YAML config (default: config.yaml)")
    p.add_argument("--org-id", action="append", default=[], help="Limit to this org id (repeatable). Overrides config.")
    p.add_argument("--network-id", action="append", default=[], help="Limit to this network id (repeatable).")
    p.add_argument("--only", action="append", default=[], help="Run only this check id (repeatable).")
    p.add_argument("--skip", action="append", default=[], help="Skip this check id (repeatable).")
    p.add_argument("--format", action="append", default=[], choices=["console", "json", "csv"],
                   help="Output format (repeatable). Overrides config.")
    p.add_argument("--output-dir", default=None, help="Directory for JSON/CSV output. Overrides config.")
    p.add_argument("--rate-limit", type=float, default=None, metavar="RPS",
                   help="Cap API requests per second. Overrides config.")
    p.add_argument("--sample", type=int, default=None, metavar="N",
                   help="Sample at most N devices of each product type per org. Overrides config.")
    p.add_argument("--sample-type", action="append", default=[], metavar="TYPE=N",
                   help="Per-product-type sample limit, e.g. --sample-type wireless=10 (repeatable).")
    p.add_argument("--devices", default=None, metavar="FILE",
                   help="Path to a text file listing device serials, names, or MACs (one per line; "
                        "'#' comments and blank lines ignored). Device-scope checks run only on listed devices.")
    p.add_argument("--list-checks", action="store_true", help="Print all known checks and exit.")
    p.add_argument("--list-networks", action="store_true",
                   help="Print networks (id, name, product types, tags) per organization and exit.")
    p.add_argument("--device-overview", action="store_true",
                   help="Print device-type counts per organization and exit.")
    p.add_argument("-v", "--verbose", action="count", default=0, help="-v for INFO, -vv for DEBUG.")
    p.add_argument("--version", action="version", version=f"meraki-sec {__version__}")
    return p


def _configure_logging(verbosity: int) -> None:
    level = logging.WARNING
    if verbosity == 1:
        level = logging.INFO
    elif verbosity >= 2:
        level = logging.DEBUG
    logging.basicConfig(
        level=level,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    # Silence third-party HTTP plumbing at DEBUG — urllib3 emits one
    # `"GET ... HTTP/1.1" 200 None` line per request, which drowns out our
    # own logs and confuses output ("None" is the content-length, not the body).
    for noisy in ("urllib3", "urllib3.connectionpool", "requests", "charset_normalizer"):
        logging.getLogger(noisy).setLevel(logging.WARNING)


def _list_checks() -> None:
    from meraki_sec.checks.base import REGISTRY
    for c in sorted(REGISTRY, key=lambda x: x.meta.id):
        m = c.meta
        print(f"{m.id:8s} [{m.severity.value:8s}] {m.scope.value:12s} {m.product_type or '-':9s} {m.title}")
        for framework, refs in m.mappings.items():
            print(f"           {framework}: {', '.join(refs)}")


def _load_device_list(path: str) -> list[str]:
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(f"device list file not found: {p}")
    out: list[str] = []
    for line in p.read_text().splitlines():
        s = line.strip()
        if not s or s.startswith("#"):
            continue
        out.append(s)
    return out


def _parse_sample_types(items: list[str]) -> dict[str, int]:
    out: dict[str, int] = {}
    for item in items:
        if "=" not in item:
            raise ValueError(f"--sample-type expects TYPE=N, got: {item!r}")
        ptype, _, n = item.partition("=")
        ptype = ptype.strip().lower()
        if not ptype or not n.strip():
            raise ValueError(f"--sample-type expects TYPE=N, got: {item!r}")
        out[ptype] = int(n)
    return out


def _resolve_orgs(client: MerakiClient, org_filters: list[str]) -> list[dict]:
    all_orgs = client.organizations()
    if not org_filters:
        return all_orgs
    wanted = {str(x) for x in org_filters}
    return [o for o in all_orgs if str(o.get("id")) in wanted or o.get("name") in wanted]


def _show_network_list(client: MerakiClient, org_filters: list[str]) -> None:
    from rich.console import Console
    from rich.table import Table

    console = Console()
    orgs = _resolve_orgs(client, org_filters)
    if not orgs:
        console.print("[yellow]No organizations resolved.[/yellow]")
        return

    grand_total = 0
    for org in orgs:
        try:
            nets = client.networks(org["id"])
        except Exception as e:
            console.print(f"[red]Failed to load networks for {org.get('name')}: {e}[/red]")
            continue

        table = Table(
            title=f"Networks: {org.get('name')} ({org.get('id')}) — {len(nets)} total",
            header_style="bold",
        )
        table.add_column("Network ID", no_wrap=True)
        table.add_column("Name")
        table.add_column("Product types")
        table.add_column("Tags")
        table.add_column("Time zone")
        for n in sorted(nets, key=lambda x: (x.get("name") or "").lower()):
            ptypes = ", ".join(n.get("productTypes") or []) or "-"
            tags = ", ".join(n.get("tags") or []) or "-"
            table.add_row(
                n.get("id") or "-",
                n.get("name") or "-",
                ptypes,
                tags,
                n.get("timeZone") or "-",
            )
        console.print(table)
        grand_total += len(nets)

    if len(orgs) > 1:
        console.print(f"[dim]Total networks across selected orgs: {grand_total}[/dim]")


def _show_device_overview(client: MerakiClient, org_filters: list[str]) -> None:
    from rich.console import Console
    from rich.table import Table

    console = Console()
    orgs = _resolve_orgs(client, org_filters)
    if not orgs:
        console.print("[yellow]No organizations resolved.[/yellow]")
        return

    grand_totals: dict[str, int] = defaultdict(int)
    for org in orgs:
        try:
            devs = client.org_devices(org["id"])
        except Exception as e:
            console.print(f"[red]Failed to load devices for {org.get('name')}: {e}[/red]")
            continue

        counts: dict[str, int] = defaultdict(int)
        for d in devs:
            ptype = device_product_type(d) or "unknown"
            counts[ptype] += 1
            grand_totals[ptype] += 1

        table = Table(
            title=f"Device overview: {org.get('name')} ({org.get('id')})",
            header_style="bold",
        )
        table.add_column("Product type")
        table.add_column("Count", justify="right")
        for ptype in sorted(counts):
            table.add_row(ptype, str(counts[ptype]))
        table.add_row("[bold]Total[/bold]", f"[bold]{len(devs)}[/bold]")
        console.print(table)

    if len(orgs) > 1 and grand_totals:
        table = Table(title="Device overview: all selected orgs", header_style="bold")
        table.add_column("Product type")
        table.add_column("Count", justify="right")
        total = 0
        for ptype in sorted(grand_totals):
            table.add_row(ptype, str(grand_totals[ptype]))
            total += grand_totals[ptype]
        table.add_row("[bold]Total[/bold]", f"[bold]{total}[/bold]")
        console.print(table)


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    _configure_logging(args.verbose)

    if args.list_checks:
        _list_checks()
        return 0

    config_path = Path(args.config)
    if not config_path.exists():
        print(
            f"error: config file not found: {config_path}\n"
            f"hint: copy config.example.yaml to {config_path} and fill in your API key.",
            file=sys.stderr,
        )
        return 2

    try:
        cfg = Config.load(config_path)
    except Exception as e:
        print(f"error loading {config_path}: {e}", file=sys.stderr)
        return 2

    try:
        cli_sample_types = _parse_sample_types(args.sample_type)
    except ValueError as e:
        print(f"error: {e}", file=sys.stderr)
        return 2

    device_filter: list[str] = []
    if args.devices:
        try:
            device_filter = _load_device_list(args.devices)
        except FileNotFoundError as e:
            print(f"error: {e}", file=sys.stderr)
            return 2
        if not device_filter:
            print(f"error: device list is empty: {args.devices}", file=sys.stderr)
            return 2

    # CLI flags override config.
    org_ids = args.org_id or cfg.organizations
    network_ids = args.network_id or cfg.networks
    only = args.only or cfg.only_checks
    skip = args.skip or cfg.skip_checks
    formats = args.format or cfg.formats
    output_dir = Path(args.output_dir) if args.output_dir else cfg.output_dir
    rate_limit = args.rate_limit if args.rate_limit is not None else cfg.meraki.max_requests_per_second
    sample_per_type = args.sample if args.sample is not None else cfg.device_sample_per_type
    sample_map = {**cfg.device_sample, **cli_sample_types}

    client = MerakiClient(
        api_key=cfg.meraki.api_key,
        base_url=cfg.meraki.base_url,
        timeout=cfg.meraki.timeout,
        max_requests_per_second=rate_limit,
    )

    if args.list_networks:
        _show_network_list(client, org_ids)
        return 0

    if args.device_overview:
        _show_device_overview(client, org_ids)
        return 0

    engine = Engine(
        client=client,
        thresholds=cfg.thresholds,
        only_checks=only,
        skip_checks=skip,
        device_sample_per_type=sample_per_type,
        device_sample=sample_map,
        device_filter=device_filter,
    )

    findings = engine.run(org_ids=org_ids or None, network_ids=network_ids or None)

    if "console" in formats:
        console_reporter.render(findings)
    if "json" in formats:
        path = json_report.write(findings, output_dir)
        print(f"wrote JSON report: {path}")
    if "csv" in formats:
        path = csv_report.write(findings, output_dir)
        print(f"wrote CSV report: {path}")

    # Exit non-zero if any FAIL findings exist (useful for CI).
    from meraki_sec.models import Status
    has_fail = any(f.status == Status.FAIL for f in findings)
    return 1 if has_fail else 0


if __name__ == "__main__":
    raise SystemExit(main())
