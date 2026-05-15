# meraki-sec

Evaluate a Cisco Meraki organization against Cisco Meraki Best Practices, the
CIS Cisco Meraki Benchmark, NIST CSF, CIS CSC v8, and the ASD Essential Eight /
ISM — and write the findings to console, JSON, and CSV.

`meraki-sec` is a read-only auditor. It uses the official Meraki Dashboard API
Python SDK, never changes dashboard state, and is designed to be safe to run
in production and in CI.

## What it checks

38 checks across six product areas:

| Prefix | Area                | Checks |
|--------|---------------------|--------|
| ORG-   | Organization & IAM  | 10     |
| NET-   | Network baseline    | 6      |
| MX-    | Appliance (MX)      | 8      |
| MR-    | Wireless (MR)       | 6      |
| MS-    | Switching (MS)      | 5      |
| MV-    | Cameras (MV)        | 2      |
| MT-    | Sensors (MT)        | 1      |

Every finding carries structured mappings to the relevant frameworks:

- **CIS Cisco Meraki Benchmark**
- **Cisco Meraki Security Best Practices**
- **NIST CSF** (function/category codes, e.g. `PR.AC-1`)
- **CIS Controls v8** (e.g. `6.5`, `13.3`)
- **ASD Essential Eight** (maturity-relevant checks only)
- **ASD ISM** (topic-based references)

Run `meraki-sec --list-checks` for the full list with every framework ID on
every check.

## Install

Requires Python 3.10+.

```bash
cd /path/to/meraki_security
python3 -m venv .venv
source .venv/bin/activate
pip install -e .
```

This installs the `meraki-sec` console script into the virtualenv.

## Configure

```bash
cp config.example.yaml config.yaml
# edit config.yaml and paste your Dashboard API key
```

Generate an API key from the Meraki dashboard under **My Profile → API access**.
The key only needs read access to the orgs you want to scan. `config.yaml` is
in `.gitignore` — keep it out of version control.

## Run

```bash
# scan every org the API key can see; write console + JSON + CSV
meraki-sec -c config.yaml

# limit the scope
meraki-sec -c config.yaml --org-id 123456 --network-id L_987

# run a single check
meraki-sec -c config.yaml --only ORG-001

# skip noisy checks
meraki-sec -c config.yaml --skip MV-002 --skip MT-001

# suppress file output, show console only
meraki-sec -c config.yaml --format console

# list every check and its framework mappings
meraki-sec --list-checks
```

### Discover what's there

Before scanning, you can list the orgs, networks, and device mix the API key
can see — handy when an org is split across many networks and you want to
scan a specific one.

```bash
# list every network in an org (id, name, product types, tags, time zone)
meraki-sec --list-networks --org-id 123456

# device-type counts per org
meraki-sec --device-overview --org-id 123456
```

Both print the org id and name on a header line above each table so the ids
are easy to copy into `--network-id` for a follow-up scan.

### Reports

Reports are timestamped and written to `./reports/` by default. When the run
is scoped to a single network or org, the name is included in the filename so
per-network reports aren't confusing to tell apart:

```
reports/meraki-sec-hq-network-YYYYMMDDTHHMMSSZ.json   # scoped to one network
reports/meraki-sec-acme-YYYYMMDDTHHMMSSZ.json         # scoped to one org
reports/meraki-sec-YYYYMMDDTHHMMSSZ.json              # multi-org scan
```

### Re-render saved JSON reports

If you've gathered reports network-by-network and want one combined readout
without re-scanning, `meraki-sec-render` re-renders the JSON in the same
layout as the live console output:

```bash
# combine every JSON in a directory; write plain text to stdout
meraki-sec-render reports/

# write to a file
meraki-sec-render reports/ -o combined.txt

# self-contained HTML (portable; opens in any browser on any OS)
meraki-sec-render reports/ --html -o combined.html

# ANSI-coloured text (best viewed in a terminal: `less -R combined.ansi`)
meraki-sec-render reports/ --ansi > combined.ansi
```

`--ansi` and `--html` are mutually exclusive; plain text is the default.

## Exit codes

| Code | Meaning                                          |
|------|--------------------------------------------------|
| 0    | Scan completed, no `FAIL` findings               |
| 1    | Scan completed, at least one `FAIL` finding      |
| 2    | Config problem (missing file, missing API key)   |

The `1` exit code is designed for CI — a failing scan breaks the build.

## Project layout

```
src/meraki_sec/
  cli.py              # argparse + main()
  config.py           # YAML loader
  client.py           # Dashboard SDK wrapper (rate-limited, cached)
  engine.py           # iterates orgs/networks/devices, runs checks
  models.py           # Finding / Target / enums / framework labels
  render_reports.py   # meraki-sec-render: re-render saved JSON as text/HTML
  checks/
    base.py           # @check decorator + REGISTRY
    organization.py   # ORG-001 … ORG-010
    network.py        # NET-001 … NET-006
    appliance.py      # MX-001 … MX-008
    wireless.py       # MR-001 … MR-006
    switch.py         # MS-001 … MS-005
    camera.py         # MV-001, MV-002
    sensor.py         # MT-001
  reporters/
    console.py        # Rich terminal output
    json_report.py
    csv_report.py
```

## Extending

Add a new check by writing a function in the appropriate `checks/*.py` module:

```python
from meraki_sec.checks.base import CheckContext, check, failed, passed
from meraki_sec.models import Scope, Severity

@check(
    id="MX-009",
    title="Example check",
    severity=Severity.MEDIUM,
    scope=Scope.NETWORK,
    product_type="appliance",
    cis=["3.5"],
    nist_csf=["PR.PT-4"],
    cis_csc=["4.2"],
    cisco=["Meraki Example Best Practice"],
    asd_ism=["Gateways: Example control"],
    description="Why this check matters.",
)
def example(ctx: CheckContext):
    meta = example.meta
    data = ctx.client.some_endpoint(ctx.network["id"])
    if not data:
        yield failed(meta, ctx, "setting is off",
                     remediation="Dashboard → path to fix.")
    else:
        yield passed(meta, ctx, "setting is on")
```

The decorator registers the function automatically; no other wiring required.
Every mapping keyword you pass is surfaced in console, JSON, CSV, and
`--list-checks`.

See `docs/USER_GUIDE.md` for the full operator walkthrough, per-check
reference, and Australian-compliance notes.
