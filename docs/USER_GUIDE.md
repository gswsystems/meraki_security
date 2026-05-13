# meraki-sec User Guide

This guide walks operators through installing, configuring, and running
`meraki-sec`; interpreting the output; integrating it into CI; and
cross-referencing the 38 built-in checks against the frameworks they map to.

- [1. Prerequisites](#1-prerequisites)
- [2. Installation](#2-installation)
- [3. Getting a Dashboard API key](#3-getting-a-dashboard-api-key)
- [4. Configuring meraki-sec](#4-configuring-meraki-sec)
- [5. Running scans](#5-running-scans)
- [6. Reading the output](#6-reading-the-output)
- [7. CI integration](#7-ci-integration)
- [8. Threshold tuning](#8-threshold-tuning)
- [9. Check reference](#9-check-reference)
- [10. Framework mappings at a glance](#10-framework-mappings-at-a-glance)
- [11. Australian compliance notes](#11-australian-compliance-notes)
- [12. Troubleshooting](#12-troubleshooting)
- [13. Extending the tool](#13-extending-the-tool)

---

## 1. Prerequisites

- **Python 3.10 or newer** (`python3 --version`)
- **Network access** from the scan host to `api.meraki.com` (or the regional
  endpoint for your dashboard)
- **A Meraki Dashboard admin account** with read access to the organizations
  you intend to scan; generator of the API key should have 2FA enabled

`meraki-sec` never writes to the dashboard and never calls an action endpoint.
Every SDK call is a GET. A read-only admin role is sufficient for every
check; full admin is not required.

## 2. Installation

```bash
cd /path/to/meraki_security
python3 -m venv .venv
source .venv/bin/activate
pip install -e .
```

`pip install -e .` creates a `meraki-sec` entry point inside `.venv/bin/`.
After this, every `meraki-sec ...` command in this guide assumes the
virtualenv is active (`source .venv/bin/activate`). Alternatively, invoke the
binary directly: `.venv/bin/meraki-sec ...`.

Deactivate with `deactivate` when finished.

## 3. Getting a Dashboard API key

1. Log in to the Meraki Dashboard as the admin who will own the scan.
2. Click your account email (top-right) → **My Profile**.
3. Scroll to **API access** and click **Generate new API key**.
4. Copy the 40-character key immediately — the dashboard never shows it again.
5. Store it in `config.yaml` (see next section). Never commit it to git.

If the key ever leaks, regenerate it from the same page — regeneration
invalidates the old key. `meraki-sec`'s own ORG-009 check will flag stale
keys on your next scan.

## 4. Configuring meraki-sec

```bash
cp config.example.yaml config.yaml
```

Edit `config.yaml`:

```yaml
meraki:
  api_key: "0000000000000000000000000000000000000000"
  base_url: null          # set only for GovCloud / China
  timeout: 60

organizations: []         # [] = scan every org the key can see
networks: []              # [] = scan every network in scope
skip_checks: []
only_checks: []

output_dir: "./reports"
formats: [console, json, csv]

thresholds:
  admin_inactive_days: 90
  api_key_stale_days: 90
  firmware_versions_behind: 2
  min_wireless_bitrate_mbps: 12
  required_dashboard_region: null   # e.g. "Australia"
  required_timezone_prefix: null    # e.g. "Australia/"
```

Notes:

- `organizations`, `networks`, `skip_checks`, `only_checks` can all be
  overridden per-run by CLI flags.
- `required_dashboard_region` and `required_timezone_prefix` are left
  `null` by default — set them if your compliance profile pins a region
  (see the [Australian compliance notes](#11-australian-compliance-notes)).
- `config.yaml` is already in `.gitignore`.

## 5. Running scans

### Full scan

```bash
meraki-sec -c config.yaml
```

This scans every org the API key can see, writes a Rich-formatted report to
the console, and emits `reports/meraki-sec-<timestamp>.json` and `.csv`.

### Scoped scan

```bash
meraki-sec -c config.yaml --org-id 123456
meraki-sec -c config.yaml --org-id 123456 --network-id L_987654321
```

Both flags are repeatable. CLI scope overrides anything in `config.yaml`.

### Scan a specific list of devices

```bash
meraki-sec -c config.yaml --devices my-devices.txt
```

`--devices` points to a text file with one device identifier per line. Each
line is matched (case-insensitive) against the device's **serial**, **name**,
or **MAC** — paste whichever you have handy. MACs match regardless of
separator (`aa:bb:cc:11:22:33`, `aa-bb-cc-11-22-33`, and `aabbcc112233` are
equivalent). Blank lines and lines starting with `#` are ignored.

Example `my-devices.txt`:

```text
# Critical APs and edge switches
Q2XX-AAAA-BBBB
edge-switch-01
aa:bb:cc:11:22:33
```

Behaviour:

- Device-scope checks (e.g. `MS-003`, `MV-001`) run **only** on listed devices.
- Org-scope and network-scope checks still run as normal against every org
  and network in scope — `--devices` narrows the device sweep, not the rest.
- Entries that do not match any device produce a warning at the end of the
  run, which is handy for catching typos.
- `--devices` composes with `--org-id` / `--network-id` (apply scope first,
  then filter devices within scope) and with sampling flags (a device must
  pass both filters to be scanned).

### Run a single check or a subset

```bash
meraki-sec -c config.yaml --only ORG-001
meraki-sec -c config.yaml --only MR-006 --only MS-004
meraki-sec -c config.yaml --skip MV-002 --skip MT-001
```

`--only` takes precedence over `--skip`. Both are repeatable.

### Change output formats

```bash
meraki-sec -c config.yaml --format console         # stdout only
meraki-sec -c config.yaml --format json            # file only
meraki-sec -c config.yaml --format console --format json
```

### Inspect the catalogue without scanning

```bash
meraki-sec --list-checks
```

Prints every check ID, severity, scope, product type, title, and every
framework mapping — no config or API key required.

### Verbose logging

```bash
meraki-sec -c config.yaml -v     # INFO
meraki-sec -c config.yaml -vv    # DEBUG (shows every SDK call)
```

## 6. Reading the output

### Console

The console reporter (Rich) renders three panels:

1. **Summary** — total findings, counts by status (PASS/WARN/FAIL/ERROR),
   counts by severity, a posture score from 0 (all failed) to 100
   (everything passing).
2. **Framework coverage** — for each framework (CIS, NIST CSF, CIS CSC v8,
   Cisco, Essential Eight, ISM), how many of its referenced controls passed
   vs failed in this scan.
3. **Findings** — one row per `FAIL` or `WARN` with check ID, severity, the
   target (org / network / device), the message, and the remediation hint.

### JSON

`reports/meraki-sec-YYYYMMDDTHHMMSSZ.json` structure:

```json
{
  "generated_at": "2026-04-21T10:00:00Z",
  "summary": {
    "status_counts": {"pass": 24, "fail": 6, "warn": 7, "error": 1},
    "severity_counts": {...},
    "posture_score": 78,
    "framework_rollup": {
      "CIS": {"pass": 8, "fail": 2},
      "NIST_CSF": {...}
    }
  },
  "findings": [
    {
      "check_id": "ORG-001",
      "title": "Two-factor authentication required for all admins",
      "severity": "critical",
      "status": "fail",
      "target": {"scope": "organization", "org_id": "123", "org_name": "..."},
      "message": "Org does not enforce 2FA; 3 admin(s) without 2FA",
      "remediation": "...",
      "mappings": {
        "CIS": ["1.1"],
        "NIST_CSF": ["PR.AC-1", "PR.AC-7"],
        "E8": ["E8.7"],
        "ISM": ["Authentication: MFA for privileged users"]
      },
      "sources": ["CIS Meraki 1.1", "NIST CSF PR.AC-1", ...],
      "evidence": {"admins_without_2fa": ["...@example.com"]}
    }
  ]
}
```

### CSV

One row per finding. Columns are flattened for spreadsheet-style review:

```
check_id, title, severity, status, scope, org_id, org_name,
network_id, network_name, device_serial, device_name,
message, remediation,
cis, nist_csf, cis_csc, cisco, essential_eight, asd_ism,
sources, evidence
```

Framework columns are comma-separated (semicolon for ISM/sources, which may
themselves contain commas). `evidence` is a compact JSON blob.

## 7. CI integration

`meraki-sec` exits `1` whenever at least one finding has status `FAIL`
(not `WARN`). Example GitHub Actions snippet:

```yaml
jobs:
  meraki-audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with: { python-version: "3.11" }
      - run: |
          python -m venv .venv
          .venv/bin/pip install -e .
      - name: Run meraki-sec
        env:
          MERAKI_API_KEY: ${{ secrets.MERAKI_API_KEY }}
        run: |
          sed -i "s|YOUR_MERAKI_DASHBOARD_API_KEY|$MERAKI_API_KEY|" config.example.yaml
          .venv/bin/meraki-sec -c config.example.yaml
      - uses: actions/upload-artifact@v4
        if: always()
        with:
          name: meraki-sec-reports
          path: reports/
```

Exit codes:

| Code | Meaning                             |
|------|-------------------------------------|
| 0    | No FAIL findings                    |
| 1    | At least one FAIL finding           |
| 2    | Config error (file missing, bad YAML, placeholder API key) |

## 8. Threshold tuning

Every tunable lives under `thresholds:` in `config.yaml`.

| Threshold                    | Consumed by     | Default | Notes                                             |
|------------------------------|-----------------|---------|---------------------------------------------------|
| `admin_inactive_days`        | (reserved)      | 90      | Reserved for future inactive-admin sweep          |
| `api_key_stale_days`         | ORG-009         | 90      | API keys whose owner hasn't logged in recently    |
| `firmware_versions_behind`   | (reserved)      | 2       | Reserved for stricter firmware drift control      |
| `min_wireless_bitrate_mbps`  | MR-003          | 12      | Minimum floor on RF-profile bitrates              |
| `required_dashboard_region`  | ORG-010         | null    | Exact `cloud.region.name` string, e.g. `Australia`|
| `required_timezone_prefix`   | NET-006         | null    | Prefix string, e.g. `Australia/`                  |

Lowering `api_key_stale_days` (to, say, `30`) enforces a stricter rotation
policy. Raising `min_wireless_bitrate_mbps` (to `24`) shifts MR-003 from
"default-avoidance" to "modern-radio-only" posture.

## 9. Check reference

Run `meraki-sec --list-checks` for the live, machine-readable version. The
tables below are a human summary grouped by category.

### Organization (ORG-001 … ORG-010)

| ID      | Severity | Title                                                    |
|---------|----------|----------------------------------------------------------|
| ORG-001 | critical | Two-factor authentication required for all admins        |
| ORG-002 | high     | Password complexity and rotation policy                  |
| ORG-003 | medium   | Account lockout after repeated failed logins             |
| ORG-004 | medium   | Idle session timeout configured                          |
| ORG-005 | medium   | Login IP allow-list configured                           |
| ORG-006 | medium   | SAML SSO enabled                                         |
| ORG-007 | high     | No shared or generic admin accounts                      |
| ORG-008 | medium   | Excess of full-organization admins                       |
| ORG-009 | high     | API keys are current and tied to MFA-protected admins    |
| ORG-010 | high     | Dashboard data residency matches required region         |

ORG-007 uses a heuristic — if you run legitimate service accounts named
`netops@` or similar, add them to `skip_checks` or rename them.

### Network baseline (NET-001 … NET-006)

| ID      | Severity | Title                                                     |
|---------|----------|-----------------------------------------------------------|
| NET-001 | high     | Syslog server configured (with 'Security events' role)    |
| NET-002 | high     | SNMP disabled or v3 only                                  |
| NET-003 | medium   | Alerts configured for security-relevant events            |
| NET-004 | medium   | Firmware upgrade window configured                        |
| NET-005 | medium   | Group policies do not re-enable broad access              |
| NET-006 | medium   | Network time zone configured for accurate event timestamps|

NET-005 protects against the "VIP group policy" footgun where a group-policy
`allow any/any` override silently undoes MX-004's firewall hardening.

### Appliance — MX (MX-001 … MX-008)

| ID      | Severity | Title                                                    |
|---------|----------|----------------------------------------------------------|
| MX-001  | critical | Intrusion prevention (IDS/IPS) enabled in prevention mode|
| MX-002  | high     | Advanced Malware Protection (AMP) enabled                |
| MX-003  | medium   | Content filtering blocks security-relevant categories    |
| MX-004  | high     | L3 firewall default-deny outbound rule in place          |
| MX-005  | medium   | L7 application firewall has blocking rules               |
| MX-006  | high     | Client VPN uses strong authentication                    |
| MX-007  | medium   | Site-to-site VPN uses IKEv2                              |
| MX-008  | high     | Third-party VPN peers use IKEv2 and strong crypto        |

MX-001/MX-002 require an Advanced Security license. Without it the SDK
returns 404 and the check yields `ERROR` (not `FAIL`) with a licence hint.

### Wireless — MR (MR-001 … MR-006)

| ID      | Severity | Title                                                     |
|---------|----------|-----------------------------------------------------------|
| MR-001  | critical | No open or WEP-authenticated SSIDs                        |
| MR-002  | medium   | Protected Management Frames (802.11w) enabled             |
| MR-003  | low      | Minimum data rate raised from defaults                    |
| MR-004  | high     | Guest SSID isolated from LAN                              |
| MR-005  | medium   | Air Marshal detecting rogue APs                           |
| MR-006  | high     | Corporate SSIDs use 802.1X (WPA2/3-Enterprise)            |

A "guest" SSID is heuristically detected when the SSID name contains the
word `guest` or `visitor`, OR when it has any splash page configured. MR-006
only evaluates SSIDs that do **not** match the guest heuristic.

### Switching — MS (MS-001 … MS-005)

| ID      | Severity | Title                                                |
|---------|----------|------------------------------------------------------|
| MS-001  | high     | Rogue DHCP server blocking enabled                   |
| MS-002  | medium   | Storm control enabled                                |
| MS-003  | high     | BPDU guard enabled on access ports                   |
| MS-004  | medium   | 802.1X access policy bound to edge ports             |
| MS-005  | low      | Disabled ports are administratively down             |

MS-005 uses a heuristic (enabled access port, default VLAN, no name) and is
deliberately low severity. If your site legitimately uses unlabelled
patch-panel ports, skip it.

### Cameras — MV (MV-001, MV-002)

| ID      | Severity | Title                                                    |
|---------|----------|----------------------------------------------------------|
| MV-001  | medium   | External RTSP disabled unless explicitly required        |
| MV-002  | low      | Camera has motion-based / continuous retention configured|

### Sensors — MT (MT-001)

| ID      | Severity | Title                               |
|---------|----------|-------------------------------------|
| MT-001  | low      | Sensor alert profiles configured    |

## 10. Framework mappings at a glance

Every check carries some subset of these framework references. The CSV
report has a dedicated column per framework; the JSON report carries them
under `mappings`.

| Framework              | Key in JSON     | CSV column         | Reference style               |
|------------------------|-----------------|--------------------|-------------------------------|
| CIS Cisco Meraki       | `CIS`           | `cis`              | `1.1`, `3.2`, ...             |
| NIST CSF               | `NIST_CSF`      | `nist_csf`         | `PR.AC-1`, `DE.CM-1`, ...     |
| CIS Controls v8        | `CIS_CSC`       | `cis_csc`          | `6.5`, `13.3`, ...            |
| Cisco Meraki best prac | `Cisco`         | `cisco`            | Free-text doc title           |
| ASD Essential Eight    | `E8`            | `essential_eight`  | `E8.2`, `E8.5`, `E8.7`        |
| ASD ISM                | `ISM`           | `asd_ism`          | `Category: Control`           |

Full list: `meraki-sec --list-checks` shows every framework reference.

## 11. Australian compliance notes

Three checks are specifically shaped for Australian regulatory contexts:

**ORG-010 — Dashboard data residency.** ASD ISM and PSPF INFOSEC-8 require
management-plane data to stay in Australian sovereign infrastructure. Set
`required_dashboard_region: "Australia"` to fail any org hosted outside it.
If this check fails, Cisco cannot migrate an org between regions — you must
provision a new org in the right region and migrate configuration across.

**NET-006 — Network time zone.** Meraki devices auto-sync NTP against Cisco
infrastructure, so the only time control you own is the network's time zone
string. Wrong or unset time zones corrupt syslog timestamps and defeat
IR correlation. Set `required_timezone_prefix: "Australia/"` to warn on
misaligned zones.

**MX-008 — Third-party VPN cipher strength.** Non-Meraki VPN peers often
default to IKEv1 and legacy ciphers for interop. ASD ISM requires IKEv2 with
AES-256 (or AES-128-GCM), SHA-256+ integrity, and DH group 14 or stronger.
The check flags `3DES`, `AES-128`, `MD5`, `SHA-1`, and DH groups `1/2/5` as
weak, and fails on any IKEv1 peer.

Essential Eight mapping summary — checks tagged with an E8 control:

| E8 control | Name                                 | Checks tagged                            |
|------------|--------------------------------------|------------------------------------------|
| E8.2       | Patch applications (firmware)        | NET-004                                  |
| E8.5       | Restrict administrative privileges   | ORG-005, ORG-007, ORG-008, ORG-009, NET-005 |
| E8.6       | Patch operating systems (firmware)   | NET-004                                  |
| E8.7       | Multi-factor authentication          | ORG-001, ORG-006, ORG-009, MX-006, MR-006, MS-004 |

## 12. Troubleshooting

**"error: config file not found: config.yaml"**
Copy the example: `cp config.example.yaml config.yaml` and edit it.

**"api_key not set" or similar `ValueError` from Config.load**
You still have `YOUR_MERAKI_DASHBOARD_API_KEY` as a placeholder in
`config.yaml`. Replace it with the real 40-character key.

**All `ORG-` checks return `ERROR: login security API unavailable`**
The API key is valid but lacks permission on that org, or the key belongs to
a network-level admin. Generate a key from an org-level admin account.

**Checks run but `FAIL` with `API unavailable (license required?)`**
MX-001 (IPS) and MX-002 (AMP) require an Advanced Security license. Without
it, Meraki returns 404 and the check reports `ERROR` rather than `FAIL`.
This is expected and will not break CI.

**Rate-limit 429 errors**
The Meraki SDK is configured with `wait_on_rate_limit=True` and retries up
to 3 times. If you are scanning a very large org and still hit limits, run
with a narrower `--org-id` scope or spread scans across the day.

**Scan takes a long time**
The runtime is dominated by per-device SDK calls (MS-003, MS-005, MV-001,
etc). `meraki-sec` caches every endpoint per-run (`lru_cache`), so each
unique URL is fetched exactly once. If you want a fast org-level smoke
check, use `--only ORG-001 --only ORG-010 --only NET-001` etc.

**Python version errors**
`meraki-sec` requires Python 3.10+. Older CPython versions lack the
`X | None` syntax used across the codebase.

## 13. Extending the tool

Checks live in `src/meraki_sec/checks/<area>.py`. To add a new check:

1. Pick an ID that fits the scheme (e.g. `MX-009`, `ORG-011`).
2. Decide scope (`Scope.ORG`, `Scope.NETWORK`, `Scope.DEVICE`) and, for
   network/device checks, the `product_type` (`appliance`, `wireless`,
   `switch`, `camera`, `sensor`).
3. If you need a new SDK endpoint, add a cached wrapper to
   `src/meraki_sec/client.py` using the `@_lru_cached` pattern used by
   existing methods.
4. Write the check function with `@check(...)` and the framework kwargs you
   know apply. Yield `passed`, `failed`, `warned`, `errored`, or
   `not_applicable` findings.
5. No registration step — the decorator appends to `REGISTRY` on import,
   and `src/meraki_sec/checks/__init__.py` already imports every module.

Example skeleton:

```python
@check(
    id="MX-009",
    title="Description of the control",
    severity=Severity.MEDIUM,
    scope=Scope.NETWORK,
    product_type="appliance",
    cis=["3.5"],
    nist_csf=["PR.PT-4"],
    cis_csc=["4.2"],
    cisco=["Meraki ... Best Practice"],
    asd_ism=["Gateways: ..."],
    description="Why this matters.",
)
def my_new_check(ctx: CheckContext):
    meta = my_new_check.meta
    net = ctx.network or {}
    data = ctx.client.my_endpoint(net["id"])
    if data is None:
        yield errored(meta, ctx, "API unavailable")
        return
    if not data.get("enabled"):
        yield failed(meta, ctx, "feature disabled",
                     remediation="Dashboard > path > enable.")
    else:
        yield passed(meta, ctx, "feature enabled")
```

Verify the new check registered by running `meraki-sec --list-checks`.
