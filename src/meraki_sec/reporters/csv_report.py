from __future__ import annotations

import csv
import json
from datetime import datetime, timezone
from pathlib import Path

from meraki_sec.models import Finding


_HEADERS = [
    "check_id", "title", "severity", "status",
    "scope", "org_id", "org_name", "network_id", "network_name",
    "device_serial", "device_name",
    "message", "remediation",
    "cis", "nist_csf", "cis_csc", "cisco",
    "essential_eight", "asd_ism",
    "sources", "evidence",
]


def write(findings: list[Finding], out_dir: Path) -> Path:
    out_dir.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    path = out_dir / f"meraki-sec-{stamp}.csv"
    with path.open("w", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(_HEADERS)
        for f in findings:
            t = f.target
            m = f.mappings or {}
            w.writerow([
                f.check_id,
                f.title,
                f.severity.value,
                f.status.value,
                t.scope.value,
                t.org_id or "",
                t.org_name or "",
                t.network_id or "",
                t.network_name or "",
                t.device_serial or "",
                t.device_name or "",
                f.message,
                f.remediation,
                ", ".join(m.get("CIS", [])),
                ", ".join(m.get("NIST_CSF", [])),
                ", ".join(m.get("CIS_CSC", [])),
                ", ".join(m.get("Cisco", [])),
                ", ".join(m.get("E8", [])),
                "; ".join(m.get("ISM", [])),
                "; ".join(f.sources),
                json.dumps(f.evidence, sort_keys=True) if f.evidence else "",
            ])
    return path
