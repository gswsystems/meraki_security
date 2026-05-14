from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from meraki_sec.models import Finding
from meraki_sec.reporters.summary import compute_summary, report_scope_slug


def write(findings: list[Finding], out_dir: Path) -> Path:
    out_dir.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    slug = report_scope_slug(findings)
    name = f"meraki-sec-{slug}-{stamp}.json" if slug else f"meraki-sec-{stamp}.json"
    path = out_dir / name
    payload = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "summary": compute_summary(findings),
        "findings": [f.to_dict() for f in findings],
    }
    path.write_text(json.dumps(payload, indent=2, sort_keys=True))
    return path
