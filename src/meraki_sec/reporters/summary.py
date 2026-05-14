from __future__ import annotations

import re
from collections import Counter

from meraki_sec.models import Finding, SEVERITY_WEIGHT, Status


def report_scope_slug(findings: list[Finding]) -> str:
    """Filename-safe slug describing what the report covers.

    Picks the network name when the run is scoped to a single network, the org
    name when scoped to a single org, else returns "" (timestamp-only file).
    """
    if not findings:
        return ""
    networks = {
        (f.target.network_id, f.target.network_name)
        for f in findings
        if f.target.network_id
    }
    if len(networks) == 1:
        _, name = next(iter(networks))
        return _slugify(name or "")
    orgs = {
        (f.target.org_id, f.target.org_name)
        for f in findings
        if f.target.org_id
    }
    if len(orgs) == 1:
        _, name = next(iter(orgs))
        return _slugify(name or "")
    return ""


def _slugify(s: str) -> str:
    s = re.sub(r"[^A-Za-z0-9]+", "-", s.strip())
    return s.strip("-").lower()


def compute_summary(findings: list[Finding]) -> dict:
    status_counts = Counter(f.status.value for f in findings)
    severity_counts = Counter(
        f.severity.value for f in findings if f.status in (Status.FAIL, Status.WARN)
    )

    # Risk score: sum of severity weights across failing/warning findings.
    # Warnings count at half weight.
    raw = 0
    for f in findings:
        w = SEVERITY_WEIGHT.get(f.severity, 0)
        if f.status == Status.FAIL:
            raw += w
        elif f.status == Status.WARN:
            raw += w // 2
    # Normalize to a 0-100 "posture score" where 100 = clean.
    # We cap raw at a reasonable ceiling so a few crits don't dominate.
    ceiling = max(1, 10 * len(findings))
    posture = max(0, 100 - int(100 * raw / ceiling))

    # Per-framework pass/fail rollup (unique checks, not finding instances).
    framework_rollup: dict[str, dict[str, int]] = {}
    seen: dict[str, dict[str, set[str]]] = {}
    for f in findings:
        for fw, refs in (f.mappings or {}).items():
            fw_state = seen.setdefault(fw, {"pass": set(), "fail": set()})
            bucket = "fail" if f.status in (Status.FAIL, Status.WARN, Status.ERROR) else "pass"
            for ref in refs:
                key = f"{f.check_id}:{ref}"
                # If any instance fails, consider it failing for that framework reference.
                if bucket == "fail":
                    fw_state["fail"].add(key)
                    fw_state["pass"].discard(key)
                elif key not in fw_state["fail"]:
                    fw_state["pass"].add(key)
    for fw, state in seen.items():
        framework_rollup[fw] = {
            "pass": len(state["pass"]),
            "fail": len(state["fail"]),
        }

    return {
        "total_findings": len(findings),
        "status_counts": dict(status_counts),
        "severity_counts": dict(severity_counts),
        "risk_score_raw": raw,
        "posture_score": posture,
        "framework_rollup": framework_rollup,
    }
