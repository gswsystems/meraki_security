from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Iterable

from meraki_sec.client import MerakiClient
from meraki_sec.models import (
    CheckMeta,
    FRAMEWORK_LABELS,
    Finding,
    Scope,
    Severity,
    Status,
    Target,
)


@dataclass
class CheckContext:
    """Everything a check function needs to run."""
    client: MerakiClient
    thresholds: dict
    # Scope-specific handles. Only some are populated depending on the check.
    org: dict | None = None
    network: dict | None = None
    device: dict | None = None

    def target(self) -> Target:
        if self.device:
            net_id = (self.network or {}).get("id") if self.network else None
            net_name = (self.network or {}).get("name") if self.network else None
            org_id = (self.org or {}).get("id") if self.org else None
            org_name = (self.org or {}).get("name") if self.org else None
            return Target(
                scope=Scope.DEVICE,
                org_id=org_id, org_name=org_name,
                network_id=net_id, network_name=net_name,
                device_serial=self.device.get("serial"),
                device_name=self.device.get("name") or self.device.get("mac"),
            )
        if self.network:
            return Target(
                scope=Scope.NETWORK,
                org_id=(self.org or {}).get("id") if self.org else None,
                org_name=(self.org or {}).get("name") if self.org else None,
                network_id=self.network.get("id"),
                network_name=self.network.get("name"),
            )
        if self.org:
            return Target(
                scope=Scope.ORG,
                org_id=self.org.get("id"),
                org_name=self.org.get("name"),
            )
        return Target(scope=Scope.ORG)


# Each check function receives a CheckContext and returns zero or more findings.
CheckFn = Callable[[CheckContext], Iterable[Finding]]


@dataclass
class Check:
    meta: CheckMeta
    fn: CheckFn


# Module-level registry populated by the @check decorator.
REGISTRY: list[Check] = []


def check(
    *,
    id: str,
    title: str,
    severity: Severity,
    scope: Scope,
    product_type: str | None = None,
    cis: list[str] | None = None,
    nist_csf: list[str] | None = None,
    cis_csc: list[str] | None = None,
    cisco: list[str] | None = None,
    essential_eight: list[str] | None = None,
    asd_ism: list[str] | None = None,
    sources: list[str] | None = None,
    description: str = "",
) -> Callable[[CheckFn], CheckFn]:
    def deco(fn: CheckFn) -> CheckFn:
        mappings: dict[str, list[str]] = {}
        if cis:
            mappings["CIS"] = list(cis)
        if nist_csf:
            mappings["NIST_CSF"] = list(nist_csf)
        if cis_csc:
            mappings["CIS_CSC"] = list(cis_csc)
        if cisco:
            mappings["Cisco"] = list(cisco)
        if essential_eight:
            mappings["E8"] = list(essential_eight)
        if asd_ism:
            mappings["ISM"] = list(asd_ism)

        # Auto-derive readable source strings from structured mappings.
        derived: list[str] = []
        for fw, ids in mappings.items():
            label = FRAMEWORK_LABELS.get(fw, fw)
            for ref in ids:
                derived.append(f"{label} {ref}")
        all_sources = list(sources or []) + derived

        meta = CheckMeta(
            id=id,
            title=title,
            severity=severity,
            scope=scope,
            product_type=product_type,
            sources=all_sources,
            mappings=mappings,
            description=description,
        )
        REGISTRY.append(Check(meta=meta, fn=fn))
        fn.meta = meta  # type: ignore[attr-defined]
        return fn
    return deco


# ----- finding helpers used by check bodies -----

def finding(
    meta: CheckMeta,
    ctx: CheckContext,
    status: Status,
    message: str,
    remediation: str = "",
    evidence: dict | None = None,
) -> Finding:
    return Finding(
        check_id=meta.id,
        title=meta.title,
        severity=meta.severity if status in (Status.FAIL, Status.WARN) else Severity.INFO,
        status=status,
        target=ctx.target(),
        message=message,
        remediation=remediation,
        sources=list(meta.sources),
        mappings={k: list(v) for k, v in meta.mappings.items()},
        evidence=evidence or {},
    )


def passed(meta: CheckMeta, ctx: CheckContext, message: str = "OK") -> Finding:
    return finding(meta, ctx, Status.PASS, message)


def failed(
    meta: CheckMeta,
    ctx: CheckContext,
    message: str,
    remediation: str = "",
    evidence: dict | None = None,
) -> Finding:
    return finding(meta, ctx, Status.FAIL, message, remediation, evidence)


def warned(
    meta: CheckMeta,
    ctx: CheckContext,
    message: str,
    remediation: str = "",
    evidence: dict | None = None,
) -> Finding:
    return finding(meta, ctx, Status.WARN, message, remediation, evidence)


def errored(meta: CheckMeta, ctx: CheckContext, message: str) -> Finding:
    return finding(meta, ctx, Status.ERROR, message)


def not_applicable(meta: CheckMeta, ctx: CheckContext, reason: str) -> Finding:
    return finding(meta, ctx, Status.NOT_APPLICABLE, reason)
