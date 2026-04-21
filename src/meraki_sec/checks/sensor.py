from __future__ import annotations

from meraki_sec.checks.base import (
    CheckContext,
    check,
    errored,
    passed,
    warned,
)
from meraki_sec.models import Scope, Severity


@check(
    id="MT-001",
    title="Sensor alert profiles configured",
    severity=Severity.LOW,
    scope=Scope.NETWORK,
    product_type="sensor",
    nist_csf=["DE.CM-1"],
    cis_csc=["8.11"],
    cisco=["Meraki MT Alert Profiles"],
    asd_ism=["System Monitoring: Environmental monitoring"],
    description="MT sensors are only useful if alert profiles wake someone up on threshold violations.",
)
def sensor_alerts(ctx: CheckContext):
    meta = sensor_alerts.meta
    net = ctx.network or {}
    try:
        profiles = ctx.client.sensor_alerts_profiles(net["id"]) or []
    except Exception:
        profiles = None
    if profiles is None:
        yield errored(meta, ctx, "sensor alerts API unavailable")
        return
    if not profiles:
        yield warned(
            meta, ctx,
            "No MT alert profiles defined",
            remediation="Environmental > Alert profiles: add thresholds for temperature/humidity/door/water as relevant.",
        )
    else:
        yield passed(meta, ctx, f"{len(profiles)} alert profile(s)")
