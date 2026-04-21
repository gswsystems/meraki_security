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
    id="MV-001",
    title="External RTSP disabled unless explicitly required",
    severity=Severity.MEDIUM,
    scope=Scope.DEVICE,
    product_type="camera",
    nist_csf=["PR.DS-2"],
    cis_csc=["4.2", "12.2"],
    cisco=["Meraki MV Security"],
    asd_ism=["Communications: Unencrypted streaming protocols"],
    description="RTSP exposes unencrypted video streams to anyone on the local network.",
)
def rtsp_disabled(ctx: CheckContext):
    meta = rtsp_disabled.meta
    dev = ctx.device or {}
    vs = ctx.client.camera_video_settings(dev.get("serial", ""))
    if vs is None:
        yield errored(meta, ctx, "camera video settings unavailable")
        return
    if vs.get("externalRtspEnabled"):
        yield warned(
            meta, ctx,
            "External RTSP is enabled",
            remediation="Cameras > Settings > Video: disable external RTSP unless a specific VMS requires it.",
        )
    else:
        yield passed(meta, ctx, "external RTSP disabled")


@check(
    id="MV-002",
    title="Camera has motion-based / continuous retention configured",
    severity=Severity.LOW,
    scope=Scope.DEVICE,
    product_type="camera",
    cisco=["Meraki MV Sense"],
)
def camera_sense(ctx: CheckContext):
    meta = camera_sense.meta
    dev = ctx.device or {}
    sense = ctx.client.camera_sense(dev.get("serial", ""))
    if sense is None:
        yield passed(meta, ctx, "Sense not applicable")
        return
    if not sense.get("senseEnabled"):
        yield warned(meta, ctx, "MV Sense disabled — no motion-based analytics")
    else:
        yield passed(meta, ctx, "MV Sense enabled")
