from __future__ import annotations

from meraki_sec.checks.base import (
    CheckContext,
    check,
    errored,
    failed,
    passed,
    warned,
)
from meraki_sec.models import Scope, Severity

WEAK_AUTH_MODES = {"open", "wep"}
WEAK_ENCRYPTION = {"wep", "wpa"}
# Meraki auth modes that count as "enterprise" (802.1X).
ENTERPRISE_AUTH_MODES = {
    "8021x-radius",
    "8021x-meraki",
    "8021x-localradius",
    "8021x-entra",
    "8021x-google",
    "ipsk-with-radius",
    "ipsk-without-radius",  # still key-per-client, not shared
}


def _is_guest(ssid: dict) -> bool:
    """Heuristic: SSID is 'guest' if named guest OR uses a splash/captive portal."""
    name = (ssid.get("name") or "").lower()
    splash = (ssid.get("splashPage") or "none").lower()
    return "guest" in name or "visitor" in name or splash not in ("none", "")


@check(
    id="MR-001",
    title="No open or WEP-authenticated SSIDs",
    severity=Severity.CRITICAL,
    scope=Scope.NETWORK,
    product_type="wireless",
    cis=["4.1"],
    nist_csf=["PR.AC-5", "PR.DS-2"],
    cis_csc=["12.6"],
    cisco=["Meraki MR Wireless Security Best Practices"],
    asd_ism=["Wireless Networks: Authentication", "Wireless Networks: Encryption"],
)
def no_open_or_wep(ctx: CheckContext):
    meta = no_open_or_wep.meta
    net = ctx.network or {}
    ssids = ctx.client.wireless_ssids(net["id"]) or []
    bad: list[str] = []
    for s in ssids:
        if not s.get("enabled"):
            continue
        auth = (s.get("authMode") or "").lower()
        enc = (s.get("encryptionMode") or "").lower()
        name = s.get("name") or f"SSID{s.get('number')}"
        splash = (s.get("splashPage") or "none").lower()
        if auth == "open" and splash in ("none", ""):
            bad.append(f"{name}: open (no splash)")
        elif auth == "psk" and enc in WEAK_ENCRYPTION:
            bad.append(f"{name}: {enc.upper()} encryption")
        elif auth in WEAK_AUTH_MODES and auth != "open":
            bad.append(f"{name}: {auth.upper()} auth")
    if bad:
        yield failed(
            meta, ctx,
            f"{len(bad)} weakly secured SSID(s): " + "; ".join(bad),
            remediation="Use WPA2/WPA3 PSK or 802.1X; require a splash page on any open SSID.",
            evidence={"weak_ssids": bad},
        )
    else:
        yield passed(meta, ctx, "no open/WEP SSIDs")


@check(
    id="MR-002",
    title="Protected Management Frames (802.11w) enabled",
    severity=Severity.MEDIUM,
    scope=Scope.NETWORK,
    product_type="wireless",
    nist_csf=["PR.DS-2", "PR.PT-4"],
    cis_csc=["12.6"],
    cisco=["Meraki 802.11w Configuration"],
    asd_ism=["Wireless Networks: Management frame protection"],
    description="802.11w prevents deauth/disassoc attacks.",
)
def pmf_enabled(ctx: CheckContext):
    meta = pmf_enabled.meta
    net = ctx.network or {}
    ssids = ctx.client.wireless_ssids(net["id"]) or []
    weak: list[str] = []
    for s in ssids:
        if not s.get("enabled"):
            continue
        pmf = (s.get("dot11w") or {}).get("enabled")
        required = (s.get("dot11w") or {}).get("required")
        if not pmf and not required:
            weak.append(s.get("name") or f"SSID{s.get('number')}")
    if weak:
        yield warned(
            meta, ctx,
            f"{len(weak)} SSID(s) do not enable 802.11w: " + ", ".join(weak),
            remediation="Enable (or require) 802.11w on WPA2/WPA3 SSIDs.",
        )
    else:
        yield passed(meta, ctx, "all enabled SSIDs use 802.11w")


@check(
    id="MR-003",
    title="Minimum data rate raised from defaults",
    severity=Severity.LOW,
    scope=Scope.NETWORK,
    product_type="wireless",
    nist_csf=["PR.PT-4"],
    cisco=["Meraki RF Profile Tuning"],
    asd_ism=["Wireless Networks: Signal coverage"],
    description="Low bitrates extend the effective attack surface of an SSID.",
)
def min_bitrate(ctx: CheckContext):
    meta = min_bitrate.meta
    net = ctx.network or {}
    threshold = int(ctx.thresholds.get("min_wireless_bitrate_mbps", 12))
    ssids = ctx.client.wireless_ssids(net["id"]) or []
    low: list[str] = []
    for s in ssids:
        if not s.get("enabled"):
            continue
        rate = s.get("minBitrate")
        if isinstance(rate, (int, float)) and rate < threshold:
            low.append(f"{s.get('name')}: {rate} Mbps")
    if low:
        yield warned(
            meta, ctx,
            f"{len(low)} SSID(s) below {threshold} Mbps min bitrate: " + ", ".join(low),
        )
    else:
        yield passed(meta, ctx, f"min bitrate >= {threshold} Mbps on all SSIDs")


@check(
    id="MR-004",
    title="Guest SSID isolated from LAN",
    severity=Severity.HIGH,
    scope=Scope.NETWORK,
    product_type="wireless",
    cis=["4.2"],
    nist_csf=["PR.AC-5"],
    cis_csc=["12.8"],
    cisco=["Meraki Guest Network Best Practices"],
    asd_ism=["Wireless Networks: Network segregation"],
)
def guest_isolation(ctx: CheckContext):
    meta = guest_isolation.meta
    net = ctx.network or {}
    ssids = ctx.client.wireless_ssids(net["id"]) or []
    offenders: list[str] = []
    for s in ssids:
        if not s.get("enabled"):
            continue
        if not _is_guest(s):
            continue
        if s.get("ipAssignmentMode") != "NAT mode":
            l3 = ctx.client.wireless_ssid_firewall_l3(net["id"], int(s.get("number", 0)))
            rules = (l3 or {}).get("rules") or []
            blocks_lan = any(
                (r.get("policy") == "deny"
                 and (r.get("destCidr") or "").lower() == "local lan")
                for r in rules
            )
            if not blocks_lan:
                offenders.append(s.get("name") or f"SSID{s.get('number')}")
    if offenders:
        yield failed(
            meta, ctx,
            f"{len(offenders)} guest SSID(s) not isolated from LAN: " + ", ".join(offenders),
            remediation="Use NAT mode, or add a Local LAN deny rule in the SSID L3 firewall.",
        )
    else:
        yield passed(meta, ctx, "guest SSIDs isolated")


@check(
    id="MR-005",
    title="Air Marshal detecting rogue APs",
    severity=Severity.MEDIUM,
    scope=Scope.NETWORK,
    product_type="wireless",
    nist_csf=["DE.CM-7"],
    cis_csc=["12.5"],
    cisco=["Meraki Air Marshal"],
    asd_ism=["Wireless Networks: Rogue access point detection"],
)
def air_marshal(ctx: CheckContext):
    meta = air_marshal.meta
    net = ctx.network or {}
    try:
        data = ctx.client.wireless_air_marshal(net["id"])
    except Exception:
        data = None
    if data is None:
        yield errored(meta, ctx, "Air Marshal API unavailable")
        return
    yield passed(meta, ctx, f"Air Marshal active ({len(data)} entries observed)")


@check(
    id="MR-006",
    title="Corporate SSIDs use 802.1X (WPA2/3-Enterprise)",
    severity=Severity.HIGH,
    scope=Scope.NETWORK,
    product_type="wireless",
    cis=["4.3"],
    nist_csf=["PR.AC-1", "PR.AC-5"],
    cis_csc=["6.5", "12.6"],
    cisco=["Meraki Enterprise SSID Authentication"],
    essential_eight=["E8.7"],
    asd_ism=["Wireless Networks: Enterprise authentication"],
    description=(
        "Corporate (non-guest) SSIDs should authenticate users against an identity source "
        "via 802.1X / WPA2-Enterprise or WPA3-Enterprise. Shared PSKs make revocation painful "
        "and complicate audit trails."
    ),
)
def corporate_ssid_enterprise_auth(ctx: CheckContext):
    meta = corporate_ssid_enterprise_auth.meta
    net = ctx.network or {}
    ssids = ctx.client.wireless_ssids(net["id"]) or []
    weak_corp: list[str] = []
    examined = 0
    for s in ssids:
        if not s.get("enabled"):
            continue
        if _is_guest(s):
            continue
        examined += 1
        auth = (s.get("authMode") or "").lower()
        wpa_enc = (s.get("wpaEncryptionMode") or "").lower()
        is_enterprise = (
            auth in ENTERPRISE_AUTH_MODES
            or "enterprise" in auth
            or "enterprise" in wpa_enc
        )
        if not is_enterprise:
            weak_corp.append(f"{s.get('name')}: authMode={auth or '(none)'}")
    if examined == 0:
        yield passed(meta, ctx, "no corporate SSIDs to evaluate")
        return
    if weak_corp:
        yield warned(
            meta, ctx,
            f"{len(weak_corp)}/{examined} corporate SSID(s) not using 802.1X: "
            + "; ".join(weak_corp),
            remediation=(
                "Configure 802.1X with RADIUS (Meraki Auth, Entra, Google, or a local RADIUS) "
                "or WPA3-Enterprise for non-guest SSIDs."
            ),
            evidence={"corporate_ssids_examined": examined},
        )
    else:
        yield passed(meta, ctx, f"{examined} corporate SSID(s) use enterprise auth")
