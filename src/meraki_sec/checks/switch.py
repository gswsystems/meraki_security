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


@check(
    id="MS-001",
    title="Rogue DHCP server blocking enabled",
    severity=Severity.HIGH,
    scope=Scope.NETWORK,
    product_type="switch",
    cis=["5.1"],
    nist_csf=["PR.AC-5", "DE.CM-1"],
    cis_csc=["12.2", "13.10"],
    cisco=["Meraki MS DHCP Snooping"],
    asd_ism=["Network Design: DHCP snooping"],
    description="Without DHCP server policy, a rogue DHCP can redirect clients to a malicious gateway.",
)
def dhcp_server_policy(ctx: CheckContext):
    meta = dhcp_server_policy.meta
    net = ctx.network or {}
    pol = ctx.client.switch_dhcp_server_policy(net["id"])
    if pol is None:
        yield errored(meta, ctx, "DHCP server policy API unavailable")
        return
    default = (pol.get("defaultPolicy") or "allow").lower()
    if default == "block":
        yield passed(meta, ctx, "default DHCP server policy = block")
    else:
        yield failed(
            meta, ctx,
            f"Default DHCP server policy is '{default}'",
            remediation="Switch > Switch settings > DHCP server policy: set default to 'block' and allow-list known servers.",
        )


@check(
    id="MS-002",
    title="Storm control enabled",
    severity=Severity.MEDIUM,
    scope=Scope.NETWORK,
    product_type="switch",
    nist_csf=["PR.PT-4"],
    cis_csc=["12.2"],
    cisco=["Meraki Storm Control"],
    asd_ism=["Network Design: Broadcast storm control"],
)
def storm_control(ctx: CheckContext):
    meta = storm_control.meta
    net = ctx.network or {}
    sc = ctx.client.switch_storm_control(net["id"])
    if sc is None:
        yield passed(meta, ctx, "storm control not configurable on this network")
        return
    any_set = any(sc.get(k) for k in ("broadcastThreshold", "multicastThreshold", "unknownUnicastThreshold"))
    if any_set:
        yield passed(meta, ctx, f"storm control configured: {sc}")
    else:
        yield warned(
            meta, ctx,
            "Storm control thresholds not configured",
            remediation="Switch > Switch settings > Storm control: set thresholds for broadcast/multicast/unknown-unicast.",
        )


@check(
    id="MS-003",
    title="BPDU guard enabled on access ports",
    severity=Severity.HIGH,
    scope=Scope.DEVICE,
    product_type="switch",
    nist_csf=["PR.AC-5", "PR.PT-4"],
    cis_csc=["12.2"],
    cisco=["Meraki MS STP Guard"],
    asd_ism=["Network Design: Spanning tree protection"],
)
def bpdu_guard(ctx: CheckContext):
    meta = bpdu_guard.meta
    dev = ctx.device or {}
    ports = ctx.client.switch_ports(dev.get("serial", "")) or []
    access_ports = [p for p in ports if (p.get("type") or "").lower() == "access" and p.get("enabled")]
    if not access_ports:
        yield passed(meta, ctx, "no enabled access ports")
        return
    missing = [p.get("portId") for p in access_ports if not p.get("stpGuard") or p.get("stpGuard") == "disabled"]
    if missing:
        yield warned(
            meta, ctx,
            f"{len(missing)} access port(s) without STP guard: {missing[:10]}{'…' if len(missing) > 10 else ''}",
            remediation="Enable 'BPDU guard' (stpGuard=bpdu guard) on edge/access ports.",
            evidence={"ports_without_bpdu_guard": missing},
        )
    else:
        yield passed(meta, ctx, "BPDU guard on all access ports")


@check(
    id="MS-004",
    title="802.1X access policy bound to edge ports",
    severity=Severity.MEDIUM,
    scope=Scope.NETWORK,
    product_type="switch",
    cis=["5.2"],
    nist_csf=["PR.AC-1", "PR.AC-5"],
    cis_csc=["6.5", "13.9"],
    cisco=["Meraki Switch Access Policies"],
    essential_eight=["E8.7"],
    asd_ism=["Network Access: 802.1X authentication"],
)
def dot1x_policy(ctx: CheckContext):
    meta = dot1x_policy.meta
    net = ctx.network or {}
    pols = ctx.client.switch_access_policies(net["id"]) or []
    active = [p for p in pols if (p.get("accessPolicyType") or "").lower() != "open"]
    if not active:
        yield warned(
            meta, ctx,
            "No 802.1X / MAB access policies defined",
            remediation="Add at least one access policy with RADIUS auth and bind it to wired access ports.",
        )
    else:
        yield passed(meta, ctx, f"{len(active)} access polic(ies) defined")


@check(
    id="MS-005",
    title="Disabled ports are administratively down",
    severity=Severity.LOW,
    scope=Scope.DEVICE,
    product_type="switch",
    nist_csf=["PR.AC-5"],
    cis_csc=["12.4"],
    cisco=["Meraki Port Hygiene"],
    asd_ism=["Network Design: Physical port security"],
    description="Unused ports left enabled become a drop-in attacker surface in open offices.",
)
def unused_ports_disabled(ctx: CheckContext):
    meta = unused_ports_disabled.meta
    dev = ctx.device or {}
    ports = ctx.client.switch_ports(dev.get("serial", "")) or []
    suspicious = [
        p.get("portId") for p in ports
        if p.get("enabled") and (p.get("type") or "").lower() == "access"
        and p.get("vlan") in (None, 1) and not p.get("name")
    ]
    if len(suspicious) > 4:
        yield warned(
            meta, ctx,
            f"{len(suspicious)} enabled access port(s) on default VLAN with no name — likely unused",
            remediation="Disable unused ports or assign them to a quarantine VLAN.",
            evidence={"ports": suspicious[:25]},
        )
    else:
        yield passed(meta, ctx, "port hygiene acceptable")
