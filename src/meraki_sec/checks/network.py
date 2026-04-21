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
    id="NET-001",
    title="Syslog server configured",
    severity=Severity.HIGH,
    scope=Scope.NETWORK,
    cis=["2.1"],
    nist_csf=["DE.CM-1", "DE.CM-7", "PR.PT-1"],
    cis_csc=["8.2", "8.9"],
    cisco=["Meraki Syslog Best Practices"],
    asd_ism=["System Monitoring: Event logging"],
    description="Without syslog, security events evaporate after the dashboard retention window.",
)
def syslog_configured(ctx: CheckContext):
    meta = syslog_configured.meta
    net = ctx.network or {}
    syslog = ctx.client.network_syslog(net["id"])
    if syslog is None:
        yield errored(meta, ctx, "syslog API unavailable")
        return
    servers = syslog.get("servers") or []
    if not servers:
        yield failed(
            meta, ctx,
            "No syslog servers configured",
            remediation="Network-wide > General: add at least one syslog server with security/event roles.",
        )
        return
    has_security = any("Security events" in (s.get("roles") or []) for s in servers)
    if not has_security:
        yield warned(
            meta, ctx,
            f"{len(servers)} syslog server(s) but none receive 'Security events'",
            evidence={"servers": servers},
        )
    else:
        yield passed(meta, ctx, f"{len(servers)} syslog server(s) including security events")


@check(
    id="NET-002",
    title="SNMP disabled or v3 only",
    severity=Severity.HIGH,
    scope=Scope.NETWORK,
    cis=["2.2"],
    nist_csf=["PR.AC-5", "PR.DS-2"],
    cis_csc=["3.10", "4.1"],
    asd_ism=["System Hardening: SNMP"],
    description="SNMP v1/v2c transmits community strings in the clear.",
)
def snmp_v3_only(ctx: CheckContext):
    meta = snmp_v3_only.meta
    net = ctx.network or {}
    snmp = ctx.client.network_snmp(net["id"])
    if snmp is None:
        yield errored(meta, ctx, "SNMP API unavailable")
        return
    access = (snmp.get("access") or "none").lower()
    if access in ("none", ""):
        yield passed(meta, ctx, "SNMP disabled")
        return
    if access == "users":
        yield passed(meta, ctx, "SNMP v3 (users) in use")
        return
    yield failed(
        meta, ctx,
        f"SNMP access is '{access}' — v1/v2c is insecure",
        remediation="Switch to SNMP v3 (users) or disable SNMP.",
        evidence={"access": access},
    )


@check(
    id="NET-003",
    title="Alerts configured for security-relevant events",
    severity=Severity.MEDIUM,
    scope=Scope.NETWORK,
    nist_csf=["DE.CM-1", "DE.AE-2"],
    cis_csc=["8.11"],
    cisco=["Meraki Alerts Configuration"],
    asd_ism=["System Monitoring: Event alerting"],
)
def alerts_configured(ctx: CheckContext):
    meta = alerts_configured.meta
    net = ctx.network or {}
    data = ctx.client.network_alerts(net["id"])
    if data is None:
        yield errored(meta, ctx, "alerts API unavailable")
        return
    alerts = data.get("alerts") or []
    enabled = [a for a in alerts if a.get("enabled")]
    if not enabled:
        yield failed(
            meta, ctx,
            "No alerts are enabled for this network",
            remediation="Network-wide > Alerts: enable at minimum device-down, configuration-change, and security alerts.",
        )
        return

    security_alert_types = {
        "applianceIdsIpsEvent", "ipsEvent", "amp", "clientVpnConnectivity",
        "gatewayDown", "settingsChanged", "rogueAp", "airMarshalRogueSsid",
    }
    enabled_types = {a.get("type") for a in enabled}
    missing = security_alert_types - enabled_types
    if missing:
        yield warned(
            meta, ctx,
            f"{len(enabled)} alerts enabled; security-relevant missing: {sorted(missing)}",
            evidence={"enabled_types": sorted(enabled_types)},
        )
    else:
        yield passed(meta, ctx, f"{len(enabled)} alerts enabled, including security events")


@check(
    id="NET-004",
    title="Firmware upgrade window configured",
    severity=Severity.MEDIUM,
    scope=Scope.NETWORK,
    nist_csf=["ID.RA-1", "PR.IP-12"],
    cis_csc=["7.3", "7.4"],
    cisco=["Meraki Firmware Upgrade Best Practices"],
    essential_eight=["E8.2", "E8.6"],
    asd_ism=["System Management: Patch and update management"],
)
def firmware_upgrade_window(ctx: CheckContext):
    meta = firmware_upgrade_window.meta
    net = ctx.network or {}
    fw = ctx.client.network_firmware_upgrades(net["id"])
    if fw is None:
        yield errored(meta, ctx, "firmware API unavailable")
        return
    window = fw.get("upgradeWindow") or {}
    products = fw.get("products") or {}
    behind: list[str] = []
    for product, info in products.items():
        current = (info.get("currentVersion") or {}).get("shortName") or ""
        available = info.get("availableVersions") or []
        stable = [v for v in available if (v.get("releaseType") or "").lower() == "stable"]
        if stable and current and not any(current == v.get("shortName") for v in stable):
            behind.append(f"{product}:{current}")
    if behind:
        yield warned(
            meta, ctx,
            "Firmware not on latest stable for: " + ", ".join(behind),
            remediation="Schedule upgrades during the configured maintenance window.",
            evidence={"behind": behind, "window": window},
        )
    else:
        yield passed(meta, ctx, "firmware current / stable")


@check(
    id="NET-005",
    title="Group policies do not re-enable broad access",
    severity=Severity.MEDIUM,
    scope=Scope.NETWORK,
    cis=["2.3"],
    nist_csf=["PR.AC-4", "PR.AC-5"],
    cis_csc=["6.8", "13.10"],
    cisco=["Meraki Group Policy Best Practices"],
    essential_eight=["E8.5"],
    asd_ism=["Network Design: Network access policy"],
    description=(
        "Group policies can override network-level firewall, content filtering, and "
        "traffic-shaping rules. A 'VIP' policy with allow-any will silently undo MX-004."
    ),
)
def group_policy_review(ctx: CheckContext):
    meta = group_policy_review.meta
    net = ctx.network or {}
    policies = ctx.client.group_policies(net["id"]) or []
    if not policies:
        yield passed(meta, ctx, "no group policies defined")
        return

    offenders: list[str] = []
    for gp in policies:
        name = gp.get("name") or gp.get("groupPolicyId") or "?"
        fw = gp.get("firewallAndTrafficShaping") or {}
        rules = fw.get("l3FirewallRules") or []
        if any(
            (r.get("policy") == "allow"
             and (str(r.get("destCidr") or "any")).lower() == "any"
             and (str(r.get("destPort") or "any")).lower() == "any"
             and (str(r.get("protocol") or "any")).lower() == "any")
            for r in rules
        ):
            offenders.append(f"{name}: L3 allow-any override")

        cf = gp.get("contentFiltering") or {}
        blocked = cf.get("blockedUrlCategories") or {}
        if blocked.get("settings") == "override" and not (blocked.get("categories") or []):
            offenders.append(f"{name}: overrides content filter with no categories blocked")

    if offenders:
        yield warned(
            meta, ctx,
            f"{len(offenders)} permissive group polic(ies) out of {len(policies)}",
            remediation="Tighten or remove allow-any overrides; never publish empty 'override' content filters.",
            evidence={"offenders": offenders},
        )
    else:
        yield passed(meta, ctx, f"{len(policies)} group polic(ies) reviewed, none permissive")


@check(
    id="NET-006",
    title="Network time zone configured for accurate event timestamps",
    severity=Severity.MEDIUM,
    scope=Scope.NETWORK,
    nist_csf=["PR.PT-1", "DE.AE-3"],
    cis_csc=["8.4"],
    cisco=["Meraki Network Time Settings"],
    asd_ism=["System Monitoring: Event log timestamping", "System Hardening: Time synchronisation"],
    description=(
        "Meraki devices synchronise time against Cisco's NTP infrastructure automatically, "
        "so the control the customer owns is the network's time zone. Wrong or unset time "
        "zones corrupt syslog timestamps and defeat incident-response correlation."
    ),
)
def timezone_configured(ctx: CheckContext):
    meta = timezone_configured.meta
    net = ctx.network or {}
    tz = net.get("timeZone") or ""
    required_prefix = ctx.thresholds.get("required_timezone_prefix")

    if not tz:
        yield failed(
            meta, ctx,
            "No time zone set on this network",
            remediation="Network-wide > General > Time zone: set to the local zone of the site.",
        )
        return

    if required_prefix and not tz.startswith(str(required_prefix)):
        yield warned(
            meta, ctx,
            f"Time zone '{tz}' does not match required prefix '{required_prefix}'",
            remediation="Align the network time zone to the requirement for accurate audit trails.",
            evidence={"timeZone": tz, "required_prefix": required_prefix},
        )
        return

    yield passed(meta, ctx, f"time zone: {tz}")
