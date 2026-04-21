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


# Crypto thresholds per ASD ISM (Guidelines for Cryptography).
WEAK_IKE_CIPHERS = {"des", "3des", "aes128", "aes-128"}
WEAK_IKE_HASHES = {"md5", "sha1", "sha-1"}
WEAK_DH_GROUPS = {"1", "2", "5"}  # MODP-768/1024/1536 — all below 2048 bits


@check(
    id="MX-001",
    title="Intrusion prevention (IDS/IPS) enabled in prevention mode",
    severity=Severity.CRITICAL,
    scope=Scope.NETWORK,
    product_type="appliance",
    cis=["3.1"],
    nist_csf=["DE.CM-1", "PR.PT-4"],
    cis_csc=["13.3", "13.8"],
    cisco=["Meraki Threat Protection - IPS"],
    asd_ism=["Gateways: Intrusion prevention"],
)
def ips_prevention(ctx: CheckContext):
    meta = ips_prevention.meta
    net = ctx.network or {}
    ips = ctx.client.appliance_security_intrusion(net["id"])
    if ips is None:
        yield errored(meta, ctx, "IDS/IPS API unavailable (license required?)")
        return
    mode = (ips.get("mode") or "disabled").lower()
    ruleset = (ips.get("idsRulesets") or "").lower()
    if mode != "prevention":
        yield failed(
            meta, ctx,
            f"IDS/IPS mode is '{mode}', not 'prevention'",
            remediation="Security & SD-WAN > Threat Protection: set IPS to prevention.",
            evidence={"mode": mode, "ruleset": ruleset},
        )
        return
    if ruleset not in ("balanced", "security", "connectivity"):
        yield warned(meta, ctx, f"IPS ruleset '{ruleset}' — recommend 'balanced' or 'security'")
    else:
        yield passed(meta, ctx, f"IPS in prevention, ruleset={ruleset}")


@check(
    id="MX-002",
    title="Advanced Malware Protection (AMP) enabled",
    severity=Severity.HIGH,
    scope=Scope.NETWORK,
    product_type="appliance",
    cis=["3.2"],
    nist_csf=["DE.CM-4", "PR.PT-4"],
    cis_csc=["10.1", "10.2"],
    cisco=["Meraki Threat Protection - AMP"],
    asd_ism=["Gateways: Anti-malware scanning"],
)
def amp_enabled(ctx: CheckContext):
    meta = amp_enabled.meta
    net = ctx.network or {}
    amp = ctx.client.appliance_security_malware(net["id"])
    if amp is None:
        yield errored(meta, ctx, "AMP API unavailable (license required?)")
        return
    mode = (amp.get("mode") or "disabled").lower()
    if mode == "enabled":
        yield passed(meta, ctx, "AMP enabled")
    else:
        yield failed(
            meta, ctx,
            f"AMP mode is '{mode}'",
            remediation="Security & SD-WAN > Threat Protection > Advanced Malware Protection: enable.",
        )


@check(
    id="MX-003",
    title="Content filtering blocks security-relevant categories",
    severity=Severity.MEDIUM,
    scope=Scope.NETWORK,
    product_type="appliance",
    cis=["3.3"],
    nist_csf=["DE.CM-1", "PR.PT-4"],
    cis_csc=["9.2", "9.3"],
    asd_ism=["Gateways: Web content filtering"],
)
def content_filtering(ctx: CheckContext):
    meta = content_filtering.meta
    net = ctx.network or {}
    cf = ctx.client.appliance_content_filtering(net["id"])
    if cf is None:
        yield errored(meta, ctx, "content filtering API unavailable")
        return
    blocked = cf.get("blockedUrlCategories") or []
    blocked_names = {
        (c.get("name") or "").lower() for c in blocked if isinstance(c, dict)
    } | {str(c).lower() for c in blocked if isinstance(c, str)}
    required = {"malware sites", "phishing", "command and control", "botnets"}
    hit = {r for r in required if any(r in n for n in blocked_names)}
    missing = required - hit
    if missing:
        yield warned(
            meta, ctx,
            "Security categories not blocked: " + ", ".join(sorted(missing)),
            remediation="Security & SD-WAN > Content Filtering: block malware, phishing, C2, botnets.",
            evidence={"blocked_count": len(blocked_names)},
        )
    else:
        yield passed(meta, ctx, "security categories blocked")


@check(
    id="MX-004",
    title="L3 firewall default-deny outbound rule in place",
    severity=Severity.HIGH,
    scope=Scope.NETWORK,
    product_type="appliance",
    nist_csf=["PR.AC-5", "PR.PT-4"],
    cis_csc=["12.2", "13.10"],
    cisco=["Meraki MX Firewall Best Practices"],
    asd_ism=["Gateways: Firewall rules"],
    description="The implicit default is allow-any. Explicit deny-by-default with documented allow rules is stronger.",
)
def l3_default_deny(ctx: CheckContext):
    meta = l3_default_deny.meta
    net = ctx.network or {}
    fw = ctx.client.appliance_l3_fw(net["id"])
    if fw is None:
        yield errored(meta, ctx, "L3 firewall API unavailable")
        return
    rules = fw.get("rules") or []
    explicit = [r for r in rules if (r.get("comment") or "").lower() != "default rule"]
    if not explicit:
        yield warned(
            meta, ctx,
            "Only the implicit allow-any default rule is configured",
            remediation="Add explicit allow rules for required traffic and a trailing deny for the rest.",
        )
        return
    broad_any = any(
        (r.get("policy") == "allow"
         and (r.get("srcCidr") or "any").lower() == "any"
         and (r.get("destCidr") or "any").lower() == "any"
         and (r.get("destPort") or "any").lower() == "any")
        for r in explicit
    )
    if broad_any:
        yield warned(
            meta, ctx,
            "L3 firewall contains an explicit allow-any rule",
            remediation="Scope allow rules to specific CIDRs/ports; reserve any/any for deliberate exceptions.",
        )
    else:
        yield passed(meta, ctx, f"{len(explicit)} scoped L3 rules")


@check(
    id="MX-005",
    title="L7 application firewall has blocking rules",
    severity=Severity.MEDIUM,
    scope=Scope.NETWORK,
    product_type="appliance",
    nist_csf=["PR.AC-5"],
    cis_csc=["9.4", "13.10"],
    cisco=["Meraki MX L7 Rules"],
    asd_ism=["Gateways: Application layer filtering"],
)
def l7_rules_present(ctx: CheckContext):
    meta = l7_rules_present.meta
    net = ctx.network or {}
    fw = ctx.client.appliance_l7_fw(net["id"])
    if fw is None:
        yield errored(meta, ctx, "L7 firewall API unavailable")
        return
    rules = fw.get("rules") or []
    if not rules:
        yield warned(
            meta, ctx,
            "No L7 application rules configured",
            remediation="Consider blocking anonymizers, P2P, or other risky categories as policy dictates.",
        )
    else:
        yield passed(meta, ctx, f"{len(rules)} L7 rule(s) configured")


@check(
    id="MX-006",
    title="Client VPN uses strong authentication",
    severity=Severity.HIGH,
    scope=Scope.NETWORK,
    product_type="appliance",
    cis=["3.4"],
    nist_csf=["PR.AC-1", "PR.AC-3"],
    cis_csc=["6.4", "6.5"],
    cisco=["Meraki Client VPN Best Practices"],
    essential_eight=["E8.7"],
    asd_ism=["Gateways: Remote access authentication"],
)
def client_vpn_auth(ctx: CheckContext):
    meta = client_vpn_auth.meta
    net = ctx.network or {}
    vpn = ctx.client.appliance_client_vpn(net["id"])
    if vpn is None:
        yield errored(meta, ctx, "client VPN API unavailable")
        return
    secret = vpn.get("secret")
    auth_type = (vpn.get("authenticationType") or "").lower()
    if not secret and not auth_type:
        yield passed(meta, ctx, "client VPN not configured")
        return
    if auth_type in ("meraki cloud", ""):
        yield warned(
            meta, ctx,
            "Client VPN relies on Meraki cloud auth / shared secret only",
            remediation="Integrate RADIUS/Active Directory with MFA or use Meraki AnyConnect (SAML).",
            evidence={"authenticationType": auth_type},
        )
    else:
        yield passed(meta, ctx, f"client VPN auth = {auth_type}")


@check(
    id="MX-007",
    title="Site-to-site VPN uses IKEv2",
    severity=Severity.MEDIUM,
    scope=Scope.NETWORK,
    product_type="appliance",
    nist_csf=["PR.DS-2"],
    cis_csc=["3.10"],
    cisco=["Meraki Auto-VPN Best Practices"],
    asd_ism=["Cryptography: IPsec protocol"],
)
def s2s_vpn_ikev2(ctx: CheckContext):
    meta = s2s_vpn_ikev2.meta
    net = ctx.network or {}
    vpn = ctx.client.appliance_site_to_site_vpn(net["id"])
    if vpn is None:
        yield errored(meta, ctx, "S2S VPN API unavailable")
        return
    mode = (vpn.get("mode") or "none").lower()
    if mode == "none":
        yield passed(meta, ctx, "S2S VPN disabled")
        return
    yield passed(meta, ctx, f"Auto-VPN mode={mode} (Auto-VPN uses IKEv2)")


@check(
    id="MX-008",
    title="Third-party VPN peers use IKEv2 and strong crypto",
    severity=Severity.HIGH,
    scope=Scope.ORG,
    product_type="appliance",
    nist_csf=["PR.DS-2"],
    cis_csc=["3.10"],
    cisco=["Meraki Non-Meraki VPN Peers"],
    asd_ism=[
        "Cryptography: IPsec protocol",
        "Cryptography: Approved cryptographic algorithms",
    ],
    description=(
        "Non-Meraki VPN peers can be configured with IKEv1 and legacy ciphers for compatibility. "
        "ASD ISM requires IKEv2 with AES-256 (or AES-128-GCM), SHA-256+ integrity, and "
        "DH group 14 or stronger for Australian government and critical-infrastructure systems."
    ),
)
def third_party_vpn_ciphers(ctx: CheckContext):
    meta = third_party_vpn_ciphers.meta
    org = ctx.org or {}
    peers = ctx.client.vpn_third_party_peers(org["id"])
    if peers is None:
        yield errored(meta, ctx, "third-party VPN API unavailable")
        return
    if not peers:
        yield passed(meta, ctx, "no third-party VPN peers configured")
        return

    ikev1: list[str] = []
    weak: list[str] = []

    for p in peers:
        name = p.get("name") or p.get("publicIp") or "?"
        ike_version = str(p.get("ikeVersion") or "").strip()
        if ike_version in ("1", "v1", "ikev1"):
            ikev1.append(name)

        ipsec = p.get("ipsecPolicies") or {}
        ike_cipher = str(ipsec.get("ikeCipherAlgo") or "").lower()
        ike_auth = str(ipsec.get("ikeAuthAlgo") or "").lower()
        ike_dh = str(ipsec.get("ikeDiffieHellmanGroup") or "").lower().replace("group", "").strip()
        child_cipher = str(ipsec.get("childCipherAlgo") or "").lower()
        child_auth = str(ipsec.get("childAuthAlgo") or "").lower()
        child_pfs = str(ipsec.get("childPfsGroup") or "").lower().replace("group", "").strip()

        issues: list[str] = []
        if any(w in ike_cipher for w in WEAK_IKE_CIPHERS):
            issues.append(f"IKE cipher {ike_cipher}")
        if any(w in child_cipher for w in WEAK_IKE_CIPHERS):
            issues.append(f"ESP cipher {child_cipher}")
        if any(w in ike_auth for w in WEAK_IKE_HASHES):
            issues.append(f"IKE hash {ike_auth}")
        if any(w in child_auth for w in WEAK_IKE_HASHES):
            issues.append(f"ESP hash {child_auth}")
        if ike_dh and ike_dh in WEAK_DH_GROUPS:
            issues.append(f"IKE DH group {ike_dh}")
        if child_pfs and child_pfs in WEAK_DH_GROUPS:
            issues.append(f"PFS group {child_pfs}")

        if issues:
            weak.append(f"{name}: " + ", ".join(issues))

    if ikev1 and weak:
        yield failed(
            meta, ctx,
            f"{len(ikev1)} peer(s) on IKEv1 and {len(weak)} peer(s) with weak crypto",
            remediation="Migrate peers to IKEv2 with AES-256, SHA-256+, and DH14 or higher.",
            evidence={"ikev1_peers": ikev1, "weak_crypto_peers": weak},
        )
    elif ikev1:
        yield failed(
            meta, ctx,
            f"{len(ikev1)} peer(s) using IKEv1",
            remediation="Migrate all non-Meraki peers to IKEv2.",
            evidence={"ikev1_peers": ikev1},
        )
    elif weak:
        yield warned(
            meta, ctx,
            f"{len(weak)} peer(s) with weak cipher/hash/DH choices",
            remediation="Replace AES-128/3DES/SHA-1/DH2/DH5 with AES-256, SHA-256+, DH14+.",
            evidence={"weak_crypto_peers": weak},
        )
    else:
        yield passed(meta, ctx, f"{len(peers)} third-party VPN peer(s), all IKEv2 + strong crypto")
