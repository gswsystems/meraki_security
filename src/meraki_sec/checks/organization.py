from __future__ import annotations

from datetime import datetime, timezone

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
    id="ORG-001",
    title="Two-factor authentication required for all admins",
    severity=Severity.CRITICAL,
    scope=Scope.ORG,
    cis=["1.1"],
    nist_csf=["PR.AC-1", "PR.AC-7"],
    cis_csc=["6.3", "6.5"],
    cisco=["Meraki Security Best Practices - MFA"],
    essential_eight=["E8.7"],
    asd_ism=["Authentication: MFA for privileged users"],
    description="All dashboard admins must have 2FA. Enforce at the org level.",
)
def two_factor_enforced(ctx: CheckContext):
    meta = two_factor_enforced.meta
    org = ctx.org or {}
    sec = ctx.client.login_security(org["id"])
    if sec is None:
        yield errored(meta, ctx, "login security API unavailable")
        return

    enforced = bool(sec.get("enforceTwoFactorAuth"))
    admins = ctx.client.admins(org["id"])
    non_2fa = [a for a in admins if not a.get("twoFactorAuthEnabled")]

    if enforced and not non_2fa:
        yield passed(meta, ctx, "2FA enforced org-wide")
        return
    if not enforced:
        yield failed(
            meta, ctx,
            f"Org does not enforce 2FA; {len(non_2fa)} admin(s) without 2FA",
            remediation="Organization > Settings > Authentication: enable 'Require two-factor authentication'.",
            evidence={"admins_without_2fa": [a.get("email") for a in non_2fa]},
        )
    else:
        yield warned(
            meta, ctx,
            f"2FA enforced but {len(non_2fa)} admin(s) still flagged without 2FA",
            evidence={"admins_without_2fa": [a.get("email") for a in non_2fa]},
        )


@check(
    id="ORG-002",
    title="Password complexity and rotation policy",
    severity=Severity.HIGH,
    scope=Scope.ORG,
    cis=["1.2"],
    nist_csf=["PR.AC-1"],
    cis_csc=["5.2"],
    cisco=["Meraki Authentication Settings"],
    asd_ism=["Authentication: Passphrase policy"],
)
def password_policy(ctx: CheckContext):
    meta = password_policy.meta
    org = ctx.org or {}
    sec = ctx.client.login_security(org["id"])
    if not sec:
        yield errored(meta, ctx, "login security API unavailable")
        return

    problems: list[str] = []
    if not sec.get("enforcePasswordExpiration"):
        problems.append("password expiration disabled")
    elif int(sec.get("passwordExpirationDays") or 0) > 180:
        problems.append(f"password expiration > 180 days ({sec.get('passwordExpirationDays')})")
    if not sec.get("enforceDifferentPasswords"):
        problems.append("password history not enforced")
    if not sec.get("enforceStrongPasswords"):
        problems.append("strong password rule disabled")

    if problems:
        yield failed(
            meta, ctx,
            "Weak password policy: " + "; ".join(problems),
            remediation="Organization > Settings > Authentication: enforce strong passwords, expiration, and history.",
            evidence={k: sec.get(k) for k in (
                "enforcePasswordExpiration", "passwordExpirationDays",
                "enforceDifferentPasswords", "enforceStrongPasswords",
            )},
        )
    else:
        yield passed(meta, ctx, "password policy meets baseline")


@check(
    id="ORG-003",
    title="Account lockout after repeated failed logins",
    severity=Severity.MEDIUM,
    scope=Scope.ORG,
    cis=["1.3"],
    nist_csf=["PR.AC-7"],
    cis_csc=["6.3"],
    asd_ism=["Authentication: Account lockout"],
)
def account_lockout(ctx: CheckContext):
    meta = account_lockout.meta
    org = ctx.org or {}
    sec = ctx.client.login_security(org["id"])
    if not sec:
        yield errored(meta, ctx, "login security API unavailable")
        return
    if not sec.get("enforceAccountLockout"):
        yield failed(
            meta, ctx,
            "Account lockout disabled",
            remediation="Enable 'Lock accounts after ... failed login attempts' and set a reasonable threshold (e.g. 5).",
        )
        return
    attempts = int(sec.get("accountLockoutAttempts") or 0)
    if attempts == 0 or attempts > 10:
        yield warned(meta, ctx, f"Account lockout threshold is {attempts}; recommend <= 10")
    else:
        yield passed(meta, ctx, f"lockout enforced after {attempts} attempts")


@check(
    id="ORG-004",
    title="Idle session timeout configured",
    severity=Severity.MEDIUM,
    scope=Scope.ORG,
    cis=["1.4"],
    nist_csf=["PR.AC-3", "PR.AC-7"],
    cis_csc=["4.3"],
    asd_ism=["Authentication: Session termination"],
)
def idle_timeout(ctx: CheckContext):
    meta = idle_timeout.meta
    org = ctx.org or {}
    sec = ctx.client.login_security(org["id"])
    if not sec:
        yield errored(meta, ctx, "login security API unavailable")
        return
    if not sec.get("enforceIdleTimeout"):
        yield failed(
            meta, ctx,
            "Idle timeout disabled",
            remediation="Enable idle timeout <= 30 minutes.",
        )
        return
    minutes = int(sec.get("idleTimeoutMinutes") or 0)
    if minutes == 0 or minutes > 30:
        yield warned(meta, ctx, f"Idle timeout is {minutes} min; recommend <= 30")
    else:
        yield passed(meta, ctx, f"idle timeout {minutes} min")


@check(
    id="ORG-005",
    title="Login IP allow-list configured",
    severity=Severity.MEDIUM,
    scope=Scope.ORG,
    nist_csf=["PR.AC-3", "PR.AC-5"],
    cis_csc=["4.2", "12.5"],
    cisco=["Meraki Security Best Practices - Login IP ranges"],
    essential_eight=["E8.5"],
    asd_ism=["Gateways: Restrict administrative access"],
    description="Restricting dashboard login to known IPs reduces exposure of credential-only login.",
)
def ip_allowlist(ctx: CheckContext):
    meta = ip_allowlist.meta
    org = ctx.org or {}
    sec = ctx.client.login_security(org["id"])
    if not sec:
        yield errored(meta, ctx, "login security API unavailable")
        return
    ranges = sec.get("loginIpRanges") or []
    if sec.get("enforceLoginIpRanges") and ranges:
        yield passed(meta, ctx, f"{len(ranges)} IP range(s) allowed")
    else:
        yield warned(
            meta, ctx,
            "Login IP allow-list not enforced",
            remediation="Consider restricting dashboard access to trusted corporate IPs when feasible.",
        )


@check(
    id="ORG-006",
    title="SAML SSO enabled",
    severity=Severity.MEDIUM,
    scope=Scope.ORG,
    nist_csf=["PR.AC-1"],
    cis_csc=["5.6", "6.7"],
    cisco=["Meraki SAML configuration"],
    essential_eight=["E8.7"],
    asd_ism=["Authentication: Single sign-on"],
)
def saml_enabled(ctx: CheckContext):
    meta = saml_enabled.meta
    org = ctx.org or {}
    saml = ctx.client.saml(org["id"])
    if saml and saml.get("enabled"):
        yield passed(meta, ctx, "SAML SSO enabled")
    else:
        yield warned(
            meta, ctx,
            "SAML SSO disabled",
            remediation="Enable SAML to centralize identity, MFA, and offboarding in your IdP.",
        )


@check(
    id="ORG-007",
    title="No shared or generic admin accounts",
    severity=Severity.HIGH,
    scope=Scope.ORG,
    cis=["1.5"],
    nist_csf=["PR.AC-1", "PR.AC-6"],
    cis_csc=["5.4"],
    essential_eight=["E8.5"],
    asd_ism=["Personnel Security: Unique user identification"],
)
def no_shared_admins(ctx: CheckContext):
    meta = no_shared_admins.meta
    org = ctx.org or {}
    admins = ctx.client.admins(org["id"])
    suspects: list[str] = []
    tokens = ("admin@", "root@", "noc@", "shared", "team", "generic", "netops@", "it@")
    for a in admins:
        email = (a.get("email") or "").lower()
        name = (a.get("name") or "").lower()
        if any(tok in email or tok in name for tok in tokens):
            suspects.append(a.get("email") or a.get("name") or "?")
    if suspects:
        yield failed(
            meta, ctx,
            f"{len(suspects)} admin account(s) look shared/generic",
            remediation="Replace shared accounts with per-user SSO accounts tied to named identities.",
            evidence={"suspects": suspects},
        )
    else:
        yield passed(meta, ctx, "no obviously shared admin accounts")


@check(
    id="ORG-008",
    title="Excess of full-organization admins",
    severity=Severity.MEDIUM,
    scope=Scope.ORG,
    cis=["1.6"],
    nist_csf=["PR.AC-4"],
    cis_csc=["6.8"],
    essential_eight=["E8.5"],
    asd_ism=["Personnel Security: Privileged access management"],
    description="Least privilege: limit the number of full-admin accounts.",
)
def limit_full_admins(ctx: CheckContext):
    meta = limit_full_admins.meta
    org = ctx.org or {}
    admins = ctx.client.admins(org["id"])
    full = [a for a in admins if a.get("orgAccess") == "full"]
    if len(full) > 5:
        yield warned(
            meta, ctx,
            f"{len(full)} admins have full org access",
            remediation="Down-scope admins to read-only, network-admin, or custom roles where possible.",
            evidence={"full_admins": [a.get("email") for a in full]},
        )
    else:
        yield passed(meta, ctx, f"{len(full)} full admin(s)")


@check(
    id="ORG-009",
    title="API keys are current and tied to MFA-protected admins",
    severity=Severity.HIGH,
    scope=Scope.ORG,
    cis=["1.7"],
    nist_csf=["PR.AC-1", "PR.AC-7", "ID.AM-6"],
    cis_csc=["5.3", "6.3"],
    cisco=["Meraki API key best practices"],
    essential_eight=["E8.5", "E8.7"],
    asd_ism=["Authentication: Machine credentials", "Personnel Security: Privileged access management"],
    description=(
        "An API key inherits its admin's org access. Stale keys (unused for months) "
        "or keys on admins without 2FA are the most common Meraki-key abuse vectors."
    ),
)
def api_key_hygiene(ctx: CheckContext):
    meta = api_key_hygiene.meta
    org = ctx.org or {}
    admins = ctx.client.admins(org["id"])
    threshold_days = int(ctx.thresholds.get("api_key_stale_days", 90))
    now = datetime.now(timezone.utc)

    key_holders = [a for a in admins if a.get("hasApiKey")]
    if not key_holders:
        yield passed(meta, ctx, "no admins have API keys")
        return

    issues: list[str] = []
    for a in key_holders:
        email = a.get("email") or a.get("name") or "?"
        if not a.get("twoFactorAuthEnabled"):
            issues.append(f"{email}: API key without 2FA")
        last_active = a.get("lastActive")
        if last_active:
            try:
                dt = datetime.fromisoformat(str(last_active).replace("Z", "+00:00"))
                days = (now - dt).days
                if days > threshold_days:
                    issues.append(f"{email}: inactive {days}d (threshold {threshold_days}d)")
            except (ValueError, TypeError):
                pass
        else:
            issues.append(f"{email}: no lastActive timestamp (never used?)")

    if issues:
        yield failed(
            meta, ctx,
            f"{len(issues)} API-key issue(s) across {len(key_holders)} key holder(s)",
            remediation=(
                "Rotate or delete unused API keys; require 2FA on every admin that holds a key. "
                "Organization > Administrators > API access."
            ),
            evidence={"issues": issues, "key_holders": [a.get("email") for a in key_holders]},
        )
    else:
        yield passed(
            meta, ctx,
            f"{len(key_holders)} API key(s), all fresh and MFA-protected",
        )


@check(
    id="ORG-010",
    title="Dashboard data residency matches required region",
    severity=Severity.HIGH,
    scope=Scope.ORG,
    nist_csf=["ID.GV-3"],
    cis_csc=["3.1"],
    cisco=["Meraki Dashboard Regions"],
    asd_ism=["Data transfers: Cloud service data residency", "PSPF: INFOSEC-8"],
    description=(
        "ASD ISM and many Australian state/federal agencies require management-plane "
        "data to remain in Australian sovereign infrastructure. Meraki hosts orgs in "
        "regional clouds; the wrong region is a compliance finding even if the network "
        "is configured perfectly otherwise."
    ),
)
def dashboard_data_residency(ctx: CheckContext):
    meta = dashboard_data_residency.meta
    org = ctx.org or {}
    required = ctx.thresholds.get("required_dashboard_region")
    # The org listing contains cloud.region.name; re-fetch the full org for reliability.
    full = ctx.client.organization(org["id"]) or org
    region = (((full.get("cloud") or {}).get("region") or {}).get("name")) or "unknown"

    if not required:
        # No requirement configured — just report the observed region informationally.
        yield passed(meta, ctx, f"dashboard region: {region} (no required region configured)")
        return

    if region.lower() == str(required).lower():
        yield passed(meta, ctx, f"dashboard region '{region}' matches requirement")
    else:
        yield failed(
            meta, ctx,
            f"dashboard region is '{region}', required '{required}'",
            remediation=(
                "Cisco Meraki cannot migrate an org between regions — contact your account team to "
                "provision a new org in the required region and migrate networks/config over."
            ),
            evidence={"observed_region": region, "required_region": required},
        )
