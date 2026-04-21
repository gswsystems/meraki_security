from __future__ import annotations

import logging
from typing import Iterable

from meraki_sec.checks.base import REGISTRY, Check, CheckContext
from meraki_sec.client import APIError, MerakiClient
from meraki_sec.models import Finding, Scope, Severity, Status, Target

log = logging.getLogger(__name__)


def _network_products(network: dict) -> set[str]:
    # `productTypes` is the authoritative field on a network object.
    return set(network.get("productTypes") or [])


def _check_applies(chk: Check, *, scope: Scope, network: dict | None = None) -> bool:
    if chk.meta.scope != scope:
        return False
    if chk.meta.product_type is None:
        return True
    if scope == Scope.ORG:
        return True  # org-wide checks don't filter on product
    if network is None:
        return False
    return chk.meta.product_type in _network_products(network)


def _filter(
    checks: list[Check],
    *,
    only: list[str],
    skip: list[str],
) -> list[Check]:
    out = checks
    if only:
        allow = set(only)
        out = [c for c in out if c.meta.id in allow]
    if skip:
        deny = set(skip)
        out = [c for c in out if c.meta.id not in deny]
    return out


class Engine:
    def __init__(
        self,
        client: MerakiClient,
        thresholds: dict,
        *,
        only_checks: list[str] | None = None,
        skip_checks: list[str] | None = None,
    ):
        self.client = client
        self.thresholds = thresholds
        self.only = only_checks or []
        self.skip = skip_checks or []

    def run(
        self,
        *,
        org_ids: list[str] | None = None,
        network_ids: list[str] | None = None,
    ) -> list[Finding]:
        orgs = self.client.organizations()
        if org_ids:
            wanted = set(org_ids)
            orgs = [o for o in orgs if o.get("id") in wanted]
        if not orgs:
            log.warning("No organizations resolved — nothing to scan.")
            return []

        all_checks = _filter(list(REGISTRY), only=self.only, skip=self.skip)
        org_checks = [c for c in all_checks if c.meta.scope == Scope.ORG]
        net_checks = [c for c in all_checks if c.meta.scope == Scope.NETWORK]
        dev_checks = [c for c in all_checks if c.meta.scope == Scope.DEVICE]

        findings: list[Finding] = []

        for org in orgs:
            log.info("Scanning org %s (%s)", org.get("name"), org.get("id"))
            for chk in org_checks:
                findings.extend(self._run_one(chk, CheckContext(
                    client=self.client,
                    thresholds=self.thresholds,
                    org=org,
                )))

            try:
                networks = self.client.networks(org["id"])
            except APIError as e:
                log.warning("org %s: cannot list networks: %s", org.get("name"), e)
                continue

            if network_ids:
                wanted_n = set(network_ids)
                networks = [n for n in networks if n.get("id") in wanted_n]

            for net in networks:
                log.info("  network %s (%s)", net.get("name"), net.get("id"))
                for chk in net_checks:
                    if not _check_applies(chk, scope=Scope.NETWORK, network=net):
                        continue
                    findings.extend(self._run_one(chk, CheckContext(
                        client=self.client,
                        thresholds=self.thresholds,
                        org=org,
                        network=net,
                    )))

                if not dev_checks:
                    continue
                try:
                    devices = self.client.network_devices(net["id"])
                except APIError as e:
                    log.warning("network %s: cannot list devices: %s", net.get("name"), e)
                    continue
                for dev in devices:
                    dev_product = (dev.get("productType") or "").lower()
                    for chk in dev_checks:
                        if chk.meta.product_type and chk.meta.product_type != dev_product:
                            continue
                        findings.extend(self._run_one(chk, CheckContext(
                            client=self.client,
                            thresholds=self.thresholds,
                            org=org,
                            network=net,
                            device=dev,
                        )))

        return findings

    def _run_one(self, chk: Check, ctx: CheckContext) -> Iterable[Finding]:
        try:
            result = chk.fn(ctx) or []
            return list(result)
        except APIError as e:
            log.warning("%s: %s", chk.meta.id, e)
            return [Finding(
                check_id=chk.meta.id,
                title=chk.meta.title,
                severity=Severity.INFO,
                status=Status.ERROR,
                target=ctx.target(),
                message=f"API error: {e}",
                sources=list(chk.meta.sources),
                mappings={k: list(v) for k, v in chk.meta.mappings.items()},
            )]
        except Exception as e:  # pragma: no cover - defensive
            log.exception("%s crashed", chk.meta.id)
            return [Finding(
                check_id=chk.meta.id,
                title=chk.meta.title,
                severity=Severity.INFO,
                status=Status.ERROR,
                target=ctx.target(),
                message=f"Check crashed: {e}",
                sources=list(chk.meta.sources),
                mappings={k: list(v) for k, v in chk.meta.mappings.items()},
            )]
