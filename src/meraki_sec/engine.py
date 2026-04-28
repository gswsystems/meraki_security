from __future__ import annotations

import logging
from collections import defaultdict
from typing import Iterable

from meraki_sec.checks.base import REGISTRY, Check, CheckContext
from meraki_sec.client import APIError, MerakiClient
from meraki_sec.models import Finding, Scope, Severity, Status, Target

log = logging.getLogger(__name__)


# Model-prefix → productType. Some Meraki endpoints omit `productType` on the
# device payload, so we fall back to the model code.
_MODEL_PREFIX_PRODUCT: dict[str, str] = {
    "MX": "appliance", "MZ": "appliance", "Z": "appliance",
    "MS": "switch", "CS": "switch",
    "MR": "wireless", "CW": "wireless",
    "MV": "camera",
    "MT": "sensor",
    "MG": "cellularGateway",
}


def device_product_type(device: dict) -> str:
    """Best-effort productType for a device, falling back to model prefix."""
    pt = (device.get("productType") or "").strip().lower()
    if pt:
        return pt
    model = (device.get("model") or "").upper()
    for prefix, ptype in _MODEL_PREFIX_PRODUCT.items():
        if model.startswith(prefix):
            return ptype
    return ""


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
        device_sample_per_type: int | None = None,
        device_sample: dict[str, int] | None = None,
    ):
        self.client = client
        self.thresholds = thresholds
        self.only = only_checks or []
        self.skip = skip_checks or []
        self.device_sample_per_type = device_sample_per_type
        self.device_sample = {k.lower(): v for k, v in (device_sample or {}).items()}

    def _sampled_serials(self, org_id: str) -> set[str] | None:
        """Build the set of device serials that should be scanned for this org.

        Returns None if no sampling is configured (scan everything).
        """
        if not self.device_sample_per_type and not self.device_sample:
            return None
        try:
            all_devs = self.client.org_devices(org_id)
        except APIError as e:
            log.warning("org %s: cannot list devices for sampling: %s", org_id, e)
            return None
        by_type: dict[str, list[dict]] = defaultdict(list)
        for d in all_devs:
            by_type[device_product_type(d)].append(d)
        allowed: set[str] = set()
        for ptype, devs in by_type.items():
            limit = self.device_sample.get(ptype, self.device_sample_per_type)
            if limit is None or limit <= 0:
                kept = devs
            else:
                kept = devs[:limit]
            if limit is not None and limit > 0 and len(devs) > limit:
                log.info(
                    "org %s: sampling %d/%d %s devices",
                    org_id, limit, len(devs), ptype or "unknown",
                )
            for d in kept:
                serial = d.get("serial")
                if serial:
                    allowed.add(serial)
        return allowed

    def run(
        self,
        *,
        org_ids: list[str] | None = None,
        network_ids: list[str] | None = None,
    ) -> list[Finding]:
        all_orgs = self.client.organizations()
        if org_ids:
            wanted = {str(x) for x in org_ids}
            orgs = [
                o for o in all_orgs
                if str(o.get("id")) in wanted or o.get("name") in wanted
            ]
            missing = wanted - {str(o.get("id")) for o in orgs} - {o.get("name") for o in orgs if o.get("name")}
            if missing:
                available = ", ".join(
                    f"{o.get('id')} ({o.get('name')})" for o in all_orgs
                ) or "<none visible to this API key>"
                log.warning(
                    "Requested org(s) not found: %s. Available: %s",
                    ", ".join(sorted(missing)), available,
                )
        else:
            orgs = all_orgs
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

            allowed_serials = self._sampled_serials(org["id"]) if dev_checks else None

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
                    if allowed_serials is not None and dev.get("serial") not in allowed_serials:
                        continue
                    dev_product = device_product_type(dev)
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
