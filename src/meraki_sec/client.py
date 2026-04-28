from __future__ import annotations

import logging
import time
from collections import deque
from functools import lru_cache
from threading import Lock
from typing import Any

import meraki

log = logging.getLogger(__name__)


class APIError(Exception):
    """Raised when an API call fails in a way the caller should handle."""


class RateLimiter:
    """Sliding-window rate limiter: at most N acquisitions per second."""

    def __init__(self, max_per_second: float | None):
        self.max_per_second = max_per_second
        self._times: deque[float] = deque()
        self._lock = Lock()

    def acquire(self) -> None:
        if not self.max_per_second or self.max_per_second <= 0:
            return
        with self._lock:
            now = time.monotonic()
            while self._times and now - self._times[0] >= 1.0:
                self._times.popleft()
            if len(self._times) >= self.max_per_second:
                wait = 1.0 - (now - self._times[0])
                if wait > 0:
                    time.sleep(wait)
                    now = time.monotonic()
                    while self._times and now - self._times[0] >= 1.0:
                        self._times.popleft()
            self._times.append(time.monotonic())


class MerakiClient:
    """Thin wrapper around the official Meraki SDK with per-endpoint caching.

    Checks frequently ask for the same data (e.g. the list of devices in a
    network). Caching keeps us under Meraki's rate limits and makes scans
    noticeably faster.
    """

    def __init__(
        self,
        api_key: str,
        base_url: str | None = None,
        timeout: int = 60,
        max_requests_per_second: float | None = None,
    ):
        kwargs: dict[str, Any] = {
            "api_key": api_key,
            "suppress_logging": True,
            "print_console": False,
            "output_log": False,
            "maximum_retries": 3,
            "wait_on_rate_limit": True,
            "single_request_timeout": timeout,
        }
        if base_url:
            kwargs["base_url"] = base_url
        self.dashboard = meraki.DashboardAPI(**kwargs)
        self.rate_limiter = RateLimiter(max_requests_per_second)

    # ----- helpers -----

    def _call(self, fn, *args, **kwargs) -> Any:
        self.rate_limiter.acquire()
        try:
            return fn(*args, **kwargs)
        except meraki.APIError as e:
            # 404 typically means the feature isn't enabled for this network/product.
            if getattr(e, "status", None) in (404, 400):
                log.debug("API %s -> %s: %s", fn.__name__, e.status, e.message)
                return None
            raise APIError(f"{fn.__name__} failed: {e}") from e
        except Exception as e:  # pragma: no cover - defensive
            raise APIError(f"{fn.__name__} crashed: {e}") from e

    # ----- organization -----

    @lru_cache(maxsize=1)
    def organizations(self) -> list[dict]:
        return self._call(self.dashboard.organizations.getOrganizations) or []

    @lru_cache(maxsize=64)
    def organization(self, org_id: str) -> dict | None:
        return self._call(self.dashboard.organizations.getOrganization, org_id)

    @lru_cache(maxsize=64)
    def admins(self, org_id: str) -> list[dict]:
        return self._call(self.dashboard.organizations.getOrganizationAdmins, org_id) or []

    @lru_cache(maxsize=64)
    def login_security(self, org_id: str) -> dict | None:
        return self._call(self.dashboard.organizations.getOrganizationLoginSecurity, org_id)

    @lru_cache(maxsize=64)
    def saml(self, org_id: str) -> dict | None:
        return self._call(self.dashboard.organizations.getOrganizationSaml, org_id)

    @lru_cache(maxsize=64)
    def networks(self, org_id: str) -> list[dict]:
        return self._call(
            self.dashboard.organizations.getOrganizationNetworks,
            org_id,
            total_pages="all",
        ) or []

    @lru_cache(maxsize=64)
    def org_devices(self, org_id: str) -> list[dict]:
        return self._call(
            self.dashboard.organizations.getOrganizationDevices,
            org_id,
            total_pages="all",
        ) or []

    @lru_cache(maxsize=64)
    def org_device_statuses(self, org_id: str) -> list[dict]:
        return self._call(
            self.dashboard.organizations.getOrganizationDevicesStatuses,
            org_id,
            total_pages="all",
        ) or []

    @lru_cache(maxsize=64)
    def org_firmware_upgrades(self, org_id: str) -> list[dict]:
        return self._call(
            self.dashboard.organizations.getOrganizationFirmwareUpgrades,
            org_id,
        ) or []

    @lru_cache(maxsize=64)
    def org_api_requests_overview(self, org_id: str) -> dict | None:
        return self._call(
            self.dashboard.organizations.getOrganizationApiRequestsOverview,
            org_id,
        )

    # ----- network generic -----

    @lru_cache(maxsize=512)
    def network(self, network_id: str) -> dict | None:
        return self._call(self.dashboard.networks.getNetwork, network_id)

    @lru_cache(maxsize=512)
    def network_devices(self, network_id: str) -> list[dict]:
        return self._call(self.dashboard.networks.getNetworkDevices, network_id) or []

    @lru_cache(maxsize=512)
    def network_syslog(self, network_id: str) -> dict | None:
        return self._call(self.dashboard.networks.getNetworkSyslogServers, network_id)

    @lru_cache(maxsize=512)
    def network_snmp(self, network_id: str) -> dict | None:
        return self._call(self.dashboard.networks.getNetworkSnmp, network_id)

    @lru_cache(maxsize=512)
    def network_alerts(self, network_id: str) -> dict | None:
        return self._call(self.dashboard.networks.getNetworkAlertsSettings, network_id)

    @lru_cache(maxsize=512)
    def network_firmware_upgrades(self, network_id: str) -> dict | None:
        return self._call(self.dashboard.networks.getNetworkFirmwareUpgrades, network_id)

    @lru_cache(maxsize=512)
    def group_policies(self, network_id: str) -> list[dict]:
        return self._call(self.dashboard.networks.getNetworkGroupPolicies, network_id) or []

    # ----- appliance (MX) -----

    @lru_cache(maxsize=512)
    def appliance_security_intrusion(self, network_id: str) -> dict | None:
        return self._call(
            self.dashboard.appliance.getNetworkApplianceSecurityIntrusion, network_id
        )

    @lru_cache(maxsize=512)
    def appliance_security_malware(self, network_id: str) -> dict | None:
        return self._call(
            self.dashboard.appliance.getNetworkApplianceSecurityMalware, network_id
        )

    @lru_cache(maxsize=512)
    def appliance_content_filtering(self, network_id: str) -> dict | None:
        return self._call(
            self.dashboard.appliance.getNetworkApplianceContentFiltering, network_id
        )

    @lru_cache(maxsize=512)
    def appliance_l3_fw(self, network_id: str) -> dict | None:
        return self._call(
            self.dashboard.appliance.getNetworkApplianceFirewallL3FirewallRules,
            network_id,
        )

    @lru_cache(maxsize=512)
    def appliance_l7_fw(self, network_id: str) -> dict | None:
        return self._call(
            self.dashboard.appliance.getNetworkApplianceFirewallL7FirewallRules,
            network_id,
        )

    @lru_cache(maxsize=512)
    def appliance_client_vpn(self, network_id: str) -> dict | None:
        fn = getattr(
            self.dashboard.appliance, "getNetworkApplianceClientVpnSettings", None
        )
        if fn is not None:
            return self._call(fn, network_id)
        # SDK >= 2.2 dropped the convenience method; fall back to raw REST.
        import urllib.parse
        metadata = {
            "tags": ["appliance", "configure", "clientVpn", "settings"],
            "operation": "getNetworkApplianceClientVpnSettings",
        }
        resource = f"/networks/{urllib.parse.quote(network_id, safe='')}/appliance/clientVpn/settings"
        self.rate_limiter.acquire()
        try:
            return self.dashboard._session.get(metadata, resource)
        except meraki.APIError as e:
            if getattr(e, "status", None) in (404, 400):
                log.debug("API clientVpn settings -> %s: %s", e.status, e.message)
                return None
            raise APIError(f"clientVpn settings failed: {e}") from e

    @lru_cache(maxsize=512)
    def appliance_site_to_site_vpn(self, network_id: str) -> dict | None:
        return self._call(
            self.dashboard.appliance.getNetworkApplianceVpnSiteToSiteVpn, network_id
        )

    @lru_cache(maxsize=64)
    def vpn_third_party_peers(self, org_id: str) -> list[dict]:
        data = self._call(
            self.dashboard.appliance.getOrganizationApplianceVpnThirdPartyVPNPeers,
            org_id,
        )
        if not data:
            return []
        return data.get("peers") if isinstance(data, dict) else (data or [])

    @lru_cache(maxsize=512)
    def appliance_vlans(self, network_id: str) -> list[dict]:
        return self._call(
            self.dashboard.appliance.getNetworkApplianceVlans, network_id
        ) or []

    @lru_cache(maxsize=512)
    def appliance_ports(self, network_id: str) -> list[dict]:
        return self._call(
            self.dashboard.appliance.getNetworkAppliancePorts, network_id
        ) or []

    # ----- wireless (MR) -----

    @lru_cache(maxsize=512)
    def wireless_ssids(self, network_id: str) -> list[dict]:
        return self._call(
            self.dashboard.wireless.getNetworkWirelessSsids, network_id
        ) or []

    @lru_cache(maxsize=512)
    def wireless_rf_profiles(self, network_id: str) -> list[dict]:
        return self._call(
            self.dashboard.wireless.getNetworkWirelessRfProfiles, network_id
        ) or []

    @lru_cache(maxsize=512)
    def wireless_air_marshal(self, network_id: str) -> list[dict]:
        return self._call(
            self.dashboard.wireless.getNetworkWirelessAirMarshal, network_id
        ) or []

    @lru_cache(maxsize=4096)
    def wireless_ssid_firewall_l3(self, network_id: str, number: int) -> dict | None:
        return self._call(
            self.dashboard.wireless.getNetworkWirelessSsidFirewallL3FirewallRules,
            network_id,
            number,
        )

    # ----- switch (MS) -----

    @lru_cache(maxsize=4096)
    def switch_ports(self, serial: str) -> list[dict]:
        return self._call(self.dashboard.switch.getDeviceSwitchPorts, serial) or []

    @lru_cache(maxsize=512)
    def switch_stp(self, network_id: str) -> dict | None:
        return self._call(self.dashboard.switch.getNetworkSwitchStp, network_id)

    @lru_cache(maxsize=512)
    def switch_dhcp_server_policy(self, network_id: str) -> dict | None:
        return self._call(
            self.dashboard.switch.getNetworkSwitchDhcpServerPolicy, network_id
        )

    @lru_cache(maxsize=512)
    def switch_access_policies(self, network_id: str) -> list[dict]:
        return self._call(
            self.dashboard.switch.getNetworkSwitchAccessPolicies, network_id
        ) or []

    @lru_cache(maxsize=512)
    def switch_storm_control(self, network_id: str) -> dict | None:
        return self._call(
            self.dashboard.switch.getNetworkSwitchStormControl, network_id
        )

    # ----- camera (MV) -----

    @lru_cache(maxsize=4096)
    def camera_video_settings(self, serial: str) -> dict | None:
        return self._call(
            self.dashboard.camera.getDeviceCameraVideoSettings, serial
        )

    @lru_cache(maxsize=4096)
    def camera_sense(self, serial: str) -> dict | None:
        return self._call(self.dashboard.camera.getDeviceCameraSense, serial)

    # ----- sensor (MT) -----

    @lru_cache(maxsize=512)
    def sensor_alerts_profiles(self, network_id: str) -> list[dict]:
        return self._call(
            self.dashboard.sensor.getNetworkSensorAlertsProfiles, network_id
        ) or []
