from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml


@dataclass
class MerakiSettings:
    api_key: str
    base_url: str | None = None
    timeout: int = 60
    max_requests_per_second: float | None = None


@dataclass
class Config:
    meraki: MerakiSettings
    organizations: list[str] = field(default_factory=list)
    networks: list[str] = field(default_factory=list)
    skip_checks: list[str] = field(default_factory=list)
    only_checks: list[str] = field(default_factory=list)
    output_dir: Path = Path("./reports")
    formats: list[str] = field(default_factory=lambda: ["console", "json", "csv"])
    thresholds: dict[str, Any] = field(default_factory=dict)
    # Limit how many devices of each product type are scanned per org.
    device_sample_per_type: int | None = None
    device_sample: dict[str, int] = field(default_factory=dict)

    @classmethod
    def load(cls, path: str | Path) -> "Config":
        raw = yaml.safe_load(Path(path).read_text())
        if not isinstance(raw, dict):
            raise ValueError(f"{path}: expected a YAML mapping at the top level")

        meraki_raw = raw.get("meraki") or {}
        api_key = meraki_raw.get("api_key")
        if not api_key or api_key == "YOUR_MERAKI_DASHBOARD_API_KEY":
            raise ValueError(
                f"{path}: meraki.api_key is missing. Set it to a real Dashboard API key."
            )

        rps_raw = meraki_raw.get("max_requests_per_second")
        rps = float(rps_raw) if rps_raw not in (None, "", 0) else None

        sample_per = raw.get("device_sample_per_type")
        sample_per = int(sample_per) if sample_per not in (None, "", 0) else None
        sample_map_raw = raw.get("device_sample") or {}
        sample_map: dict[str, int] = {}
        for k, v in sample_map_raw.items():
            if v in (None, "", 0):
                continue
            sample_map[str(k).lower()] = int(v)

        return cls(
            meraki=MerakiSettings(
                api_key=api_key,
                base_url=meraki_raw.get("base_url"),
                timeout=int(meraki_raw.get("timeout", 60)),
                max_requests_per_second=rps,
            ),
            organizations=list(raw.get("organizations") or []),
            networks=list(raw.get("networks") or []),
            skip_checks=list(raw.get("skip_checks") or []),
            only_checks=list(raw.get("only_checks") or []),
            output_dir=Path(raw.get("output_dir") or "./reports"),
            formats=list(raw.get("formats") or ["console", "json", "csv"]),
            thresholds=dict(raw.get("thresholds") or {}),
            device_sample_per_type=sample_per,
            device_sample=sample_map,
        )
