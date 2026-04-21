"""Importing this package registers all built-in checks with the registry."""
from meraki_sec.checks import (  # noqa: F401
    organization,
    network,
    appliance,
    wireless,
    switch,
    camera,
    sensor,
)
