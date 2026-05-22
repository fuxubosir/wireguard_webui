"""Network and AllowedIPs helpers.

This module intentionally contains pure functions only. It must not read or
write WireGuard config files and must not run system commands.
"""
from __future__ import annotations

import ipaddress
from typing import Iterable


class NetworkValidationError(ValueError):
    """Raised when a configured CIDR value cannot be normalized."""

    def __init__(self, value: str, reason: str):
        super().__init__(reason)
        self.value = value
        self.reason = reason


def csv_or_list(value) -> list[str]:
    if value is None:
        return []
    if isinstance(value, list):
        return [str(x).strip() for x in value if str(x).strip()]
    return [x.strip() for x in str(value).split(",") if x.strip()]


def network_from_cidr(value: str, fallback: str) -> tuple[str, str]:
    """Return normalized IPv4 CIDR and the current /24-style wg_net prefix."""
    try:
        net = ipaddress.ip_network(str(value or "").strip(), strict=False)
        if net.version != 4:
            raise ValueError("only ipv4")
    except Exception:
        net = ipaddress.ip_network(fallback, strict=False)
    parts = str(net.network_address).split(".")
    return str(net), ".".join(parts[:3])


def normalize_allowed_ips(items: Iterable[str]) -> str:
    seen: set[str] = set()
    out: list[str] = []
    for item in items:
        for part in str(item or "").split(","):
            ip = part.strip()
            if not ip or ip in seen:
                continue
            seen.add(ip)
            out.append(ip)
    return ",".join(out)


def normalize_ipv4_networks(values) -> list[str]:
    out: list[str] = []
    for item in csv_or_list(values):
        try:
            net = ipaddress.ip_network(str(item).strip(), strict=False)
        except Exception:
            raise NetworkValidationError(str(item), "format")
        if net.version != 4:
            raise NetworkValidationError(str(item), "ipv4")
        cidr = str(net)
        if cidr not in out:
            out.append(cidr)
    return out
