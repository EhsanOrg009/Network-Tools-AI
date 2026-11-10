"""Shared target authorization for all active network execution paths."""

from __future__ import annotations

import ipaddress
import re
import socket
from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from netagent.config import Settings
    from netagent.database import Database

_HOST = re.compile(r"(?=.{1,253}\Z)[A-Za-z0-9](?:[A-Za-z0-9_.-]*[A-Za-z0-9])?\Z")
_ZONE = re.compile(r"[A-Za-z0-9_.-]{1,64}\Z")


class TargetNotAuthorized(ValueError):
    pass


def normalized_network(value: str):
    """Normalize mapped IPv6 into its effective IPv4 network."""
    network = ipaddress.ip_network(value, strict=False)
    if network.version == 6 and network.network_address.ipv4_mapped is not None:
        if network.prefixlen < 96:
            raise ValueError("IPv4-mapped range must have prefix >=96")
        return ipaddress.ip_network(f"{network.network_address.ipv4_mapped}/{network.prefixlen - 96}")
    return network


@dataclass
class ToolScope:
    settings: Settings
    extra_targets: list[str]
    db: Database | None = None

    def networks(self, *, discovery: bool = False) -> list[str]:
        values = [str(n) for n in self.settings.monitor_cidr_list + self.settings.authorized_target_list]
        values += self.extra_targets
        # Derived policy authorizes low-impact discovery only, never arbitrary
        # port scans, ping, or model-selected follow-up diagnostics.
        if discovery and self.db is not None:
            from netagent.services.discovery import auto_discovery_eligible_networks
            values += [e["cidr"] for e in auto_discovery_eligible_networks(self.db, self.settings)]
        return values

    def authorize(self, target: str, *, hostname: bool = False,
                  host_only: bool = False, discovery: bool = False) -> str:
        target = str(target or "").strip()
        if not target or len(target) > 253 or any(c.isspace() for c in target) or target.startswith("-"):
            raise TargetNotAuthorized("invalid target")
        zone = ""
        literal = target
        if "%" in literal:
            literal, zone = literal.split("%", 1)
            if not _ZONE.fullmatch(zone) or "/" in literal:
                raise TargetNotAuthorized("invalid IPv6 zone identifier")
            try:
                addr = ipaddress.ip_address(literal)
                if addr.version != 6 or not addr.is_link_local:
                    raise ValueError()
            except ValueError as exc:
                raise TargetNotAuthorized("zone requires a link-local IPv6 address") from exc
        try:
            candidate = normalized_network(literal)
        except ValueError as exc:
            if not hostname or zone or not _HOST.fullmatch(target):
                raise TargetNotAuthorized("target is not an IP or CIDR") from exc
            try:
                resolved = socket.getaddrinfo(target, None, type=socket.SOCK_STREAM)
            except OSError as err:
                raise TargetNotAuthorized("DNS resolution failed") from err
            addresses = []
            for family, _, _, _, sockaddr in resolved:
                if family not in (socket.AF_INET, socket.AF_INET6):
                    continue
                address = sockaddr[0]
                if family == socket.AF_INET6 and len(sockaddr) > 3 and sockaddr[3]:
                    address += f"%{sockaddr[3]}"
                addresses.append(self.authorize(address, host_only=True, discovery=discovery))
            if not addresses:
                raise TargetNotAuthorized("DNS returned no IP addresses")
            # Pass a checked numeric address to subprocess/socket: no second
            # DNS lookup of the untrusted name can change the destination.
            return addresses[0]
        if host_only and candidate.prefixlen != candidate.max_prefixlen:
            raise TargetNotAuthorized("a single host is required")
        allowed = False
        for value in self.networks(discovery=discovery):
            try:
                network = normalized_network(value)
                if candidate.version == network.version and candidate.subnet_of(network):
                    allowed = True
                    break
            except ValueError:
                continue
        if not allowed:
            raise TargetNotAuthorized(f"target {candidate} outside authorized scope / خارج از محدودهٔ مجاز")
        if candidate.prefixlen == candidate.max_prefixlen:
            return str(candidate.network_address) + (f"%{zone}" if zone else "")
        return str(candidate)
