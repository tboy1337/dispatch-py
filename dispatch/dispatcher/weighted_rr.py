"""
Weighted round-robin dispatcher implementation.
"""

import asyncio
import ipaddress
import socket
from dataclasses import dataclass
from typing import List, Optional, Tuple, Union

import netifaces

from .base import Dispatch

@dataclass
class RawWeightedAddress:
    """Raw weighted address as parsed from command line arguments."""
    interface: str
    weight: int = 1

    @classmethod
    def from_str(cls, src: str) -> 'RawWeightedAddress':
        """Parse a weighted address from a string."""
        parts = src.split('/')
        interface = parts[0]
        weight = int(parts[1]) if len(parts) > 1 else 1

        if weight <= 0:
            raise ValueError(f"Weight must be positive, got {weight}")

        return cls(interface=interface, weight=weight)

class Interface:
    """Represents a network interface or IP address."""

    def __init__(self,
                 name: Optional[str] = None,
                 ipv4: Optional[ipaddress.IPv4Address] = None,
                 ipv6: Optional[ipaddress.IPv6Address] = None,
                 ip: Optional[Union[ipaddress.IPv4Address, ipaddress.IPv6Address]] = None):
        """
        Initialize an interface.

        Args:
            name: Interface name
            ipv4: IPv4 address
            ipv6: IPv6 address
            ip: Direct IP address
        """
        self.name = name
        self.ipv4 = ipv4
        self.ipv6 = ipv6
        self.ip = ip

    @property
    def is_named(self) -> bool:
        """Return True if this is a named interface."""
        return self.name is not None

    @property
    def is_direct_ip(self) -> bool:
        """Return True if this is a direct IP address."""
        return self.ip is not None

@dataclass
class WeightedAddress:
    """A weighted address for the dispatcher."""
    interface: Interface
    weight: int

    def __str__(self) -> str:
        """Return a string representation of the weighted address."""
        if self.interface.is_named:
            result = f"{self.interface.name}/{self.weight}"
            if self.interface.ipv4:
                result += f" ({self.interface.ipv4})"
            if self.interface.ipv6:
                result += f" ({self.interface.ipv6})"
            return result
        if self.interface.is_direct_ip:
            return f"{self.interface.ip}/{self.weight}"

        return f"Unknown interface/{self.weight}"

    @classmethod
    def resolve(cls, addresses: List[RawWeightedAddress]) -> List['WeightedAddress']:
        """Resolve raw weighted addresses to actual network interfaces or IP addresses."""
        # pylint: disable=too-many-branches  # Complex algorithm requires multiple branches
        result = []

        # Get all network interfaces
        interfaces: dict[
            str, dict[str, Union[ipaddress.IPv4Address, ipaddress.IPv6Address, None]]
        ] = {}
        for iface_name in netifaces.interfaces():  # type: ignore[misc]
            ipv4_addrs: List[ipaddress.IPv4Address] = []
            ipv6_addrs: List[ipaddress.IPv6Address] = []

            # Get addresses for each interface
            addrs = netifaces.ifaddresses(iface_name)  # type: ignore[misc]

            # IPv4 addresses
            if netifaces.AF_INET in addrs:  # type: ignore[misc]
                for addr in addrs[netifaces.AF_INET]:  # type: ignore[misc]
                    if 'addr' in addr:  # type: ignore[misc]
                        ip = ipaddress.IPv4Address(addr['addr'])  # type: ignore[misc]
                        if not ip.is_loopback:
                            ipv4_addrs.append(ip)

            # IPv6 addresses
            if netifaces.AF_INET6 in addrs:  # type: ignore[misc]
                for addr in addrs[netifaces.AF_INET6]:  # type: ignore[misc]
                    if 'addr' in addr:  # type: ignore[misc]
                        # Remove scope ID if present
                        addr_str = addr['addr'].split('%')[0]  # type: ignore[misc]
                        ipv6 = ipaddress.IPv6Address(addr_str)  # type: ignore[misc]
                        if not ipv6.is_loopback:
                            ipv6_addrs.append(ipv6)

            interfaces[iface_name] = {  # type: ignore[misc]
                'ipv4': ipv4_addrs[0] if ipv4_addrs else None,
                'ipv6': ipv6_addrs[0] if ipv6_addrs else None
            }

        # Process each weighted address
        for addr in addresses:
            # Try to find the interface by name
            if addr.interface in interfaces:
                iface = interfaces[addr.interface]
                ipv4_union = iface['ipv4']
                ipv6_union = iface['ipv6']

                if not ipv4_union and not ipv6_union:
                    raise ValueError(
                        f"No IP addresses found for network interface '{addr.interface}'"
                    )

                # Cast to proper types for Interface constructor
                ipv4_addr = ipv4_union if isinstance(ipv4_union, ipaddress.IPv4Address) else None
                ipv6_addr = ipv6_union if isinstance(ipv6_union, ipaddress.IPv6Address) else None

                interface = Interface(name=addr.interface, ipv4=ipv4_addr, ipv6=ipv6_addr)
                result.append(cls(interface=interface, weight=addr.weight))
            else:
                # Try to parse as IP address
                try:
                    ip_addr = ipaddress.ip_address(addr.interface)
                    if ip_addr.is_loopback:
                        raise ValueError(f"Local address '{ip_addr}' is a loopback address")
                    interface = Interface(ip=ip_addr)
                    result.append(cls(interface=interface, weight=addr.weight))
                except ValueError as exc:
                    raise ValueError(
                        f"Failed to parse '{addr.interface}' as an IP address or "
                        f"network interface name"
                    ) from exc

        return result

@dataclass
class WeightedIp:
    """An IP address with a weight for the dispatcher."""
    ip: Union[ipaddress.IPv4Address, ipaddress.IPv6Address]
    weight: int

class State:
    """State for a specific IP address type (IPv4 or IPv6) in the dispatcher."""

    def __init__(self, ips: List[WeightedIp]):
        """
        Initialize the state.

        Args:
            ips: List of weighted IP addresses
        """
        self.ips = ips
        self.ip_idx = 0
        self.count = 0

class WeightedRoundRobinDispatcher(Dispatch):
    """A weighted round-robin dispatcher that selects local addresses for connections."""

    def __init__(self, addresses: List[WeightedAddress]):
        """
        Initialize the dispatcher.

        Args:
            addresses: List of weighted addresses to dispatch to

        Raises:
            ValueError: If no addresses are provided
        """
        if not addresses:
            raise ValueError("No addresses provided for dispatcher")

        self.lock = asyncio.Lock()

        # Group by IP version
        ipv4_ips = []
        ipv6_ips = []

        for addr in addresses:
            if addr.interface.is_direct_ip:
                ip = addr.interface.ip
                if ip is not None:
                    if isinstance(ip, ipaddress.IPv4Address):
                        ipv4_ips.append(WeightedIp(ip=ip, weight=addr.weight))
                    else:
                        ipv6_ips.append(WeightedIp(ip=ip, weight=addr.weight))
            else:
                if addr.interface.ipv4:
                    ipv4_ips.append(WeightedIp(ip=addr.interface.ipv4, weight=addr.weight))
                if addr.interface.ipv6:
                    ipv6_ips.append(WeightedIp(ip=addr.interface.ipv6, weight=addr.weight))

        self.ipv4 = State(ips=ipv4_ips)
        self.ipv6 = State(ips=ipv6_ips)

    async def dispatch(
        self, remote_address: Tuple[str, int]
    ) -> Union[ipaddress.IPv4Address, ipaddress.IPv6Address]:
        """
        Select a local IP address for an outgoing connection.

        Args:
            remote_address: The remote address to connect to

        Returns:
            A local IP address to bind to
        """
        async with self.lock:
            # Get remote IP
            try:
                remote_host = remote_address[0]
                # Check if it's already an IP address
                remote_ip = ipaddress.ip_address(remote_host)
            except ValueError as hostname_exc:
                # It's a hostname, resolve it
                try:
                    # Get address info for the hostname
                    info = await asyncio.get_event_loop().getaddrinfo(
                        remote_host,
                        remote_address[1],
                        type=socket.SOCK_STREAM
                    )
                    if not info:
                        raise ValueError(
                            f"Could not resolve hostname: {remote_host}"
                        ) from hostname_exc

                    # Get the first address
                    remote_ip = ipaddress.ip_address(info[0][4][0])
                except Exception as exc:
                    raise ValueError(f"Failed to resolve hostname: {remote_host}") from exc

            # Select the appropriate state based on the remote IP type
            if isinstance(remote_ip, ipaddress.IPv4Address):
                state = self.ipv4
                if not state.ips:
                    raise ValueError("No IPv4 address available for dispatching")
            else:
                state = self.ipv6
                if not state.ips:
                    raise ValueError("No IPv6 address available for dispatching")

            # Select an IP using the weighted round robin algorithm
            weighted_ip = state.ips[state.ip_idx]
            state.count += 1

            # If we've reached the weight, move to the next IP
            if state.count >= weighted_ip.weight:
                state.count = 0
                state.ip_idx = (state.ip_idx + 1) % len(state.ips)

            return weighted_ip.ip
