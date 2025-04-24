"""
Weighted round-robin dispatcher implementation.
"""

import asyncio
import ipaddress
import netifaces
import socket
from typing import Dict, List, Optional, Tuple, Union, cast
from dataclasses import dataclass
import re

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
        elif self.interface.is_direct_ip:
            return f"{self.interface.ip}/{self.weight}"
        else:
            return f"Unknown interface/{self.weight}"
    
    @classmethod
    def resolve(cls, addresses: List[RawWeightedAddress]) -> List['WeightedAddress']:
        """Resolve raw weighted addresses to actual network interfaces or IP addresses."""
        result = []
        
        # Get all network interfaces
        interfaces = {}
        for iface_name in netifaces.interfaces():
            ipv4_addrs = []
            ipv6_addrs = []
            
            # Get addresses for each interface
            addrs = netifaces.ifaddresses(iface_name)
            
            # IPv4 addresses
            if netifaces.AF_INET in addrs:
                for addr in addrs[netifaces.AF_INET]:
                    if 'addr' in addr:
                        ip = ipaddress.IPv4Address(addr['addr'])
                        if not ip.is_loopback:
                            ipv4_addrs.append(ip)
            
            # IPv6 addresses
            if netifaces.AF_INET6 in addrs:
                for addr in addrs[netifaces.AF_INET6]:
                    if 'addr' in addr:
                        # Remove scope ID if present
                        addr_str = addr['addr'].split('%')[0]
                        ip = ipaddress.IPv6Address(addr_str)
                        if not ip.is_loopback:
                            ipv6_addrs.append(ip)
            
            interfaces[iface_name] = {
                'ipv4': ipv4_addrs[0] if ipv4_addrs else None,
                'ipv6': ipv6_addrs[0] if ipv6_addrs else None
            }
        
        # Process each weighted address
        for addr in addresses:
            # Try to find the interface by name
            if addr.interface in interfaces:
                iface = interfaces[addr.interface]
                ipv4 = iface['ipv4']
                ipv6 = iface['ipv6']
                
                if not ipv4 and not ipv6:
                    raise ValueError(f"No IP addresses found for network interface '{addr.interface}'")
                
                interface = Interface(name=addr.interface, ipv4=ipv4, ipv6=ipv6)
                result.append(cls(interface=interface, weight=addr.weight))
            else:
                # Try to parse as IP address
                try:
                    ip = ipaddress.ip_address(addr.interface)
                    if ip.is_loopback:
                        raise ValueError(f"Local address '{ip}' is a loopback address")
                    interface = Interface(ip=ip)
                    result.append(cls(interface=interface, weight=addr.weight))
                except ValueError:
                    raise ValueError(f"Failed to parse '{addr.interface}' as an IP address or network interface name")
        
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
        """
        self.lock = asyncio.Lock()
        
        # Group by IP version
        ipv4_ips = []
        ipv6_ips = []
        
        for addr in addresses:
            if addr.interface.is_direct_ip:
                ip = addr.interface.ip
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
    
    async def dispatch(self, remote_address: Tuple[str, int]) -> Union[ipaddress.IPv4Address, ipaddress.IPv6Address]:
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
            except ValueError:
                # It's a hostname, resolve it
                try:
                    # Get address info for the hostname
                    info = await asyncio.get_event_loop().getaddrinfo(
                        remote_host, 
                        remote_address[1],
                        type=socket.SOCK_STREAM
                    )
                    if not info:
                        raise ValueError(f"Could not resolve hostname: {remote_host}")
                    
                    # Get the first address
                    remote_ip = ipaddress.ip_address(info[0][4][0])
                except Exception as e:
                    raise ValueError(f"Failed to resolve hostname: {remote_host}") from e
            
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