"""
List network interfaces.
"""

import ipaddress
from typing import Dict, List, Tuple

import netifaces
from colorama import Fore, Style

def get_interface_addresses() -> Dict[str, List[Tuple[str, str]]]:
    """
    Get all network interfaces and their addresses.
    
    Returns:
        A dictionary mapping interface names to lists of (address type, address) tuples
    """
    interfaces: Dict[str, List[Tuple[str, str]]] = {}

    for iface_name in netifaces.interfaces():  # type: ignore[misc]
        interfaces[iface_name] = []  # type: ignore[misc]

        # Get addresses for each interface
        addrs = netifaces.ifaddresses(iface_name)  # type: ignore[misc]

        # IPv4 addresses
        if netifaces.AF_INET in addrs:  # type: ignore[misc]
            for addr in addrs[netifaces.AF_INET]:  # type: ignore[misc]
                if 'addr' in addr:  # type: ignore[misc]
                    ip = ipaddress.IPv4Address(addr['addr'])  # type: ignore[misc]
                    interfaces[iface_name].append(('IPv4', str(ip)))  # type: ignore[misc]

        # IPv6 addresses
        if netifaces.AF_INET6 in addrs:  # type: ignore[misc]
            for addr in addrs[netifaces.AF_INET6]:  # type: ignore[misc]
                if 'addr' in addr:  # type: ignore[misc]
                    # Remove scope ID if present
                    addr_str = addr['addr'].split('%')[0]  # type: ignore[misc]
                    ip_v6 = ipaddress.IPv6Address(addr_str)  # type: ignore[misc]
                    interfaces[iface_name].append(('IPv6', str(ip_v6)))  # type: ignore[misc]

    return interfaces

def list_interfaces() -> None:
    """
    List all network interfaces and their addresses.
    """
    interfaces = get_interface_addresses()

    if not interfaces:
        print(f"{Fore.RED}No network interfaces found{Style.RESET_ALL}")  # type: ignore[misc]
        return

    print(f"{Fore.GREEN}Available network interfaces:{Style.RESET_ALL}")  # type: ignore[misc]
    print("")

    for iface_name, addresses in interfaces.items():
        if not addresses:
            continue

        print(f"{Fore.CYAN}{iface_name}{Style.RESET_ALL}:")  # type: ignore[misc]

        for addr_type, addr in addresses:
            loopback = ""
            ip = ipaddress.ip_address(addr)

            if ip.is_loopback:
                loopback = f" {Fore.RED}(loopback){Style.RESET_ALL}"  # type: ignore[misc]

            print(
                f"  {Fore.YELLOW}{addr_type}{Style.RESET_ALL}: "  # type: ignore[misc]
                f"{addr}{loopback}"
            )

        print("")
