"""
List network interfaces.
"""

import netifaces
import ipaddress
from colorama import Fore, Style
from typing import Dict, List, Tuple

def get_interface_addresses() -> Dict[str, List[Tuple[str, str]]]:
    """
    Get all network interfaces and their addresses.
    
    Returns:
        A dictionary mapping interface names to lists of (address type, address) tuples
    """
    interfaces = {}
    
    for iface_name in netifaces.interfaces():
        interfaces[iface_name] = []
        
        # Get addresses for each interface
        addrs = netifaces.ifaddresses(iface_name)
        
        # IPv4 addresses
        if netifaces.AF_INET in addrs:
            for addr in addrs[netifaces.AF_INET]:
                if 'addr' in addr:
                    ip = ipaddress.IPv4Address(addr['addr'])
                    interfaces[iface_name].append(('IPv4', str(ip)))
        
        # IPv6 addresses
        if netifaces.AF_INET6 in addrs:
            for addr in addrs[netifaces.AF_INET6]:
                if 'addr' in addr:
                    # Remove scope ID if present
                    addr_str = addr['addr'].split('%')[0]
                    ip = ipaddress.IPv6Address(addr_str)
                    interfaces[iface_name].append(('IPv6', str(ip)))
    
    return interfaces

def list_interfaces() -> None:
    """
    List all network interfaces and their addresses.
    """
    interfaces = get_interface_addresses()
    
    if not interfaces:
        print(f"{Fore.RED}No network interfaces found{Style.RESET_ALL}")
        return
    
    print(f"{Fore.GREEN}Available network interfaces:{Style.RESET_ALL}")
    print("")
    
    for iface_name, addresses in interfaces.items():
        if not addresses:
            continue
            
        print(f"{Fore.CYAN}{iface_name}{Style.RESET_ALL}:")
        
        for addr_type, addr in addresses:
            loopback = ""
            ip = ipaddress.ip_address(addr)
            
            if ip.is_loopback:
                loopback = f" {Fore.RED}(loopback){Style.RESET_ALL}"
                
            print(f"  {Fore.YELLOW}{addr_type}{Style.RESET_ALL}: {addr}{loopback}")
        
        print("") 