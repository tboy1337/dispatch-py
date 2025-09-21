"""
Network utilities for the SOCKS proxy.
"""

import socket
import ipaddress
from typing import Union

def create_bound_socket(ip_address: Union[ipaddress.IPv4Address, ipaddress.IPv6Address],
                        socket_type: int = socket.SOCK_STREAM) -> socket.socket:
    """
    Create a socket bound to the specified IP address.
    
    Args:
        ip_address: The IP address to bind to
        socket_type: The socket type (default: SOCK_STREAM for TCP)
        
    Returns:
        A socket bound to the specified IP address
    """
    if isinstance(ip_address, ipaddress.IPv4Address):
        sock = socket.socket(socket.AF_INET, socket_type)
        sock.bind((str(ip_address), 0))  # Bind to any available port
    else:
        sock = socket.socket(socket.AF_INET6, socket_type)
        sock.bind((str(ip_address), 0))  # Bind to any available port

    return sock

def get_address_family(ip_address: Union[ipaddress.IPv4Address, ipaddress.IPv6Address]) -> int:
    """
    Get the address family for the given IP address.
    
    Args:
        ip_address: The IP address to get the family for
        
    Returns:
        The address family (socket.AF_INET or socket.AF_INET6)
    """
    if isinstance(ip_address, ipaddress.IPv4Address):
        return socket.AF_INET

    return socket.AF_INET6
