#!/usr/bin/env python3
"""
Socket patching for simulating multiple network interfaces.
"""

import socket
import threading
import logging
import ipaddress
from typing import Dict, Set, Tuple, List, Optional, Callable, Any, Union

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Store original socket functions
_orig_socket = socket.socket
_orig_gethostbyname = socket.gethostbyname
_orig_getaddrinfo = socket.getaddrinfo

# Get the original socket methods
_orig_bind = socket.socket.bind
_orig_connect = socket.socket.connect
_orig_sendto = socket.socket.sendto
_orig_recvfrom = socket.socket.recvfrom

# Mappings for tracking socket state
socket_bindings = {}  # fileno -> virtual_ip
socket_locks = {}     # fileno -> lock
local_ip_mapping = {} # hostname -> ip

# Reference to the current network simulator - will be set by NetworkPatcher
# This avoids circular imports
current_network_sim = None

class PatchedSocket(socket.socket):
    """Patched socket class for simulating multiple interfaces"""
    
    def __init__(self, *args, **kwargs):
        """Initialize a patched socket"""
        # Call original init
        super().__init__(*args, **kwargs)
        
        # Create a lock for this socket
        socket_locks[self.fileno()] = threading.RLock()
        
        logger.debug(f"Created patched socket {self.fileno()}")
    
    def bind(self, address):
        """Intercept socket binding to associate with virtual interfaces"""
        host, port = address if isinstance(address, tuple) else (address, 0)
        
        with socket_locks[self.fileno()]:
            # Check if this is one of our virtual interfaces
            if isinstance(host, str) and host in local_ip_mapping:
                virtual_ip = local_ip_mapping[host]
                logger.debug(f"Binding socket {self.fileno()} to virtual interface {virtual_ip}")
                
                # Store the binding for later use
                socket_bindings[self.fileno()] = virtual_ip
                
                # Let the network simulator know about this binding
                if current_network_sim:
                    current_network_sim.bind_socket(self, virtual_ip)
                
                # Call original bind with the actual IP
                return _orig_bind(self, (host, port))
            else:
                # Not a virtual interface, proceed normally
                return _orig_bind(self, address)
    
    def connect(self, address):
        """Intercept socket connections"""
        # Just pass through to original for now
        return _orig_connect(self, address)
    
    def sendto(self, data, *args):
        """Intercept socket sendto operations to simulate network conditions"""
        # Extract address from args (could be either (flags, address) or just address)
        if len(args) == 1:
            address = args[0]
            flags = 0
        else:
            flags, address = args
        
        with socket_locks[self.fileno()]:
            # Check if this socket is bound to a virtual interface
            if self.fileno() in socket_bindings and current_network_sim:
                virtual_ip = socket_bindings[self.fileno()]
                
                # Create a callback to track when the packet is actually sent
                result = [None]
                event = threading.Event()
                
                def send_callback(success):
                    if success:
                        try:
                            # Actual send happens in the simulator
                            pass
                        except Exception as e:
                            logger.error(f"Error in sendto callback: {e}")
                            result[0] = e
                    event.set()
                
                # Queue the packet for sending
                current_network_sim.send_through_interface(self, data, address, send_callback)
                
                # Wait for the packet to be processed
                if not event.wait(timeout=10):
                    logger.warning(f"Timeout waiting for packet to be sent on interface {virtual_ip}")
                
                # If there was an error, raise it
                if isinstance(result[0], Exception):
                    raise result[0]
                
                # Return the number of bytes sent
                return len(data)
            else:
                # Not using a virtual interface, proceed normally
                return _orig_sendto(self, data, *args)
    
    def recvfrom(self, bufsize, flags=0):
        """Intercept socket recvfrom operations"""
        # Just pass through to original for now - we're only simulating outbound traffic
        return _orig_recvfrom(self, bufsize, flags)
    
    def close(self):
        """Clean up when socket is closed"""
        with socket_locks[self.fileno()]:
            if self.fileno() in socket_bindings:
                del socket_bindings[self.fileno()]
            
            if self.fileno() in socket_locks:
                del socket_locks[self.fileno()]
        
        return super().close()


def patched_gethostbyname(host):
    """Patch gethostbyname to return virtual IPs for specific hosts during testing"""
    # Check if we're looking up a virtual hostname
    if host in local_ip_mapping:
        return local_ip_mapping[host]
    
    # Otherwise use the original implementation
    return _orig_gethostbyname(host)


def patched_getaddrinfo(host, port, family=0, type=0, proto=0, flags=0):
    """Patch getaddrinfo to handle virtual IPs"""
    # Check if we're looking up a virtual hostname
    if host in local_ip_mapping:
        virtual_ip = local_ip_mapping[host]
        
        # Create a response that matches what getaddrinfo would return
        family_val = family if family != 0 else socket.AF_INET
        sock_type = type if type != 0 else socket.SOCK_STREAM
        proto_val = proto if proto != 0 else 0
        
        return [(family_val, sock_type, proto_val, '', (virtual_ip, port))]
    
    # Otherwise use the original implementation
    return _orig_getaddrinfo(host, port, family, type, proto, flags)


def register_virtual_host(hostname: str, ip_address: str):
    """Register a hostname to resolve to a specific virtual IP address"""
    local_ip_mapping[hostname] = ip_address
    logger.info(f"Registered virtual host: {hostname} -> {ip_address}")


def install_socket_patch():
    """Install the socket patching to intercept network operations"""
    logger.info("Installing socket patching for virtual interfaces")
    
    # Patch socket.socket
    socket.socket = PatchedSocket
    
    # Patch DNS resolution
    socket.gethostbyname = patched_gethostbyname
    socket.getaddrinfo = patched_getaddrinfo
    
    return True


def remove_socket_patch():
    """Remove the socket patching and restore original behavior"""
    logger.info("Removing socket patching")
    
    # Restore original functions
    socket.socket = _orig_socket
    socket.gethostbyname = _orig_gethostbyname
    socket.getaddrinfo = _orig_getaddrinfo
    
    # Clear mappings
    socket_bindings.clear()
    socket_locks.clear()
    local_ip_mapping.clear()
    
    return True


class NetworkPatcher:
    """Context manager for patching network functions during tests"""
    
    def __init__(self, interface_configs_or_simulator=None, virtual_hosts=None, interface_configs=None):
        """
        Initialize the network patcher
        
        Args:
            interface_configs_or_simulator: Either a list of interface configurations,
                                            a NetworkSimulator instance, or None for defaults
            virtual_hosts: Dict mapping hostnames to virtual IPs
            interface_configs: Alternative way to specify interface configurations
                              (for backward compatibility)
        """
        self.interface_configs = None
        self.simulator = None
        
        # Check if interface_configs is directly provided (for backward compatibility)
        if interface_configs is not None:
            self.interface_configs = interface_configs
        else:
            # Check if we received a NetworkSimulator instance or interface configs
            from tests.network_simulator import NetworkSimulator
            if isinstance(interface_configs_or_simulator, NetworkSimulator):
                self.simulator = interface_configs_or_simulator
            else:
                self.interface_configs = interface_configs_or_simulator
        
        self.virtual_hosts = virtual_hosts or {}
    
    def __enter__(self):
        global current_network_sim
        from tests.network_simulator import create_simulated_network
        
        # Create the simulated network if we don't already have a simulator
        if self.simulator is None:
            # If we have interface_configs, create simulator from those configs
            self.simulator = create_simulated_network(self.interface_configs)
        
        # Update the global network_sim reference
        current_network_sim = self.simulator
        
        # Install socket patching
        install_socket_patch()
        
        # Register virtual hosts
        for hostname, ip in self.virtual_hosts.items():
            register_virtual_host(hostname, ip)
        
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        global current_network_sim
        from tests.network_simulator import cleanup_simulated_network
        
        # Remove socket patching
        remove_socket_patch()
        
        # Clean up the network simulator
        if self.simulator:
            cleanup_simulated_network()
            
        # Clear the reference
        current_network_sim = None
        
        return False  # Don't suppress exceptions


# Example usage:
# with NetworkPatcher() as patcher:
#     # Run tests here
#     pass 