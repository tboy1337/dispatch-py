#!/usr/bin/env python3
"""
Network interface simulator for testing dispatch-py without requiring multiple physical connections.
This module creates virtual network interfaces with configurable properties like bandwidth, latency, and packet loss.
"""

import socket
import threading
import time
import random
import logging
import queue
from typing import Dict, List, Tuple, Optional, Callable, Union
import ipaddress

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class VirtualInterface:
    """Represents a simulated network interface with configurable properties"""
    
    def __init__(self, ip_address: str, bandwidth_kbps: int = 1000, 
                 latency_ms: int = 20, packet_loss_percent: float = 0.0,
                 jitter_ms: int = 0, name: str = None):
        """
        Initialize a virtual network interface
        
        Args:
            ip_address: IP address for this interface
            bandwidth_kbps: Bandwidth limit in Kbps
            latency_ms: Base latency in milliseconds
            packet_loss_percent: Percentage of packets to drop (0-100)
            jitter_ms: Random jitter to add to latency (+/- jitter_ms)
            name: Optional name for this interface
        """
        self.ip_address = ip_address
        self.bandwidth_kbps = bandwidth_kbps
        self.latency_ms = latency_ms
        self.packet_loss_percent = packet_loss_percent
        self.jitter_ms = jitter_ms
        self.name = name or f"vif-{ip_address}"
        
        # Track bytes sent for bandwidth simulation
        self.bytes_sent = 0
        self.last_send_time = time.time()
        
        # For statistics
        self.total_bytes_sent = 0
        self.total_packets_sent = 0
        self.dropped_packets = 0
        
        # State
        self.up = True
        self._lock = threading.RLock()
    
    def should_drop_packet(self, size: int) -> bool:
        """Determine if a packet should be dropped based on packet loss rate"""
        if not self.up:
            return True
        
        if self.packet_loss_percent > 0:
            return random.random() * 100 < self.packet_loss_percent
        
        return False
    
    def calculate_delay(self) -> float:
        """Calculate the delay for this packet in seconds"""
        if not self.up:
            return float('inf')  # Interface is down
            
        base_delay = self.latency_ms / 1000.0  # convert to seconds
        
        if self.jitter_ms > 0:
            # Add random jitter
            jitter = (random.random() * 2 - 1) * (self.jitter_ms / 1000.0)
            return max(0, base_delay + jitter)
        
        return base_delay
    
    def simulate_bandwidth_limit(self, size: int) -> float:
        """
        Simulate bandwidth limitation by calculating how long sending should take
        Returns the additional delay in seconds needed to enforce the bandwidth limit
        """
        if self.bandwidth_kbps <= 0:
            return 0  # No bandwidth limit
            
        with self._lock:
            now = time.time()
            time_diff = now - self.last_send_time
            
            # Reset byte counter if it's been a while
            if time_diff > 1.0:
                self.bytes_sent = 0
            
            # Calculate how long this packet should take to send
            bits_to_send = size * 8
            ideal_time = bits_to_send / (self.bandwidth_kbps * 1000)
            
            # Update stats
            self.bytes_sent += size
            self.total_bytes_sent += size
            self.last_send_time = now
            
            return ideal_time
    
    def send_packet(self, data: bytes, dest: Tuple[str, int]) -> Tuple[bool, float]:
        """
        Simulate sending a packet through this interface
        
        Args:
            data: The data to send
            dest: (host, port) destination tuple
            
        Returns:
            (success, delay): Whether the packet was sent and the delay in seconds
        """
        with self._lock:
            self.total_packets_sent += 1
            
            # Check if packet should be dropped
            if self.should_drop_packet(len(data)):
                self.dropped_packets += 1
                return False, 0
            
            # Calculate delay components
            network_delay = self.calculate_delay()
            bandwidth_delay = self.simulate_bandwidth_limit(len(data))
            
            total_delay = network_delay + bandwidth_delay
            
            return True, total_delay
    
    def get_stats(self) -> Dict:
        """Get statistics for this interface"""
        with self._lock:
            return {
                "name": self.name,
                "ip": self.ip_address,
                "up": self.up,
                "bandwidth_kbps": self.bandwidth_kbps,
                "latency_ms": self.latency_ms,
                "packet_loss_percent": self.packet_loss_percent,
                "total_bytes_sent": self.total_bytes_sent,
                "total_packets_sent": self.total_packets_sent,
                "dropped_packets": self.dropped_packets,
                "loss_rate": (self.dropped_packets / max(1, self.total_packets_sent)) * 100
            }
    
    def set_up(self, status: bool = True):
        """Set the interface up or down"""
        with self._lock:
            self.up = status
    
    def __str__(self):
        return f"{self.name} ({self.ip_address}): {'UP' if self.up else 'DOWN'}"


class NetworkSimulator:
    """
    Simulates a network with multiple virtual interfaces.
    Intercepts socket connections and routes them through the virtual interfaces.
    """
    
    def __init__(self):
        self.interfaces: Dict[str, VirtualInterface] = {}
        self.active = False
        self._lock = threading.RLock()
        self.socket_map: Dict[socket.socket, str] = {}  # Maps sockets to interface IPs
        self.packet_queue = queue.Queue()
        self._worker_thread = None
    
    def add_interface(self, interface: VirtualInterface) -> None:
        """Add a virtual interface to the simulator"""
        with self._lock:
            self.interfaces[interface.ip_address] = interface
            logger.info(f"Added virtual interface: {interface}")
    
    def create_interface(self, ip_address: str, **kwargs) -> VirtualInterface:
        """Create and add a new virtual interface"""
        interface = VirtualInterface(ip_address, **kwargs)
        self.add_interface(interface)
        return interface
    
    def remove_interface(self, ip_address: str) -> None:
        """Remove a virtual interface"""
        with self._lock:
            if ip_address in self.interfaces:
                del self.interfaces[ip_address]
                logger.info(f"Removed virtual interface: {ip_address}")
    
    def bind_socket(self, sock: socket.socket, ip_address: str) -> bool:
        """Bind a socket to a virtual interface"""
        with self._lock:
            if ip_address not in self.interfaces:
                logger.error(f"Cannot bind to unknown interface: {ip_address}")
                return False
            
            self.socket_map[sock] = ip_address
            logger.debug(f"Bound socket {sock.fileno()} to interface {ip_address}")
            return True
    
    def _packet_worker(self):
        """Worker thread that processes queued packets with appropriate delays"""
        while self.active:
            try:
                # Get next packet from queue
                item = self.packet_queue.get(timeout=0.1)
                if item is None:  # Poison pill
                    break
                    
                sock, data, addr, interface_ip, callback = item
                interface = self.interfaces.get(interface_ip)
                
                if not interface:
                    logger.error(f"Interface {interface_ip} not found for packet delivery")
                    if callback:
                        callback(False)
                    continue
                
                # Simulate sending the packet
                success, delay = interface.send_packet(data, addr)
                
                if success:
                    # Wait for the calculated delay
                    if delay > 0:
                        time.sleep(delay)
                    
                    # Actually send the data
                    try:
                        if sock.fileno() != -1:  # Check if socket is still valid
                            sock.sendto(data, addr)
                    except (socket.error, OSError) as e:
                        logger.error(f"Error sending data: {e}")
                        success = False
                
                # Notify the callback
                if callback:
                    callback(success)
                
                self.packet_queue.task_done()
                
            except queue.Empty:
                continue
            except Exception as e:
                logger.error(f"Error in packet worker: {e}")
    
    def start(self):
        """Start the network simulator"""
        with self._lock:
            if self.active:
                return
            
            self.active = True
            self._worker_thread = threading.Thread(target=self._packet_worker, daemon=True)
            self._worker_thread.start()
            logger.info("Network simulator started")
    
    def stop(self):
        """Stop the network simulator"""
        with self._lock:
            if not self.active:
                return
            
            self.active = False
            self.packet_queue.put(None)  # Add poison pill
            
            if self._worker_thread:
                self._worker_thread.join(timeout=5)
                self._worker_thread = None
            
            logger.info("Network simulator stopped")
    
    def send_through_interface(self, sock: socket.socket, data: bytes, 
                               addr: Tuple[str, int], callback: Callable = None):
        """
        Send data through a specific interface with simulated network conditions
        
        Args:
            sock: The socket to send data through
            data: The data to send
            addr: The destination address (host, port)
            callback: Optional callback function(success) to call when done
        """
        if not self.active:
            logger.warning("Attempting to send through inactive simulator")
            return
        
        with self._lock:
            interface_ip = self.socket_map.get(sock)
            if not interface_ip:
                logger.error(f"No interface bound to socket {sock.fileno()}")
                if callback:
                    callback(False)
                return
        
        # Queue the packet for sending
        self.packet_queue.put((sock, data, addr, interface_ip, callback))
    
    def get_interface_stats(self) -> List[Dict]:
        """Get statistics for all interfaces"""
        with self._lock:
            return [interface.get_stats() for interface in self.interfaces.values()]


# Global instance for easy access
network_sim = NetworkSimulator()

def create_simulated_network(config=None):
    """
    Create a simulated network with multiple interfaces based on config
    
    Args:
        config: List of interface configurations or None for default config
    
    Returns:
        The NetworkSimulator instance
    """
    # Default configuration if none is provided
    if config is None:
        config = [
            {
                "ip": "192.168.100.10", 
                "bandwidth_kbps": 5000,  # 5 Mbps
                "latency_ms": 20,
                "packet_loss_percent": 0.5,
                "name": "fast-connection"
            },
            {
                "ip": "192.168.100.11",
                "bandwidth_kbps": 1000,  # 1 Mbps
                "latency_ms": 50,
                "packet_loss_percent": 1.0,
                "name": "medium-connection"
            },
            {
                "ip": "192.168.100.12",
                "bandwidth_kbps": 500,   # 500 Kbps
                "latency_ms": 100,
                "packet_loss_percent": 2.0,
                "name": "slow-connection" 
            }
        ]
    
    # Create the interfaces
    for interface_config in config:
        network_sim.create_interface(
            ip_address=interface_config["ip"],
            bandwidth_kbps=interface_config.get("bandwidth_kbps", 1000),
            latency_ms=interface_config.get("latency_ms", 20),
            packet_loss_percent=interface_config.get("packet_loss_percent", 0),
            jitter_ms=interface_config.get("jitter_ms", 0),
            name=interface_config.get("name")
        )
    
    # Start the simulator
    network_sim.start()
    
    return network_sim

def cleanup_simulated_network():
    """Stop and clean up the network simulator"""
    global network_sim
    if network_sim:
        network_sim.stop()
        network_sim = NetworkSimulator()

# Example usage:
# sim = create_simulated_network()
# interface_ips = [interface.ip_address for interface in sim.interfaces.values()]
# print(f"Created virtual interfaces with IPs: {interface_ips}") 