#!/usr/bin/env python3
"""
Basic tests for the network simulator core functionality.
This tests the simulator components directly without requiring external connections.
"""

import unittest
import time
import socket
import threading
import os
import sys
import logging
from unittest import mock

from tests.network_simulator import (
    VirtualInterface,
    NetworkSimulator,
    create_simulated_network,
    cleanup_simulated_network
)
from tests.socket_patcher import NetworkPatcher, install_socket_patch, remove_socket_patch

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


class TestVirtualInterface(unittest.TestCase):
    """Test cases for the VirtualInterface class"""
    
    def test_interface_creation(self):
        """Test that interfaces can be created with various parameters"""
        interface = VirtualInterface(
            ip_address="192.168.200.1",
            bandwidth_kbps=2000,
            latency_ms=30,
            packet_loss_percent=5.0,
            jitter_ms=5,
            name="test-interface"
        )
        
        self.assertEqual(interface.ip_address, "192.168.200.1")
        self.assertEqual(interface.bandwidth_kbps, 2000)
        self.assertEqual(interface.latency_ms, 30)
        self.assertEqual(interface.packet_loss_percent, 5.0)
        self.assertEqual(interface.jitter_ms, 5)
        self.assertEqual(interface.name, "test-interface")
        self.assertTrue(interface.up)  # Interface should be up by default
    
    def test_interface_state(self):
        """Test changing interface state"""
        interface = VirtualInterface(ip_address="192.168.200.2")
        
        # Interface should be up by default
        self.assertTrue(interface.up)
        
        # Set interface down
        interface.set_up(False)
        self.assertFalse(interface.up)
        
        # Set interface back up
        interface.set_up(True)
        self.assertTrue(interface.up)
    
    def test_interface_packet_simulation(self):
        """Test packet simulation through the interface"""
        # Create a high bandwidth, low latency, no packet loss interface
        fast_interface = VirtualInterface(
            ip_address="192.168.200.3",
            bandwidth_kbps=100000,  # 100 Mbps
            latency_ms=1,           # 1ms latency
            packet_loss_percent=0.0  # No packet loss
        )
        
        # Create test data (1KB)
        test_data = b'x' * 1000
        dest = ('8.8.8.8', 53)  # Dummy destination
        
        # Send a packet and measure
        success, delay = fast_interface.send_packet(test_data, dest)
        
        # Packet should be sent successfully
        self.assertTrue(success)
        
        # Delay should be very small (latency + bandwidth delay)
        # 1ms latency + bandwidth delay for 1KB at 100Mbps should be ~0.001s
        self.assertGreater(delay, 0.001)  # At least latency
        self.assertLess(delay, 0.01)  # But not too much
        
        # Create a slow, lossy interface
        slow_interface = VirtualInterface(
            ip_address="192.168.200.4",
            bandwidth_kbps=100,      # 100 Kbps
            latency_ms=200,          # 200ms latency
            packet_loss_percent=100.0  # 100% packet loss for deterministic testing
        )
        
        # Send a packet 
        success, delay = slow_interface.send_packet(test_data, dest)
        
        # With 100% packet loss, the packet should be dropped
        self.assertFalse(success)
        
        # Set the interface down and try again
        fast_interface.set_up(False)
        success, delay = fast_interface.send_packet(test_data, dest)
        
        # Should fail when interface is down
        self.assertFalse(success)


class TestNetworkSimulator(unittest.TestCase):
    """Test cases for the NetworkSimulator class"""
    
    def setUp(self):
        # Clean up any previous simulators
        cleanup_simulated_network()
    
    def tearDown(self):
        # Clean up
        cleanup_simulated_network()
    
    def test_simulator_creation(self):
        """Test creating a simulator with interfaces"""
        simulator = create_simulated_network([
            {
                "ip": "192.168.200.10",
                "bandwidth_kbps": 1000,
                "name": "interface-1"
            },
            {
                "ip": "192.168.200.11",
                "bandwidth_kbps": 2000,
                "name": "interface-2"
            }
        ])
        
        # Check that the simulator has the correct interfaces
        self.assertEqual(len(simulator.interfaces), 2)
        self.assertIn("192.168.200.10", simulator.interfaces)
        self.assertIn("192.168.200.11", simulator.interfaces)
        
        # Check interface properties
        self.assertEqual(simulator.interfaces["192.168.200.10"].bandwidth_kbps, 1000)
        self.assertEqual(simulator.interfaces["192.168.200.11"].bandwidth_kbps, 2000)
        
        # Check that simulator is active
        self.assertTrue(simulator.active)
    
    def test_simulator_operations(self):
        """Test simulator operations like adding/removing interfaces"""
        simulator = create_simulated_network()
        
        # Add a new interface
        interface = simulator.create_interface(
            ip_address="192.168.200.20",
            bandwidth_kbps=3000,
            name="test-operations"
        )
        
        # Check that it was added
        self.assertIn("192.168.200.20", simulator.interfaces)
        self.assertEqual(interface.bandwidth_kbps, 3000)
        
        # Get statistics
        stats = simulator.get_interface_stats()
        self.assertGreaterEqual(len(stats), 1)  # At least our added interface
        
        # Find our interface in stats
        found = False
        for stat in stats:
            if stat['name'] == "test-operations":
                found = True
                self.assertEqual(stat['ip'], "192.168.200.20")
                self.assertEqual(stat['bandwidth_kbps'], 3000)
        self.assertTrue(found, "Could not find our interface in stats")
        
        # Remove an interface
        simulator.remove_interface("192.168.200.20")
        self.assertNotIn("192.168.200.20", simulator.interfaces)
    
    def test_socket_binding(self):
        """Test binding sockets to interfaces"""
        simulator = create_simulated_network([
            {"ip": "192.168.200.30", "name": "bind-test"}
        ])
        
        # Create a socket
        test_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        
        # Bind it to our interface
        result = simulator.bind_socket(test_socket, "192.168.200.30")
        self.assertTrue(result)
        self.assertIn(test_socket, simulator.socket_map)
        self.assertEqual(simulator.socket_map[test_socket], "192.168.200.30")
        
        # Try binding to a non-existent interface
        result = simulator.bind_socket(test_socket, "192.168.200.99")
        self.assertFalse(result)
        
        # Clean up
        test_socket.close()


class TestSocketPatcher(unittest.TestCase):
    """Test cases for the socket patching mechanism"""
    
    def setUp(self):
        # Clean up
        remove_socket_patch()
        cleanup_simulated_network()
    
    def tearDown(self):
        # Clean up
        remove_socket_patch()
        cleanup_simulated_network()
    
    def test_socket_patching(self):
        """Test that socket patching works"""
        # Store original socket
        original_socket = socket.socket
        
        # Install socket patch
        result = install_socket_patch()
        self.assertTrue(result)
        
        # Check that socket class has been patched
        from tests.socket_patcher import PatchedSocket
        self.assertEqual(socket.socket, PatchedSocket)
        
        # Remove patch
        result = remove_socket_patch()
        self.assertTrue(result)
        
        # Check that original has been restored
        self.assertEqual(socket.socket, original_socket)
    
    def test_network_patcher_context(self):
        """Test the NetworkPatcher context manager"""
        from tests.socket_patcher import PatchedSocket, _orig_gethostbyname
        
        # Before patching, socket.socket should be the original
        original_socket = socket.socket
        
        # Create a network simulator with a test interface
        interface_config = {"ip": "192.168.200.40", "name": "context-test"}
        
        # Use the context manager
        with NetworkPatcher(interface_configs=[interface_config]) as patcher:
            # Inside the context, socket.socket should be patched
            self.assertNotEqual(socket.socket, original_socket)
            self.assertEqual(socket.socket, PatchedSocket)
            
            # Make sure gethostbyname is patched
            self.assertNotEqual(socket.gethostbyname, _orig_gethostbyname)
            
        # After the context, socket.socket should be restored
        self.assertEqual(socket.socket, original_socket)


class TestEndToEnd(unittest.TestCase):
    """End-to-end tests for the network simulation"""
    
    def test_udp_sendto(self):
        """Test sending UDP packets through simulated interfaces"""
        with NetworkPatcher(interface_configs=[
            {
                "ip": "192.168.200.50",
                "bandwidth_kbps": 1000,
                "latency_ms": 50,
                "name": "udp-test"
            }
        ]) as patcher:
            # Create a UDP socket
            udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            
            # Bind to localhost but associated with our virtual interface
            udp_socket.bind(('127.0.0.1', 0))
            
            # Manually bind to our virtual interface
            from tests.network_simulator import network_sim
            network_sim.bind_socket(udp_socket, "192.168.200.50")
            
            # Get the bound port
            _, port = udp_socket.getsockname()
            
            # Create a simple UDP echo server in a thread
            echo_received = threading.Event()
            received_data = [None]
            
            def echo_server():
                server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                server.bind(('127.0.0.1', 12345))
                server.settimeout(5)
                
                try:
                    data, addr = server.recvfrom(1024)
                    received_data[0] = data
                    echo_received.set()
                    server.sendto(data, addr)
                except socket.timeout:
                    pass
                finally:
                    server.close()
            
            # Start the echo server
            server_thread = threading.Thread(target=echo_server)
            server_thread.daemon = True
            server_thread.start()
            
            # Wait for server to start
            time.sleep(0.5)
            
            # Send data to the echo server
            test_message = b"Hello, simulated network!"
            udp_socket.sendto(test_message, ('127.0.0.1', 12345))
            
            # Wait for the echo server to receive the data (with delay)
            self.assertTrue(echo_received.wait(timeout=2))
            self.assertEqual(received_data[0], test_message)
            
            # Clean up
            udp_socket.close()
            server_thread.join(timeout=1)


if __name__ == '__main__':
    unittest.main() 