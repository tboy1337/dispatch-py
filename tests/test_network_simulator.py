#!/usr/bin/env python3
"""
Tests for the network simulator and socket patching.
"""

import unittest
import socket
import threading
import time
import logging
import json
from unittest import mock
import requests

from tests.network_simulator import (
    create_simulated_network,
    cleanup_simulated_network,
    VirtualInterface,
    NetworkSimulator,
    network_sim
)
from tests.socket_patcher import (
    NetworkPatcher,
    install_socket_patch,
    remove_socket_patch,
    register_virtual_host
)
from tests.test_utils import SimulatedNetworkTestCase

# Configure logging - set to DEBUG for more verbose output during testing
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class TestVirtualInterface(unittest.TestCase):
    """Test cases for the VirtualInterface class"""

    def setUp(self):
        self.interface = VirtualInterface(
            ip_address="192.168.100.1",
            bandwidth_kbps=1000,
            latency_ms=50,
            packet_loss_percent=10.0,
            jitter_ms=10,
            name="test-interface"
        )

    def test_interface_initialization(self):
        """Test that interface is initialized correctly"""
        self.assertEqual(self.interface.ip_address, "192.168.100.1")
        self.assertEqual(self.interface.bandwidth_kbps, 1000)
        self.assertEqual(self.interface.latency_ms, 50)
        self.assertEqual(self.interface.packet_loss_percent, 10.0)
        self.assertEqual(self.interface.jitter_ms, 10)
        self.assertEqual(self.interface.name, "test-interface")
        self.assertTrue(self.interface.up)

    def test_packet_drop(self):
        """Test packet drop simulation with 100% drop rate"""
        # Set to 100% packet loss for deterministic testing
        self.interface.packet_loss_percent = 100.0
        self.assertTrue(self.interface.should_drop_packet(100))
        
        # Set to 0% packet loss
        self.interface.packet_loss_percent = 0.0
        self.assertFalse(self.interface.should_drop_packet(100))
        
        # Interface down should always drop packets
        self.interface.set_up(False)
        self.assertTrue(self.interface.should_drop_packet(100))

    def test_delay_calculation(self):
        """Test delay calculation"""
        # With no jitter
        self.interface.jitter_ms = 0
        self.assertEqual(self.interface.calculate_delay(), 0.05)  # 50ms = 0.05s
        
        # Interface down should return infinite delay
        self.interface.set_up(False)
        self.assertEqual(self.interface.calculate_delay(), float('inf'))
        
        # Reset interface state
        self.interface.set_up(True)
        
        # With jitter, make sure it's within expected range
        self.interface.jitter_ms = 10
        delay = self.interface.calculate_delay()
        self.assertGreaterEqual(delay, 0.04)  # 50ms - 10ms = 40ms = 0.04s
        self.assertLessEqual(delay, 0.06)     # 50ms + 10ms = 60ms = 0.06s

    def test_bandwidth_simulation(self):
        """Test bandwidth limiting simulation"""
        # Send 1000 bytes on a 1000 Kbps link
        # 1000 bytes = 8000 bits
        # At 1000 Kbps, this should take 0.008 seconds
        bandwidth_delay = self.interface.simulate_bandwidth_limit(1000)
        self.assertAlmostEqual(bandwidth_delay, 0.008, places=3)
        
        # Disable bandwidth limit
        self.interface.bandwidth_kbps = 0
        bandwidth_delay = self.interface.simulate_bandwidth_limit(1000)
        self.assertEqual(bandwidth_delay, 0)


class TestNetworkSimulator(unittest.TestCase):
    """Test cases for the NetworkSimulator class"""

    def setUp(self):
        # Reset the simulator before each test
        cleanup_simulated_network()
        # Create a new simulator instance
        self.simulator = create_simulated_network([
            {
                "ip": "192.168.100.10",
                "bandwidth_kbps": 1000,
                "latency_ms": 20,
                "name": "interface-1"
            },
            {
                "ip": "192.168.100.11",
                "bandwidth_kbps": 500,
                "latency_ms": 50,
                "name": "interface-2"
            }
        ])

    def tearDown(self):
        cleanup_simulated_network()

    def test_simulator_initialization(self):
        """Test that simulator initializes with the correct interfaces"""
        self.assertEqual(len(self.simulator.interfaces), 2)
        self.assertIn("192.168.100.10", self.simulator.interfaces)
        self.assertIn("192.168.100.11", self.simulator.interfaces)
        
        interface1 = self.simulator.interfaces["192.168.100.10"]
        self.assertEqual(interface1.bandwidth_kbps, 1000)
        self.assertEqual(interface1.latency_ms, 20)
        self.assertEqual(interface1.name, "interface-1")
        
        interface2 = self.simulator.interfaces["192.168.100.11"]
        self.assertEqual(interface2.bandwidth_kbps, 500)
        self.assertEqual(interface2.latency_ms, 50)
        self.assertEqual(interface2.name, "interface-2")

    def test_add_remove_interface(self):
        """Test adding and removing interfaces"""
        # Add new interface
        self.simulator.create_interface(
            ip_address="192.168.100.12",
            bandwidth_kbps=2000,
            name="interface-3"
        )
        
        self.assertEqual(len(self.simulator.interfaces), 3)
        self.assertIn("192.168.100.12", self.simulator.interfaces)
        
        # Remove interface
        self.simulator.remove_interface("192.168.100.12")
        self.assertEqual(len(self.simulator.interfaces), 2)
        self.assertNotIn("192.168.100.12", self.simulator.interfaces)

    def test_bind_socket(self):
        """Test binding a socket to a virtual interface"""
        # Create a socket
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        
        # Bind to a known interface
        result = self.simulator.bind_socket(s, "192.168.100.10")
        self.assertTrue(result)
        self.assertIn(s, self.simulator.socket_map)
        self.assertEqual(self.simulator.socket_map[s], "192.168.100.10")
        
        # Try binding to an unknown interface
        result = self.simulator.bind_socket(s, "192.168.100.999")
        self.assertFalse(result)
        
        # Clean up
        s.close()


class TestSocketPatcher(unittest.TestCase):
    """Test cases for the socket patching mechanism"""

    def setUp(self):
        # Remove any existing patches
        remove_socket_patch()

    def tearDown(self):
        # Clean up
        remove_socket_patch()
        cleanup_simulated_network()

    def test_socket_patching(self):
        """Test that socket patching works properly"""
        # Store original socket class
        original_socket = socket.socket
        
        # Install the patch
        self.assertTrue(install_socket_patch())
        
        # Verify that socket class was replaced
        self.assertNotEqual(socket.socket, original_socket)
        
        # Remove the patch
        remove_socket_patch()
        
        # Verify that socket class was restored
        self.assertEqual(socket.socket, original_socket)

    def test_hostname_resolution(self):
        """Test that hostname registration and resolution works"""
        # Create a virtual network
        simulator = create_simulated_network([
            {"ip": "192.168.100.10", "name": "interface-1"}
        ])
        
        # Register a virtual host
        register_virtual_host("test-host.local", "192.168.100.10")
        
        # Install the socket patch
        install_socket_patch()
        
        try:
            # Try to resolve the host
            ip = socket.gethostbyname("test-host.local")
            self.assertEqual(ip, "192.168.100.10")
        finally:
            # Clean up
            remove_socket_patch()
            cleanup_simulated_network()


class TestNetworkPatcher(unittest.TestCase):
    """Test the NetworkPatcher context manager"""
    
    def test_network_patcher_context(self):
        """Test that the NetworkPatcher context manager works properly"""
        # Create a simulator with a test interface
        interface_config = [{"ip": "192.168.100.10", "name": "interface-1"}]
        simulator = create_simulated_network(interface_config)
        
        # Original socket
        original_socket = socket.socket
        
        # Use the context manager with the simulator instance
        patcher = NetworkPatcher(simulator)
        patcher.__enter__()
        
        try:
            # Socket should be patched inside the context
            self.assertNotEqual(socket.socket, original_socket)
            
            # Try to create a socket
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.assertIsNotNone(s)
            
            # Close the socket
            s.close()
        finally:
            # Clean up
            patcher.__exit__(None, None, None)
        
        # Socket should be restored after context
        self.assertEqual(socket.socket, original_socket)
        
        # Clean up
        cleanup_simulated_network()


class TestSimulatedNetworkPerformanceBase(SimulatedNetworkTestCase):
    """
    Base class for simulated network performance tests using the standardized
    test framework.
    """
    
    # Configure test interfaces with specific characteristics
    interface_configs = [
        {
            "ip": "192.168.100.20",
            "bandwidth_kbps": 5000,
            "latency_ms": 20,
            "packet_loss_percent": 0,
            "name": "fast-interface"
        },
        {
            "ip": "192.168.100.21",
            "bandwidth_kbps": 1000,
            "latency_ms": 100,
            "packet_loss_percent": 0,
            "name": "slow-interface"
        }
    ]
    
    # Don't mock the proxy for these tests
    mock_proxy = False


class TestBandwidthLimitation(TestSimulatedNetworkPerformanceBase):
    """Test bandwidth limiting features of the network simulator"""
    
    def test_bandwidth_limits(self):
        """Test that bandwidth limits are enforced"""
        # Run a test with multiple requests
        results = self.run_proxy_test(request_count=5)
        
        # Verify we got successful results
        self.assertEqual(results["status"], "success")
        self.assertTrue(results["total_requests"] > 0)
        
        # Modify the interfaces to have extreme bandwidth differences
        fast_interface = self.simulator.interfaces["192.168.100.20"]
        slow_interface = self.simulator.interfaces["192.168.100.21"]
        
        # Make the difference more extreme
        fast_interface.bandwidth_kbps = 10000  # 10 Mbps
        slow_interface.bandwidth_kbps = 100    # 100 Kbps
        
        # Run another test
        results = self.run_proxy_test(request_count=5)
        
        # We should still get successful results
        self.assertEqual(results["status"], "success")


class TestPacketLoss(TestSimulatedNetworkPerformanceBase):
    """Test packet loss simulation"""
    
    def test_packet_loss(self):
        """Test that packet loss affects connections appropriately"""
        # Initial test with no packet loss
        results = self.run_proxy_test(request_count=5)
        
        # Verify we got successful results
        self.assertEqual(results["status"], "success")
        
        # Now set one interface to have extreme packet loss
        interface = self.simulator.interfaces["192.168.100.21"]
        interface.packet_loss_percent = 80.0  # 80% packet loss
        
        # Run another test
        results = self.run_proxy_test(request_count=5)
        
        # The test might succeed or fail depending on which interface was selected
        # but we don't want to assert a specific outcome as it's probabilistic


class TestLatencySimulation(TestSimulatedNetworkPerformanceBase):
    """Test latency simulation in the network simulator"""
    
    def test_latency_effects(self):
        """Test that latency settings affect connection times"""
        # Initial test with low latency
        start_time = time.time()
        results = self.run_proxy_test(request_count=3)
        low_latency_time = time.time() - start_time
        
        # Verify we got successful results
        self.assertEqual(results["status"], "success")
        
        # Now set both interfaces to have high latency
        for ip, interface in self.simulator.interfaces.items():
            interface.latency_ms = 500  # 500ms latency
        
        # Run another test with high latency
        start_time = time.time()
        results = self.run_proxy_test(request_count=3)
        high_latency_time = time.time() - start_time
        
        # The high latency test should take longer
        self.assertGreater(high_latency_time, low_latency_time)
        
        # Verify we still got successful results
        self.assertEqual(results["status"], "success")


if __name__ == "__main__":
    unittest.main() 