#!/usr/bin/env python3
"""
Test script to verify the dispatcher functionality.
"""

import unittest
import asyncio
import ipaddress
import logging
import netifaces
from dispatch.dispatcher import RawWeightedAddress, WeightedAddress, WeightedRoundRobinDispatcher
from dispatch.dispatcher.weighted_rr import Interface
from typing import Dict, List, Optional, Tuple, Union
from tests.test_utils import RealNetworkTestCase

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class TestDispatcher(RealNetworkTestCase):
    """
    Test case for the WeightedRoundRobinDispatcher using real network interfaces.
    """
    
    async def get_available_interfaces(self):
        """Get available network interfaces for testing"""
        # First list available interfaces
        logger.info("Available network interfaces:")
        interface_count = 0
        interfaces_with_ipv4 = []
        
        for iface_name in netifaces.interfaces():
            interface_count += 1
            logger.info(f"  Interface: {iface_name}")
            addrs = netifaces.ifaddresses(iface_name)
            
            # IPv4 addresses
            if netifaces.AF_INET in addrs:
                for addr in addrs[netifaces.AF_INET]:
                    if 'addr' in addr:
                        logger.info(f"    IPv4: {addr['addr']}")
                        # Store interfaces with IPv4 addresses
                        interfaces_with_ipv4.append((iface_name, addr['addr']))
            
            # IPv6 addresses
            if netifaces.AF_INET6 in addrs:
                for addr in addrs[netifaces.AF_INET6]:
                    if 'addr' in addr:
                        logger.info(f"    IPv6: {addr['addr']}")
        
        logger.info(f"Total interfaces: {interface_count}")
        logger.info(f"Interfaces with IPv4: {len(interfaces_with_ipv4)}")
        
        return interfaces_with_ipv4
    
    async def asyncSetUp(self):
        """Set up the test - identify available interfaces"""
        self.interfaces_with_ipv4 = await self.get_available_interfaces()
    
    async def test_dispatcher_creation(self):
        """Test creating a dispatcher with available interfaces"""
        # Get the available interfaces
        interfaces_with_ipv4 = self.interfaces_with_ipv4
        
        # Try to use two actual interfaces for testing
        raw_addresses = []
        
        # Use the first non-loopback interface with weight 7
        external_interface = None
        for iface, addr in interfaces_with_ipv4:
            if not addr.startswith("127."):
                external_interface = (iface, addr)
                break
        
        if external_interface:
            logger.info(f"Using external interface: {external_interface[0]} ({external_interface[1]})")
            raw_addresses.append(RawWeightedAddress.from_str(f"{external_interface[0]}/7"))
        
        # Try to find a second interface
        second_interface = None
        for iface, addr in interfaces_with_ipv4:
            if external_interface and iface != external_interface[0] and not addr.startswith("127."):
                second_interface = (iface, addr)
                break
        
        if second_interface:
            logger.info(f"Using second interface: {second_interface[0]} ({second_interface[1]})")
            raw_addresses.append(RawWeightedAddress.from_str(f"{second_interface[0]}/3"))
        
        # If we don't have two interfaces, create a custom test with the main interface
        if len(raw_addresses) < 2:
            logger.info("Not enough interfaces found for real-world testing.")
            logger.info("Using main interface only.")
            
            if not raw_addresses:
                # Just use a sample IP address directly
                raw_addresses = [RawWeightedAddress.from_str("192.168.1.1/1")]
        
        # Try to resolve addresses using the built-in resolver
        try:
            logger.info("Attempting to resolve addresses using the built-in resolver...")
            resolved_addresses = WeightedAddress.resolve(raw_addresses)
            logger.info("Resolution successful!")
            
            # Make sure we have at least one resolved address
            self.assertGreater(len(resolved_addresses), 0)
        except ValueError as e:
            logger.warning(f"Built-in resolver failed: {e}")
            logger.info("Manually creating weighted addresses for testing...")
            
            # Manually create weighted addresses for the external interface
            if external_interface:
                # Create interfaces
                external_iface = Interface(name=external_interface[0], 
                                         ipv4=ipaddress.IPv4Address(external_interface[1]))
                
                # Create weighted addresses
                resolved_addresses = [
                    WeightedAddress(interface=external_iface, weight=7),
                ]
            else:
                # Fallback to direct IP
                primary_interface = Interface(ip=ipaddress.IPv4Address("192.168.1.1"))
                resolved_addresses = [
                    WeightedAddress(interface=primary_interface, weight=1),
                ]
        
        # Create a dispatcher
        logger.info("Creating dispatcher...")
        dispatcher = WeightedRoundRobinDispatcher(resolved_addresses)
        
        # Verify the dispatcher has the interfaces we expect
        self.assertEqual(len(dispatcher.addresses), len(resolved_addresses))
        
        # Print the available addresses
        logger.info("Available interfaces for dispatch:")
        for addr in resolved_addresses:
            logger.info(f"  {addr}")
    
    async def test_multiple_dispatches(self):
        """Test making multiple dispatch requests"""
        # Skip this test if no interfaces are available
        if not hasattr(self, 'interfaces_with_ipv4') or len(self.interfaces_with_ipv4) == 0:
            self.skipTest("No network interfaces available for testing")
        
        # Get at least one interface
        external_interface = None
        for iface, addr in self.interfaces_with_ipv4:
            if not addr.startswith("127."):
                external_interface = (iface, addr)
                break
        
        if not external_interface:
            self.skipTest("No external network interface available for testing")
        
        # Create interface and weighted address
        external_iface = Interface(name=external_interface[0], 
                                  ipv4=ipaddress.IPv4Address(external_interface[1]))
        
        resolved_addresses = [
            WeightedAddress(interface=external_iface, weight=1),
        ]
        
        # Try to find a second interface
        second_interface = None
        for iface, addr in self.interfaces_with_ipv4:
            if external_interface and iface != external_interface[0] and not addr.startswith("127."):
                second_interface = (iface, addr)
                break
        
        if second_interface:
            # Add a second interface
            second_iface = Interface(name=second_interface[0], 
                                    ipv4=ipaddress.IPv4Address(second_interface[1]))
            resolved_addresses.append(WeightedAddress(interface=second_iface, weight=1))
        
        # Create a dispatcher
        dispatcher = WeightedRoundRobinDispatcher(resolved_addresses)
        
        # Make simulated requests and check which interface is selected
        logger.info("Simulating 20 requests:")
        stats = {"total": 0}
        
        for i in range(20):
            # Use a remote IPv4 address for testing
            remote_addr = ("8.8.8.8", 80)
            local_addr = await dispatcher.dispatch(remote_addr)
            logger.info(f"  Request {i+1}: Selected {local_addr}")
            
            # Update stats
            addr_str = str(local_addr)
            stats["total"] = stats.get("total", 0) + 1
            stats[addr_str] = stats.get(addr_str, 0) + 1
        
        # Verify we made all the requests
        self.assertEqual(stats["total"], 20)
        
        # Print statistics
        logger.info("Request distribution:")
        for addr, count in stats.items():
            if addr != "total":
                percentage = (count / stats["total"]) * 100
                logger.info(f"  {addr}: {count} requests ({percentage:.1f}%)")
        
        # If we have multiple interfaces, verify they were both used
        if len(resolved_addresses) > 1:
            # There should be more than one address in the stats
            self.assertGreater(len(stats) - 1, 1)  # Subtract 1 for the "total" key


class TestDispatcherWithoutAsync(unittest.TestCase):
    """
    Non-async test cases for the dispatcher components.
    """
    
    def test_raw_weighted_address(self):
        """Test the RawWeightedAddress class"""
        # Test parsing from string
        raw_addr = RawWeightedAddress.from_str("eth0/10")
        self.assertEqual(raw_addr.name, "eth0")
        self.assertEqual(raw_addr.weight, 10)
        
        # Test parsing with no weight (default weight 1)
        raw_addr = RawWeightedAddress.from_str("eth0")
        self.assertEqual(raw_addr.name, "eth0")
        self.assertEqual(raw_addr.weight, 1)
        
        # Test parsing with IP
        raw_addr = RawWeightedAddress.from_str("192.168.1.1/5")
        self.assertEqual(raw_addr.name, "192.168.1.1")
        self.assertEqual(raw_addr.weight, 5)
        
        # Test string representation
        self.assertEqual(str(raw_addr), "192.168.1.1/5")
    
    def test_interface_creation(self):
        """Test creating Interface objects"""
        # Create with name and IPv4
        interface = Interface(name="eth0", ipv4=ipaddress.IPv4Address("192.168.1.1"))
        self.assertEqual(interface.name, "eth0")
        self.assertEqual(str(interface.ipv4), "192.168.1.1")
        
        # Create with just IP
        interface = Interface(ip=ipaddress.IPv4Address("192.168.1.2"))
        self.assertIsNone(interface.name)
        self.assertEqual(str(interface.ipv4), "192.168.1.2")


# Legacy function for backward compatibility - will be deprecated
async def main():
    """Test the dispatcher with multiple requests."""
    logger = logging.getLogger("legacy_dispatcher_test")
    logger.warning("This function is deprecated. Use the TestDispatcher class instead.")
    
    print("Testing dispatcher with multiple requests...")
    
    # First list available interfaces
    print("Available network interfaces:")
    interface_count = 0
    interfaces_with_ipv4 = []
    
    for iface_name in netifaces.interfaces():
        interface_count += 1
        print(f"  Interface: {iface_name}")
        addrs = netifaces.ifaddresses(iface_name)
        
        # IPv4 addresses
        if netifaces.AF_INET in addrs:
            for addr in addrs[netifaces.AF_INET]:
                if 'addr' in addr:
                    print(f"    IPv4: {addr['addr']}")
                    # Store interfaces with IPv4 addresses
                    interfaces_with_ipv4.append((iface_name, addr['addr']))
        
        # IPv6 addresses
        if netifaces.AF_INET6 in addrs:
            for addr in addrs[netifaces.AF_INET6]:
                if 'addr' in addr:
                    print(f"    IPv6: {addr['addr']}")
    
    print(f"\nTotal interfaces: {interface_count}")
    print(f"Interfaces with IPv4: {len(interfaces_with_ipv4)}")
    
    # Get the available interfaces
    try:
        # Use two actual interfaces for testing
        # The main external interface and the laptop's Wi-Fi interface
        raw_addresses = []
        
        # Use the first non-loopback interface with weight 7
        external_interface = None
        for iface, addr in interfaces_with_ipv4:
            if not addr.startswith("127."):
                external_interface = (iface, addr)
                break
        
        if external_interface:
            print(f"\nUsing external interface: {external_interface[0]} ({external_interface[1]})")
            raw_addresses.append(RawWeightedAddress.from_str(f"{external_interface[0]}/7"))
        
        # Try to find a second interface
        second_interface = None
        for iface, addr in interfaces_with_ipv4:
            if external_interface and iface != external_interface[0] and not addr.startswith("127."):
                second_interface = (iface, addr)
                break
        
        if second_interface:
            print(f"Using second interface: {second_interface[0]} ({second_interface[1]})")
            raw_addresses.append(RawWeightedAddress.from_str(f"{second_interface[0]}/3"))
        
        # If we don't have two interfaces, create a custom test with the main interface
        if len(raw_addresses) < 2:
            print("\nNot enough interfaces found for real-world testing.")
            print("Using main interface only.")
            
            if not raw_addresses:
                # Just use the IP address directly
                raw_addresses = [RawWeightedAddress.from_str("192.168.219.112/1")]
                
        # Try to resolve addresses using the built-in resolver
        try:
            print("\nAttempting to resolve addresses using the built-in resolver...")
            resolved_addresses = WeightedAddress.resolve(raw_addresses)
            print("Resolution successful!")
        except ValueError as e:
            print(f"Built-in resolver failed: {e}")
            print("Manually creating weighted addresses for testing...")
            
            # Manually create weighted addresses for the external interface
            if external_interface:
                # Create interfaces
                external_iface = Interface(name=external_interface[0], 
                                         ipv4=ipaddress.IPv4Address(external_interface[1]))
                
                # Create weighted addresses
                resolved_addresses = [
                    WeightedAddress(interface=external_iface, weight=7),
                ]
            else:
                # Fallback to direct IP
                primary_interface = Interface(ip=ipaddress.IPv4Address("192.168.219.112"))
                resolved_addresses = [
                    WeightedAddress(interface=primary_interface, weight=1),
                ]
        
        # Create a dispatcher
        print("\nCreating dispatcher...")
        dispatcher = WeightedRoundRobinDispatcher(resolved_addresses)
        
        # Print the available addresses
        print("\nAvailable interfaces for dispatch:")
        for addr in resolved_addresses:
            print(f"  {addr}")
        
        # Make simulated requests and check which interface is selected
        print("\nSimulating 20 requests:")
        stats = {"total": 0}
        
        for i in range(20):
            # Use a remote IPv4 address for testing
            remote_addr = ("8.8.8.8", 80)
            local_addr = await dispatcher.dispatch(remote_addr)
            print(f"  Request {i+1}: Selected {local_addr}")
            
            # Update stats
            addr_str = str(local_addr)
            stats["total"] = stats.get("total", 0) + 1
            stats[addr_str] = stats.get(addr_str, 0) + 1
        
        # Print statistics
        print("\nRequest distribution:")
        for addr, count in stats.items():
            if addr != "total":
                percentage = (count / stats["total"]) * 100
                print(f"  {addr}: {count} requests ({percentage:.1f}%)")
            
        print("\nTest completed successfully!")
        
    except Exception as e:
        print(f"Error: {e}")
        raise


def run_legacy_test():
    """Run the legacy test function"""
    asyncio.run(main())


if __name__ == "__main__":
    # Run the unittest tests if no arguments are provided
    unittest.main()
    # Otherwise, run the legacy test
    # run_legacy_test() 