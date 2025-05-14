#!/usr/bin/env python3
"""
Test script to verify load balancing across multiple interfaces.
"""

import unittest
import requests
import socket
import sys
import time
import json
from collections import Counter
from tests.test_utils import SimulatedNetworkTestCase, RealNetworkTestCase

class TestMultiRequest(SimulatedNetworkTestCase):
    """
    Test case for verifying load balancing across multiple interfaces
    using a simulated network environment.
    """
    
    def test_multiple_requests(self):
        """Test the SOCKS proxy by making multiple requests through it."""
        num_requests = 20
        
        # Run the standardized test
        results = self.run_proxy_test(request_count=num_requests)
        
        # Verify the results
        self.assertEqual(results["status"], "success")
        self.assertEqual(results["total_requests"], num_requests)
        
        # There should be more than one interface used
        self.assertGreater(len(results["distribution"]), 1)
        
        # Print the results for debugging
        print("\nResults:")
        print(f"  Total requests: {results['total_requests']}")
        print("\nIP distribution:")
        
        for ip, data in results["distribution"].items():
            print(f"  {ip}: {data['count']} requests ({data['percentage']:.1f}%)")

class TestRealNetworkMultiRequest(RealNetworkTestCase):
    """
    Test case for verifying load balancing across multiple real interfaces
    if they are available.
    """
    
    def setUp(self):
        """Set up the test - detect available network interfaces"""
        super().setUp()
        # Get available interface IPs - this would be implementation-specific
        # For now, we'll just use some sample IPs for demonstration
        try:
            import netifaces
            self.interface_ips = []
            
            for iface in netifaces.interfaces():
                addrs = netifaces.ifaddresses(iface)
                if netifaces.AF_INET in addrs:
                    for addr in addrs[netifaces.AF_INET]:
                        if 'addr' in addr and not addr['addr'].startswith('127.'):
                            self.interface_ips.append(addr['addr'])
            
            # If we have at least two interfaces, start the proxy
            if len(self.interface_ips) >= 2:
                self.start_proxy(self.interface_ips[:2])
            else:
                self.skipTest("Not enough real network interfaces available for this test")
        except ImportError:
            self.skipTest("netifaces module not available")
    
    def test_multiple_requests(self):
        """Test the proxy by making multiple requests through real interfaces."""
        if not hasattr(self, 'interface_ips') or len(self.interface_ips) < 2:
            self.skipTest("Not enough real network interfaces available")
            
        num_requests = 10
        
        # Run the standardized test
        results = self.run_proxy_test(request_count=num_requests)
        
        # Verify the results
        self.assertEqual(results["status"], "success")
        self.assertTrue(results["total_requests"] > 0)
        
        # Print the results for debugging
        print("\nResults with real interfaces:")
        print(f"  Total requests: {results['total_requests']}")
        print("\nIP distribution:")
        
        for ip, data in results["distribution"].items():
            print(f"  {ip}: {data['count']} requests ({data['percentage']:.1f}%)")

def legacy_test_multiple_requests(num_requests=20):
    """
    Original implementation - kept for reference and backward compatibility.
    Will be deprecated in future versions.
    """
    print("WARNING: This function is deprecated. Use the TestMultiRequest class instead.")
    proxy_url = "socks5://127.0.0.1:1080"
    
    # Configure the proxy
    proxies = {
        'http': proxy_url,
        'https': proxy_url
    }
    
    print(f"Testing proxy at {proxy_url}")
    print(f"Making {num_requests} requests to http://httpbin.org/ip...")
    
    ip_counter = Counter()
    success_count = 0
    failure_count = 0
    
    for i in range(num_requests):
        print(f"Request {i+1}/{num_requests}...")
        try:
            # Try to make a request through the proxy
            response = requests.get("http://httpbin.org/ip", proxies=proxies, timeout=10)
            
            # Check if successful
            if response.status_code == 200:
                success_count += 1
                
                # Parse the response to get the IP
                data = response.json()
                ip = data.get('origin', 'unknown')
                ip_counter[ip] += 1
                
                print(f"  Success - IP: {ip}")
            else:
                failure_count += 1
                print(f"  Failed with status code: {response.status_code}")
                
            # Add a small delay to space out requests
            time.sleep(0.5)
            
        except Exception as e:
            failure_count += 1
            print(f"  Error: {e}")
    
    # Print the results
    print("\nResults:")
    print(f"  Total requests: {num_requests}")
    print(f"  Successful: {success_count}")
    print(f"  Failed: {failure_count}")
    print("\nIP distribution:")
    
    for ip, count in ip_counter.items():
        percentage = (count / success_count) * 100 if success_count > 0 else 0
        print(f"  {ip}: {count} requests ({percentage:.1f}%)")
    
    # Return success if all requests were successful
    return failure_count == 0

if __name__ == "__main__":
    # If run directly, use unittest runner
    unittest.main()
    
    # Legacy mode if arguments are provided
    if len(sys.argv) > 1 and sys.argv[1].isdigit():
        try:
            num_requests = int(sys.argv[1])
            success = legacy_test_multiple_requests(num_requests)
            sys.exit(0 if success else 1)
        except ValueError:
            print(f"Invalid number of requests: {sys.argv[1]}")
            sys.exit(1) 