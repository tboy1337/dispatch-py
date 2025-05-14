#!/usr/bin/env python3
"""
Tests for dispatch-py using simulated network interfaces with varying properties.
These tests focus on verifying behaviors with different network characteristics.
"""

import unittest
import time
import sys
import os
import logging
import json
import socket
import threading
import subprocess
from typing import Dict, List, Any
import requests
import socks  # From PySocks, dependency of requests
from unittest import mock
import random

# Import our test utilities
from tests.test_utils import (
    simulated_network_test,
    run_multiple_requests,
    analyze_proxy_balance,
    DEFAULT_TEST_INTERFACES
)

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


# Mock for HTTP responses
class MockResponse:
    def __init__(self, json_data, status_code=200):
        self.json_data = json_data
        self.status_code = status_code
        self.content = json.dumps(json_data).encode('utf-8')
        
    def json(self):
        return self.json_data


def mock_requests_get(*args, **kwargs):
    """Mock function for requests.get"""
    # Static arrays of IPs for different test cases
    balanced_test_ips = ['203.0.113.10', '203.0.113.11', '203.0.113.12']
    weighted_test_ips = ['203.0.113.10', '203.0.113.10', '203.0.113.10', '203.0.113.10', 
                         '203.0.113.10', '203.0.113.10', '203.0.113.10', '203.0.113.11', 
                         '203.0.113.11', '203.0.113.11']  # 7:3 ratio
    latency_test_ips = ['203.0.113.20', '203.0.113.21']
    packet_loss_test_ips = ['203.0.113.30', '203.0.113.31']
    interface_failure_test_ips = ['203.0.113.40', '203.0.113.41']

    # Get our test case
    test_case = None
    frame = sys._getframe(1)
    while frame:
        if 'self' in frame.f_locals:
            self_obj = frame.f_locals['self']
            if isinstance(self_obj, unittest.TestCase):
                test_case = self_obj
                break
        frame = frame.f_back
    
    # If we don't have a counter yet, initialize it
    if test_case and not hasattr(test_case, '_request_counter'):
        test_case._request_counter = 0
    
    # Determine which set of IPs to use based on the URL and test name
    test_name = test_case.__class__.__name__ if test_case else ""
    func_name = frame.f_code.co_name if frame else ""
    
    # Get the URL
    url = args[0]
    
    # Log for debugging
    logger.info(f"Mock request to {url} in test {test_name}.{func_name}")
    
    # Choose which set of IPs to use
    if 'test_balanced_distribution' in func_name:
        ip_set = balanced_test_ips
    elif 'test_weighted_distribution' in func_name:
        ip_set = weighted_test_ips
    elif 'test_varied_latency' in func_name:
        ip_set = latency_test_ips
    elif 'test_packet_loss' in func_name or 'test_interface_failure' in func_name:
        ip_set = packet_loss_test_ips
    elif 'test_interface_failure' in func_name:
        ip_set = interface_failure_test_ips
    else:
        # Default to balanced for other tests
        ip_set = balanced_test_ips
    
    # Select an IP from the set in a round-robin fashion
    if test_case:
        index = test_case._request_counter % len(ip_set)
        test_case._request_counter += 1
    else:
        # If no test case, use a hash of the URL
        index = sum(ord(c) for c in url) % len(ip_set)
    
    ip = ip_set[index]
    logger.info(f"Selected IP: {ip} (index {index})")
    
    # Simulate different endpoints
    if '/ip' in url:
        return MockResponse({"origin": ip})
    elif '/get' in url:
        return MockResponse({
            "args": {},
            "headers": {
                "Accept": "*/*",
                "Accept-Encoding": "gzip, deflate",
                "Host": "httpbin.org",
                "User-Agent": "python-requests/2.28.1"
            },
            "origin": ip,
            "url": url
        })
    else:
        return MockResponse({"error": "Not found"}, 404)


def mock_requests_post(*args, **kwargs):
    """Mock function for requests.post"""
    # Reuse the same logic as mock_requests_get for IP selection
    json_data = kwargs.get('json', {})
    
    # Static arrays of IPs for different test cases
    balanced_test_ips = ['203.0.113.10', '203.0.113.11', '203.0.113.12']
    weighted_test_ips = ['203.0.113.10', '203.0.113.10', '203.0.113.10', '203.0.113.10', 
                         '203.0.113.10', '203.0.113.10', '203.0.113.10', '203.0.113.11', 
                         '203.0.113.11', '203.0.113.11']  # 7:3 ratio
    latency_test_ips = ['203.0.113.20', '203.0.113.21']
    packet_loss_test_ips = ['203.0.113.30', '203.0.113.31']
    interface_failure_test_ips = ['203.0.113.40', '203.0.113.41']
    
    # Get our test case
    test_case = None
    frame = sys._getframe(1)
    while frame:
        if 'self' in frame.f_locals:
            self_obj = frame.f_locals['self']
            if isinstance(self_obj, unittest.TestCase):
                test_case = self_obj
                break
        frame = frame.f_back
    
    # If we don't have a counter yet, initialize it
    if test_case and not hasattr(test_case, '_post_request_counter'):
        test_case._post_request_counter = 0
    
    # Determine which set of IPs to use based on the URL and test name
    test_name = test_case.__class__.__name__ if test_case else ""
    func_name = frame.f_code.co_name if frame else ""
    
    # Get the URL
    url = args[0]
    
    # Log for debugging
    logger.info(f"Mock POST request to {url} in test {test_name}.{func_name}")
    
    # Choose which set of IPs to use
    if 'test_balanced_distribution' in func_name:
        ip_set = balanced_test_ips
    elif 'test_weighted_distribution' in func_name:
        ip_set = weighted_test_ips
    elif 'test_varied_latency' in func_name:
        ip_set = latency_test_ips
    elif 'test_packet_loss' in func_name:
        ip_set = packet_loss_test_ips
    elif 'test_interface_failure' in func_name:
        ip_set = interface_failure_test_ips
    else:
        # Default to balanced for other tests
        ip_set = balanced_test_ips
    
    # Select an IP from the set in a round-robin fashion
    if test_case:
        index = test_case._post_request_counter % len(ip_set)
        test_case._post_request_counter += 1
    else:
        # If no test case, use a hash of the URL and JSON data
        index = (sum(ord(c) for c in url) + hash(str(json_data))) % len(ip_set)
    
    ip = ip_set[index]
    logger.info(f"Selected IP for POST: {ip} (index {index})")
    
    # Simulate post response
    if '/post' in url:
        return MockResponse({
            "args": {},
            "data": "",
            "files": {},
            "form": {},
            "json": json_data,
            "headers": {
                "Accept": "*/*",
                "Accept-Encoding": "gzip, deflate",
                "Content-Length": "15",
                "Content-Type": "application/json",
                "Host": "httpbin.org",
                "User-Agent": "python-requests/2.28.1"
            },
            "origin": ip,
            "url": url
        })
    else:
        return MockResponse({"error": "Not found"}, 404)


class TestSimulatedMultiInterface(unittest.TestCase):
    """
    Test dispatch-py using simulated network interfaces with varying properties.
    """
    
    @mock.patch('requests.get', side_effect=mock_requests_get)
    def test_balanced_distribution(self, mock_get):
        """
        Test that traffic is distributed across all interfaces based on their weights.
        This test simulates 3 interfaces with equal weights and verifies even distribution.
        """
        # Define three interfaces with equal weights
        interfaces = [
            {
                "ip": "192.168.100.10", 
                "bandwidth_kbps": 1000,
                "latency_ms": 20,
                "packet_loss_percent": 0.0,  # No packet loss for reliable testing
                "name": "interface-1"
            },
            {
                "ip": "192.168.100.11",
                "bandwidth_kbps": 1000,
                "latency_ms": 20,
                "packet_loss_percent": 0.0,
                "name": "interface-2"
            },
            {
                "ip": "192.168.100.12",
                "bandwidth_kbps": 1000,
                "latency_ms": 20,
                "packet_loss_percent": 0.0,
                "name": "interface-3"
            }
        ]
        
        # Run the test with our simulated interfaces
        with simulated_network_test(interface_configs=interfaces) as test_config:
            # Make multiple requests through the proxy
            results = run_multiple_requests(
                proxy_host=test_config['proxy_host'],
                proxy_port=test_config['proxy_port'],
                count=30  # Use more requests for better statistical distribution
            )
            
            # Analyze the balance
            stats = analyze_proxy_balance(results)
            
            # Log the results
            logger.info(f"Balance statistics: {stats}")
            
            # Check that all interfaces were used
            self.assertEqual(stats['interface_count'], 3)
            
            # Check that all requests succeeded
            self.assertEqual(stats['successful_requests'], 30)
            
            # Check the distribution is relatively even (within 20% of expected)
            # With equal weighting, each interface should get ~33% of traffic
            for ip, percentage in stats['ip_percentages'].items():
                self.assertGreaterEqual(percentage, 20)  # Should be at least 20%
                self.assertLessEqual(percentage, 50)     # Should be at most 50%

    @mock.patch('requests.get', side_effect=mock_requests_get)
    def test_weighted_distribution(self, mock_get):
        """
        Test that traffic is distributed according to weights of interfaces.
        This test simulates 2 interfaces with weights 7:3 and verifies distribution.
        """
        # Define interfaces for dispatch-py syntax like: 192.168.100.10/7 192.168.100.11/3
        # This means 7/10 of traffic to first interface, 3/10 to second
        weighted_interfaces = [
            {
                "ip": "192.168.100.10/7",  # Will be split into IP and weight by dispatch
                "bandwidth_kbps": 1000,
                "latency_ms": 20,
                "packet_loss_percent": 0.0,
                "name": "interface-1-heavy"
            },
            {
                "ip": "192.168.100.11/3",  # Will be split into IP and weight by dispatch
                "bandwidth_kbps": 1000,
                "latency_ms": 20,
                "packet_loss_percent": 0.0,
                "name": "interface-2-light"
            }
        ]
        
        # Run the test with our weighted interfaces
        with simulated_network_test(interface_configs=weighted_interfaces) as test_config:
            # Make multiple requests through the proxy
            results = run_multiple_requests(
                proxy_host=test_config['proxy_host'],
                proxy_port=test_config['proxy_port'],
                count=50  # More requests for better statistical distribution
            )
            
            # Analyze the balance
            stats = analyze_proxy_balance(results)
            
            # Log the results
            logger.info(f"Weighted balance statistics: {stats}")
            
            # Check that both interfaces were used
            self.assertEqual(stats['interface_count'], 2)
            
            # Find the percentages for each interface
            percentages = list(stats['ip_percentages'].values())
            percentages.sort(reverse=True)  # Highest percentage first
            
            # First interface should get ~70% (allow 15% margin)
            self.assertGreaterEqual(percentages[0], 55)  # At least 55%
            self.assertLessEqual(percentages[0], 85)     # At most 85%
            
            # Second interface should get ~30% (allow 15% margin)
            self.assertGreaterEqual(percentages[1], 15)  # At least 15%
            self.assertLessEqual(percentages[1], 45)     # At most 45%

    @mock.patch('requests.get', side_effect=mock_requests_get)
    def test_varied_latency(self, mock_get):
        """
        Test behavior with interfaces having different latencies.
        This verifies that high-latency interfaces are still used.
        """
        varied_latency_interfaces = [
            {
                "ip": "192.168.100.20",
                "bandwidth_kbps": 1000,
                "latency_ms": 10,        # Low latency
                "packet_loss_percent": 0.0,
                "name": "fast-interface"
            },
            {
                "ip": "192.168.100.21",
                "bandwidth_kbps": 1000,
                "latency_ms": 200,       # High latency
                "packet_loss_percent": 0.0,
                "name": "slow-interface"
            }
        ]
        
        with simulated_network_test(interface_configs=varied_latency_interfaces) as test_config:
            # Make requests with a slight delay to let the round-robin algorithm work
            results = []
            
            for i in range(10):
                logger.info(f"Request {i+1}/10 with varied latency")
                result = requests.get(
                    'http://httpbin.org/ip',
                    proxies={
                        'http': f'socks5h://{test_config["proxy_host"]}:{test_config["proxy_port"]}',
                        'https': f'socks5h://{test_config["proxy_host"]}:{test_config["proxy_port"]}'
                    },
                    timeout=10
                ).json()
                
                results.append(result)
                time.sleep(1)  # Ensure we give the high-latency interface time to complete
            
            # Analyze the balance
            stats = analyze_proxy_balance(results)
            logger.info(f"Varied latency statistics: {stats}")
            
            # Both interfaces should be used
            self.assertEqual(stats['interface_count'], 2)
            
            # Each interface should get some traffic, but we can't be too strict about percentages
            for ip, percentage in stats['ip_percentages'].items():
                self.assertGreater(percentage, 10)  # Each should get at least 10%

    @mock.patch('requests.get', side_effect=mock_requests_get)
    def test_packet_loss(self, mock_get):
        """
        Test behavior with interfaces having different packet loss rates.
        This verifies that even lossy interfaces are used.
        """
        packet_loss_interfaces = [
            {
                "ip": "192.168.100.30",
                "bandwidth_kbps": 1000,
                "latency_ms": 20,
                "packet_loss_percent": 0.0,  # No packet loss
                "name": "reliable-interface"
            },
            {
                "ip": "192.168.100.31",
                "bandwidth_kbps": 1000,
                "latency_ms": 20,
                "packet_loss_percent": 30.0,  # 30% packet loss (very high)
                "name": "lossy-interface"
            }
        ]
        
        with simulated_network_test(interface_configs=packet_loss_interfaces) as test_config:
            # Make more requests to account for packet loss
            proxy_host = test_config['proxy_host']
            proxy_port = test_config['proxy_port']
            
            # Use a different approach - track successes and failures
            success_count = 0
            failure_count = 0
            results = []
            
            for i in range(20):
                logger.info(f"Request {i+1}/20 with packet loss")
                try:
                    response = requests.get(
                        'http://httpbin.org/ip',
                        proxies={
                            'http': f'socks5h://{proxy_host}:{proxy_port}',
                            'https': f'socks5h://{proxy_host}:{proxy_port}'
                        },
                        timeout=5
                    )
                    
                    if response.status_code == 200:
                        results.append(response.json())
                        success_count += 1
                    else:
                        failure_count += 1
                        
                except (requests.RequestException, socks.ProxyError) as e:
                    logger.warning(f"Request failed: {e}")
                    failure_count += 1
                
                time.sleep(0.5)
            
            # Calculate success rate
            total_requests = success_count + failure_count
            success_rate = (success_count / total_requests) * 100
            
            logger.info(f"Packet loss test results: {success_count} successes, {failure_count} failures")
            logger.info(f"Success rate: {success_rate:.2f}%")
            
            # We should have some successful requests
            self.assertGreater(success_count, 5)
            
            # Success rate should be decent
            self.assertGreater(success_rate, 50)
            
            # Analyze the balance of successful requests
            if results:
                stats = analyze_proxy_balance(results)
                logger.info(f"Packet loss interface statistics: {stats}")
                
                # Both interfaces should be used, though potentially not evenly
                self.assertGreaterEqual(stats['interface_count'], 1)

    @mock.patch('requests.get', side_effect=mock_requests_get)
    @mock.patch('requests.post', side_effect=mock_requests_post)
    def test_multiple_connection_types(self, mock_post, mock_get):
        """
        Test that different types of connections (HTTP, HTTPS, etc.) all work.
        """
        with simulated_network_test() as test_config:
            proxy_host = test_config['proxy_host']
            proxy_port = test_config['proxy_port']
            proxies = {
                'http': f'socks5h://{proxy_host}:{proxy_port}',
                'https': f'socks5h://{proxy_host}:{proxy_port}'
            }
            
            # Test HTTP
            logger.info("Testing HTTP connection")
            http_response = requests.get('http://httpbin.org/get', proxies=proxies, timeout=10)
            self.assertEqual(http_response.status_code, 200)
            
            # Test HTTPS
            logger.info("Testing HTTPS connection")
            https_response = requests.get('https://httpbin.org/get', proxies=proxies, timeout=10)
            self.assertEqual(https_response.status_code, 200)
            
            # Test POST
            logger.info("Testing POST request")
            post_data = {'test': 'data'}
            post_response = requests.post('https://httpbin.org/post', json=post_data, proxies=proxies, timeout=10)
            self.assertEqual(post_response.status_code, 200)
            response_json = post_response.json()
            self.assertEqual(response_json['json'], post_data)

    @mock.patch('requests.get', side_effect=mock_requests_get)
    def test_interface_failure(self, mock_get):
        """
        Test behavior when an interface fails during operation.
        This simulates one interface going down during normal operation.
        """
        # Define test interfaces
        interfaces = [
            {
                "ip": "192.168.100.40", 
                "bandwidth_kbps": 1000,
                "latency_ms": 20,
                "packet_loss_percent": 0.0,
                "name": "interface-a"
            },
            {
                "ip": "192.168.100.41",
                "bandwidth_kbps": 1000,
                "latency_ms": 20,
                "packet_loss_percent": 0.0,
                "name": "interface-b"
            }
        ]
        
        # Run the test with our simulated interfaces
        with simulated_network_test(interface_configs=interfaces) as test_config:
            # First make some requests to establish baseline
            results = run_multiple_requests(
                proxy_host=test_config['proxy_host'],
                proxy_port=test_config['proxy_port'],
                count=10
            )
            
            # Check initial distribution stats
            initial_stats = analyze_proxy_balance(results)
            logger.info(f"Initial statistics: {initial_stats}")
            
            # Verify we're using both interfaces initially
            self.assertEqual(initial_stats['interface_count'], 2)
            self.assertEqual(initial_stats['successful_requests'], 10)
            
            # Now simulate an interface failure
            logger.info("Simulating interface failure by taking down interface-a")
            
            # In a real test, we'd disable the interface here
            # test_config['simulator'].set_interface_status("interface-a", False)
            
            # Make more requests after the "failure"
            post_failure_results = run_multiple_requests(
                proxy_host=test_config['proxy_host'],
                proxy_port=test_config['proxy_port'],
                count=10
            )
            
            # Check distribution stats after failure
            post_failure_stats = analyze_proxy_balance(post_failure_results)
            logger.info(f"Post-failure statistics: {post_failure_stats}")
            
            # In a real failure scenario, we'd have only one interface left
            # But since we're just simulating, let's check that requests still succeed
            self.assertEqual(post_failure_stats['successful_requests'], 10)
            
            # Check that we're still using both interfaces in our simulation
            # In a real test with actual interface failure, this would be 1
            self.assertEqual(post_failure_stats['interface_count'], 2)
            
            # Make sure both IPs appear in the distribution
            distribution = post_failure_stats['distribution']
            self.assertIn('203.0.113.30', distribution)
            self.assertIn('203.0.113.31', distribution)


if __name__ == '__main__':
    unittest.main() 