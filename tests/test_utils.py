#!/usr/bin/env python3
"""
Test utilities for running dispatch-py tests with simulated multiple network interfaces.
"""

import os
import sys
import time
import socket
import logging
import subprocess
import threading
import json
import requests
import unittest
import tempfile
from contextlib import contextmanager
from typing import List, Dict, Optional, Tuple, Any, Union
from unittest import mock

# Import the network simulator components
from tests.network_simulator import create_simulated_network, cleanup_simulated_network
from tests.socket_patcher import NetworkPatcher

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Default test interface configurations
DEFAULT_TEST_INTERFACES = [
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

def is_port_open(port, host='127.0.0.1', timeout=1.0):
    """Check if a port is open on a host"""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    result = sock.connect_ex((host, port))
    sock.close()
    return result == 0

def wait_for_port(port, host='127.0.0.1', timeout=10.0, retry_interval=0.5):
    """Wait for a port to be open, with a timeout"""
    start_time = time.time()
    while time.time() - start_time < timeout:
        if is_port_open(port, host, retry_interval):
            return True
        time.sleep(retry_interval)
    return False

def start_proxy_process(interface_ips, ip='127.0.0.1', port=1080, debug=True):
    """
    Start the dispatch proxy process using the given interface IPs
    
    Args:
        interface_ips: List of IP addresses to use for balancing
        ip: IP address for the proxy to listen on
        port: Port for the proxy to listen on
        debug: Whether to run in debug mode
    
    Returns:
        The subprocess.Popen object for the proxy process
    """
    # Build the command to start the proxy
    cmd = [
        sys.executable, 
        "run_dispatch.py"
    ]
    
    if debug:
        cmd.append("--debug")
    
    cmd.extend([
        "start",
        *interface_ips,  # Expand the list of IPs
        "--ip", ip,
        "--port", str(port)
    ])
    
    logger.info(f"Starting proxy with command: {' '.join(cmd)}")
    
    # Start the process
    process = subprocess.Popen(
        cmd, 
        stdout=subprocess.PIPE, 
        stderr=subprocess.PIPE,
        universal_newlines=True,
        bufsize=1  # Line buffered
    )
    
    # Check if the proxy started successfully
    if not wait_for_port(port, ip, timeout=10.0):
        stdout, stderr = process.communicate(timeout=1)
        logger.error(f"Failed to start proxy. Output: {stdout}\nError: {stderr}")
        process.terminate()
        raise RuntimeError(f"Failed to start proxy on {ip}:{port}")
    
    logger.info(f"Proxy started successfully on {ip}:{port}")
    return process

def make_http_request_through_proxy(proxy_host='127.0.0.1', proxy_port=1080, 
                                   target_url='http://httpbin.org/ip', timeout=10):
    """
    Make an HTTP request through the SOCKS proxy
    
    Args:
        proxy_host: The proxy hostname
        proxy_port: The proxy port
        target_url: The URL to request
        timeout: Request timeout in seconds
    
    Returns:
        dict: The response JSON or None on error
    """
    proxies = {
        'http': f'socks5h://{proxy_host}:{proxy_port}',
        'https': f'socks5h://{proxy_host}:{proxy_port}'
    }
    
    try:
        logger.info(f"Making request to {target_url} through proxy {proxy_host}:{proxy_port}")
        response = requests.get(target_url, proxies=proxies, timeout=timeout)
        
        if response.status_code == 200:
            return response.json()
        else:
            logger.error(f"HTTP error: {response.status_code}")
            return None
    except Exception as e:
        logger.error(f"Error making request: {e}")
        return None

def run_multiple_requests(proxy_host='127.0.0.1', proxy_port=1080, 
                         target_url='http://httpbin.org/ip', count=10):
    """
    Run multiple HTTP requests through the proxy and return results
    
    Args:
        proxy_host: The proxy hostname
        proxy_port: The proxy port
        target_url: The URL to request
        count: Number of requests to make
    
    Returns:
        List of results
    """
    results = []
    
    for i in range(count):
        logger.info(f"Request {i+1}/{count}")
        result = make_http_request_through_proxy(
            proxy_host=proxy_host,
            proxy_port=proxy_port,
            target_url=target_url
        )
        
        results.append(result)
        time.sleep(0.5)  # Small delay between requests
    
    return results

def analyze_proxy_balance(results):
    """
    Analyze the results to check if traffic is correctly balanced
    
    Args:
        results: List of response dictionaries from requests made through the proxy
    
    Returns:
        dict: Statistics about the balance
    """
    # Count requests per source IP
    ip_counts = {}
    
    for result in results:
        if result and 'origin' in result:
            ip = result['origin']
            ip_counts[ip] = ip_counts.get(ip, 0) + 1
    
    total_requests = sum(ip_counts.values())
    
    if total_requests == 0:
        return {
            "status": "error",
            "message": "No successful requests",
            "total_requests": 0,
            "distribution": {},
            "interface_count": 0,
            "successful_requests": 0,
            "ip_percentages": {}
        }
    
    # Calculate distribution percentages
    distribution = {
        ip: {
            "count": count,
            "percentage": (count / total_requests) * 100
        }
        for ip, count in ip_counts.items()
    }
    
    # Calculate percentages for each IP
    ip_percentages = {ip: (count / total_requests) * 100 for ip, count in ip_counts.items()}
    
    return {
        "status": "success",
        "message": f"Requests distributed across {len(ip_counts)} IPs",
        "total_requests": total_requests,
        "distribution": distribution,
        "interface_count": len(ip_counts),
        "successful_requests": total_requests,
        "ip_percentages": ip_percentages
    }

class MockedProxyProcess:
    """Mock process object that mimics a running proxy process for testing"""
    
    def __init__(self, ip='127.0.0.1', port=1080):
        self.ip = ip
        self.port = port
    
    def terminate(self):
        """Mock terminate method"""
        pass
    
    def wait(self, timeout=None):
        """Mock wait method"""
        return 0
    
    def kill(self):
        """Mock kill method"""
        pass

@contextmanager
def simulated_network_test(interface_configs=None, proxy_port=1080, mock_proxy=True):
    """
    Context manager for running tests with a simulated network
    
    Args:
        interface_configs: Network interface configurations
        proxy_port: Port for the proxy
        mock_proxy: Whether to mock the proxy process
    
    Yields:
        dict: Configuration with proxy_host, proxy_port, simulator, and interface_ips
    """
    if interface_configs is None:
        interface_configs = DEFAULT_TEST_INTERFACES
    
    # Get interface IPs
    interface_ips = [config["ip"] for config in interface_configs]
    
    try:
        # Create the simulated network
        simulator = create_simulated_network(interface_configs)
        
        # Set up network patching with our simulator
        patcher = NetworkPatcher(simulator)
        patcher.__enter__()
        
        try:
            if mock_proxy:
                # Create a mock proxy process
                proxy_process = MockedProxyProcess(port=proxy_port)
            else:
                # Start the actual proxy
                proxy_process = start_proxy_process(
                    interface_ips=interface_ips,
                    port=proxy_port
                )
            
            try:
                # Yield a dictionary with all configuration info
                test_config = {
                    'simulator': simulator,
                    'proxy_process': proxy_process,
                    'interface_ips': interface_ips,
                    'proxy_host': '127.0.0.1',
                    'proxy_port': proxy_port
                }
                yield test_config
            finally:
                # Clean up the proxy process
                if not mock_proxy and proxy_process:
                    proxy_process.terminate()
                    try:
                        proxy_process.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        proxy_process.kill()
        finally:
            # Clean up the network patcher
            patcher.__exit__(None, None, None)
    finally:
        # Clean up the simulated network
        cleanup_simulated_network()

# Standardized test base classes

class SimulatedNetworkTestCase(unittest.TestCase):
    """
    Base test case for tests using simulated network interfaces
    
    This provides a standardized setup/teardown pattern and utility methods
    for tests that need to simulate multiple network interfaces.
    """
    
    # Default test settings - can be overridden in subclasses
    interface_configs = DEFAULT_TEST_INTERFACES
    proxy_port = 1080
    mock_proxy = True
    
    def setUp(self):
        """Set up the simulated network for each test"""
        self.context_manager = simulated_network_test(
            interface_configs=self.interface_configs,
            proxy_port=self.proxy_port,
            mock_proxy=self.mock_proxy
        )
        self.test_config = self.context_manager.__enter__()
        self.simulator = self.test_config['simulator']
        self.proxy_process = self.test_config['proxy_process']
        self.interface_ips = self.test_config['interface_ips']
        self.proxy_host = self.test_config['proxy_host']
        self.proxy_port = self.test_config['proxy_port']
    
    def tearDown(self):
        """Clean up after each test"""
        self.context_manager.__exit__(None, None, None)
    
    def run_proxy_test(self, request_count=10, target_url='http://httpbin.org/ip'):
        """Run a standardized proxy test with multiple requests"""
        results = run_multiple_requests(
            proxy_host=self.proxy_host,
            proxy_port=self.proxy_port,
            target_url=target_url, 
            count=request_count
        )
        
        # Analyze the results
        return analyze_proxy_balance(results)

class RealNetworkTestCase(unittest.TestCase):
    """
    Base test case for tests using real network interfaces
    
    This provides a standardized setup/teardown pattern and utility methods
    for tests that need to use real network interfaces.
    """
    
    proxy_port = 1080
    proxy_process = None
    
    def setUp(self):
        """Set up for each test - may be implemented in subclasses"""
        pass
    
    def tearDown(self):
        """Clean up after each test"""
        if self.proxy_process:
            self.proxy_process.terminate()
            try:
                self.proxy_process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.proxy_process.kill()
    
    def start_proxy(self, interface_ips, debug=True):
        """Start the proxy process with the given interfaces"""
        self.proxy_process = start_proxy_process(
            interface_ips=interface_ips,
            port=self.proxy_port,
            debug=debug
        )
        return self.proxy_process
    
    def run_proxy_test(self, request_count=10, target_url='http://httpbin.org/ip'):
        """Run a standardized proxy test with multiple requests"""
        results = run_multiple_requests(
            proxy_port=self.proxy_port,
            target_url=target_url, 
            count=request_count
        )
        
        # Analyze the results
        return analyze_proxy_balance(results)

# Example usage:
# with simulated_network_test() as test_config:
#     proxy_host = test_config['proxy_host']
#     proxy_port = test_config['proxy_port']
#     results = run_multiple_requests(proxy_host=proxy_host, proxy_port=proxy_port, count=10)
#     stats = analyze_proxy_balance(results)
#     print(f"Balance statistics: {stats}") 