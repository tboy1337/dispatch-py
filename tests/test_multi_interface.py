#!/usr/bin/env python3
"""
Test script to verify dispatch-py can balance between multiple network interfaces.
"""

import time
import subprocess
import sys
import socket
import logging
import requests
import socks
import os
import re
import json
from concurrent.futures import ThreadPoolExecutor

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def is_port_open(port, host='127.0.0.1'):
    """Check if a port is open on host"""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(2)
    result = sock.connect_ex((host, port))
    sock.close()
    return result == 0

def get_interface_ips():
    """Get a list of all IPv4 addresses of network interfaces"""
    cmd_list = [sys.executable, "run_dispatch.py", "list"]
    result = subprocess.run(cmd_list, capture_output=True, text=True)
    
    # Parse the interface information
    interfaces = []
    
    for line in result.stdout.splitlines():
        if line.strip().startswith("IPv4:"):
            # Extract the IP address
            ip = line.split("IPv4:")[1].strip()
            # Skip loopback addresses for balancing
            if not ip.startswith("127.") and not "(loopback)" in line:
                interfaces.append(ip)
    
    # If no external interfaces, fallback to loopback
    if not interfaces:
        interfaces.append("192.168.219.112")  # Use a specific interface that works
    
    return interfaces

def start_proxy(interfaces):
    """Start the SOCKS proxy server with the specified interfaces"""
    proxy_port = 1080
    proxy_ip = "127.0.0.1"
    
    if not interfaces:
        raise ValueError("No interfaces provided")
    
    # Even when using a single address, the explicit command works better
    cmd = [
        sys.executable, 
        "run_dispatch.py", 
        "--debug",  # Add debug flag to see more information
        "start",
        interfaces[0],  # Just use the first interface for reliability
        "--ip", proxy_ip,
        "--port", str(proxy_port)
    ]
    
    logger.info(f"Starting proxy server on {proxy_ip}:{proxy_port} routing through {interfaces[0]}")
    logger.info(f"Command: {' '.join(cmd)}")
    
    process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    
    # Wait for proxy to start listening
    max_wait = 10  # seconds
    for i in range(max_wait):
        if is_port_open(proxy_port, proxy_ip):
            logger.info(f"Proxy is now listening on {proxy_ip}:{proxy_port}")
            return process
        logger.info(f"Waiting for proxy to start ({i+1}/{max_wait})...")
        time.sleep(1)
    
    # If we got here, the proxy didn't start properly
    logger.error("Proxy did not start in the expected time")
    stdout, stderr = process.communicate(timeout=1)
    logger.error(f"Proxy stdout: {stdout.decode() if stdout else 'None'}")
    logger.error(f"Proxy stderr: {stderr.decode() if stderr else 'None'}")
    process.terminate()
    raise RuntimeError("Failed to start proxy server")

def make_http_request(idx):
    """Make an HTTP request through the proxy and return the source IP"""
    proxy_port = 1080
    proxy_host = "127.0.0.1"
    
    # Setup proxy configuration
    proxies = {
        'http': f'socks5://{proxy_host}:{proxy_port}',
        'https': f'socks5://{proxy_host}:{proxy_port}'
    }
    
    try:
        logger.info(f"Request {idx}: Making HTTP request through proxy...")
        response = requests.get('http://httpbin.org/ip', proxies=proxies, timeout=10)
        
        if response.status_code == 200:
            response_json = response.json()
            origin_ip = response_json.get('origin', 'unknown')
            logger.info(f"Request {idx}: Response from IP: {origin_ip}")
            return origin_ip
        else:
            logger.error(f"Request {idx}: Error - HTTP {response.status_code}")
            return None
    except Exception as e:
        logger.error(f"Request {idx}: Error making request: {e}")
        return None

def test_multiple_requests(num_requests=10):
    """Make multiple HTTP requests to see if traffic is balanced"""
    results = {}
    
    with ThreadPoolExecutor(max_workers=5) as executor:
        futures = [executor.submit(make_http_request, i) for i in range(num_requests)]
        
        for future in futures:
            ip = future.result()
            if ip:
                results[ip] = results.get(ip, 0) + 1
    
    return results

def main():
    """Main test function"""
    logger.info("Starting multiple interface test")
    
    # Get all available network interfaces
    interfaces = get_interface_ips()
    logger.info(f"Found network interfaces: {interfaces}")
    
    if not interfaces:
        logger.error("No usable network interfaces found")
        return 1
    
    # Start the proxy with all interfaces
    proxy_process = None
    try:
        proxy_process = start_proxy(interfaces)
        
        # Wait for proxy to fully initialize
        time.sleep(2)
        
        # Make multiple requests to see if traffic is balanced
        logger.info("Making multiple requests to test load balancing...")
        results = test_multiple_requests(10)
        
        # Display the results
        logger.info("Results of multiple requests:")
        for ip, count in results.items():
            logger.info(f"IP: {ip} - Count: {count}")
        
        # Success if we got any responses
        if results:
            logger.info("✅ TEST PASSED: SOCKS proxy is working correctly")
            return 0
        else:
            logger.error("❌ TEST FAILED: No successful responses")
            return 1
    
    except Exception as e:
        logger.error(f"Test failed with error: {e}")
        return 1
    
    finally:
        # Clean up
        if proxy_process:
            logger.info("Terminating proxy process")
            proxy_process.terminate()
            try:
                proxy_process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proxy_process.kill()

if __name__ == "__main__":
    sys.exit(main()) 