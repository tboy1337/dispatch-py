#!/usr/bin/env python3
"""
Simple script to test the SOCKS proxy functionality.
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

def find_usable_ip():
    """Find a usable IP address from the network interfaces"""
    cmd_list = [sys.executable, "run_dispatch.py", "list"]
    result = subprocess.run(cmd_list, capture_output=True, text=True)
    
    # Look for IPv4 addresses that aren't loopback
    ip_pattern = r'IPv4: (\d+\.\d+\.\d+\.\d+)'
    ip_addresses = re.findall(ip_pattern, result.stdout)
    
    for ip in ip_addresses:
        if not ip.startswith('127.'):
            return ip
    
    # If no non-loopback IP found, use loopback
    return '127.0.0.1'

def start_proxy():
    """Start the SOCKS proxy server as a subprocess"""
    proxy_port = 1080
    proxy_ip = "127.0.0.1"
    
    # Get a usable interface IP address
    dispatch_ip = find_usable_ip()
    
    logger.info(f"Starting proxy server on {proxy_ip}:{proxy_port} routing through {dispatch_ip}")
    
    # Start the proxy in a subprocess with the correct command format
    cmd = [
        sys.executable, 
        "run_dispatch.py", 
        "start", 
        dispatch_ip,  # The address to dispatch traffic through
        "--ip", proxy_ip,  # The IP to accept connections from
        "--port", str(proxy_port)  # The port to listen on
    ]
    
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

def test_http_request_with_socks():
    """Test a simple HTTP request through the SOCKS proxy using PySocks"""
    proxy_port = 1080
    proxy_host = "127.0.0.1"
    
    # Save the default socket
    default_socket = socket.socket
    
    try:
        # Configure the proxy
        socks.set_default_proxy(socks.SOCKS5, proxy_host, proxy_port)
        socket.socket = socks.socksocket
        
        # Make a request
        logger.info("Making HTTP request through proxy...")
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(30)
        s.connect(("httpbin.org", 80))
        s.sendall(b"GET /ip HTTP/1.1\r\nHost: httpbin.org\r\nConnection: close\r\n\r\n")
        
        # Get the response
        response = b""
        while True:
            data = s.recv(4096)
            if not data:
                break
            response += data
        
        s.close()
        response_text = response.decode('utf-8')
        logger.info(f"Response: {response_text}")
        
        # Verify the response has an IP address
        if '"origin":' in response_text:
            return True
        else:
            logger.error("Response did not contain expected IP information")
            return False
            
    except Exception as e:
        logger.error(f"Error making request: {e}")
        return False
    finally:
        # Restore the default socket
        socket.socket = default_socket

def test_http_request_with_requests():
    """Test a simple HTTP request through the SOCKS proxy using the requests library"""
    proxy_port = 1080
    proxy_host = "127.0.0.1"
    
    # Setup proxy configuration for requests
    proxies = {
        'http': f'socks5://{proxy_host}:{proxy_port}',
        'https': f'socks5://{proxy_host}:{proxy_port}'
    }
    
    try:
        logger.info("Making HTTP request through proxy using requests...")
        response = requests.get('http://httpbin.org/ip', proxies=proxies, timeout=30)
        logger.info(f"Response status: {response.status_code}")
        logger.info(f"Response body: {response.text}")
        
        if response.status_code == 200 and '"origin":' in response.text:
            return True
        else:
            logger.error("Response did not contain expected data")
            return False
            
    except Exception as e:
        logger.error(f"Error making request with requests: {e}")
        return False

def main():
    """Main test function"""
    logger.info("Starting SOCKS proxy test")
    
    # Start the proxy
    proxy_process = None
    try:
        proxy_process = start_proxy()
        
        # Wait for proxy to fully initialize
        time.sleep(2)
        
        # Test using PySocks directly
        sock_result = test_http_request_with_socks()
        
        # Test using requests library
        requests_result = test_http_request_with_requests()
        
        if sock_result and requests_result:
            logger.info("✅ SOCKS proxy test PASSED (both methods)")
            return 0
        elif sock_result:
            logger.info("✅ SOCKS proxy test PASSED (socket method only)")
            return 0
        elif requests_result:
            logger.info("✅ SOCKS proxy test PASSED (requests method only)")
            return 0
        else:
            logger.error("❌ SOCKS proxy test FAILED (all methods)")
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