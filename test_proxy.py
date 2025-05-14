#!/usr/bin/env python3
"""
Simple test script to check the SOCKS proxy
"""

import requests
import sys
import time

def test_proxy(proxy_host="127.0.0.1", proxy_port=1080, url="http://httpbin.org/ip"):
    """Test connecting to a URL through the SOCKS proxy"""
    proxies = {
        'http': f'socks5h://{proxy_host}:{proxy_port}',
        'https': f'socks5h://{proxy_host}:{proxy_port}'
    }
    
    print(f"Connecting to {url} through proxy {proxy_host}:{proxy_port}")
    
    try:
        response = requests.get(url, proxies=proxies, timeout=10)
        
        if response.status_code == 200:
            print(f"Success! Response: {response.text}")
            return True
        else:
            print(f"HTTP error: {response.status_code}")
            return False
    except Exception as e:
        print(f"Error: {e}")
        return False

if __name__ == "__main__":
    # Default values
    proxy_host = "127.0.0.1"
    proxy_port = 1080
    url = "http://httpbin.org/ip"
    
    # Parse command line arguments if provided
    if len(sys.argv) > 1:
        proxy_host = sys.argv[1]
    if len(sys.argv) > 2:
        proxy_port = int(sys.argv[2])
    if len(sys.argv) > 3:
        url = sys.argv[3]
    
    # Test the proxy
    test_proxy(proxy_host, proxy_port, url) 