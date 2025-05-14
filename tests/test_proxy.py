#!/usr/bin/env python3
"""
Simple test script to verify the SOCKS proxy is working.
"""

import requests
import socket
import sys

def test_proxy():
    """Test the SOCKS proxy by making a request through it."""
    proxy_url = "socks5://127.0.0.1:1080"
    
    # Configure the proxy
    proxies = {
        'http': proxy_url,
        'https': proxy_url
    }
    
    print(f"Testing proxy at {proxy_url}")
    print("Making request to http://httpbin.org/ip...")
    
    try:
        # Try to make a request through the proxy
        response = requests.get("http://httpbin.org/ip", proxies=proxies, timeout=10)
        
        # Print the response
        print(f"Response status code: {response.status_code}")
        print("Response content:")
        print(response.text)
        
        return response.status_code == 200
    
    except requests.exceptions.RequestException as e:
        print(f"Error: {e}")
        return False
    except socket.error as e:
        print(f"Socket error: {e}")
        return False

if __name__ == "__main__":
    success = test_proxy()
    sys.exit(0 if success else 1) 