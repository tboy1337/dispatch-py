#!/usr/bin/env python3
"""
Test script for the SOCKS proxy.
"""

import argparse
import socket
import socks
import sys
import time
from urllib.request import urlopen

def parse_args():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(description='Test SOCKS proxy connection')
    parser.add_argument('--proxy-host', default='127.0.0.1', help='SOCKS proxy host')
    parser.add_argument('--proxy-port', type=int, default=1080, help='SOCKS proxy port')
    parser.add_argument('--url', default='https://httpbin.org/ip', help='URL to test')
    return parser.parse_args()

def main():
    """Main entry point."""
    args = parse_args()
    
    # Create a SOCKS socket
    socks.set_default_proxy(socks.SOCKS5, args.proxy_host, args.proxy_port)
    socket.socket = socks.socksocket
    
    print(f"Testing connection through SOCKS proxy at {args.proxy_host}:{args.proxy_port}")
    print(f"Connecting to {args.url}")
    
    try:
        start_time = time.time()
        response = urlopen(args.url)
        elapsed = time.time() - start_time
        
        print(f"Connection successful! Response time: {elapsed:.2f} seconds")
        print("Response:")
        print(response.read().decode('utf-8'))
        
        return 0
    except Exception as e:
        print(f"Connection failed: {e}")
        return 1

if __name__ == '__main__':
    sys.exit(main()) 