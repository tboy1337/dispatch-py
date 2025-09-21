#!/usr/bin/env python3
"""
Test script for the SOCKS proxy.
"""

import argparse
import socket
import sys
import time
import urllib.error
from urllib.request import urlopen

import socks

def parse_args() -> argparse.Namespace:
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(description='Test SOCKS proxy connection')
    parser.add_argument('--proxy-host', default='127.0.0.1', help='SOCKS proxy host')
    parser.add_argument('--proxy-port', type=int, default=1080, help='SOCKS proxy port')
    parser.add_argument('--url', default='https://httpbin.org/ip', help='URL to test')
    return parser.parse_args()

def main() -> int:
    """Main entry point."""
    args = parse_args()

    # Create a SOCKS socket
    socks.set_default_proxy(socks.SOCKS5, args.proxy_host, args.proxy_port)  # type: ignore[misc]
    socket.socket = socks.socksocket  # type: ignore[misc]

    print(
        f"Testing connection through SOCKS proxy at "
        f"{args.proxy_host}:{args.proxy_port}"  # type: ignore[misc]
    )
    print(f"Connecting to {args.url}")  # type: ignore[misc]

    try:
        start_time = time.time()
        with urlopen(args.url) as response:  # type: ignore[misc]
            elapsed = time.time() - start_time

            print(f"Connection successful! Response time: {elapsed:.2f} seconds")
            print("Response:")
            print(response.read().decode('utf-8'))  # type: ignore[misc]

            return 0
    except (urllib.error.URLError, socket.error, OSError) as exception:
        print(f"Connection failed: {exception}")
        return 1

if __name__ == '__main__':
    sys.exit(main())
