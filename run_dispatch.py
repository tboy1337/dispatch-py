#!/usr/bin/env python3
"""
Launcher script for the Dispatch SOCKS proxy.
"""

import os
import sys

# Add the current directory to the path so we can import the package
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

try:
    from dispatch.main import main
    if __name__ == '__main__':
        main()

except ImportError as exc:
    print(f"Error importing dispatch: {exc}")
    print("\nPlease install the required dependencies:")
    print("pip install -r requirements.txt")
    sys.exit(1)
