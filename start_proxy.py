#!/usr/bin/env python3
"""
Simplified startup script for the SOCKS proxy.
"""

import sys
from dispatch.main import main

def _for_test():
    """Function to be called during testing"""
    main()

if __name__ == '__main__':
    sys.exit(main()) 