# -*- coding: utf-8 -*-
"""
SOCKS proxy package for load balancing network traffic.
"""

__version__ = "1.0.1"
__author__ = "tboy1337"

# Import key components
from .dispatcher import WeightedAddress, RawWeightedAddress
from .server import run_server
from .list import list_interfaces

__all__ = [
    "WeightedAddress",
    "RawWeightedAddress", 
    "run_server",
    "list_interfaces"
]
