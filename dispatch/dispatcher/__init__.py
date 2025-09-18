"""
Dispatcher module for the SOCKS proxy.
"""

from .weighted_rr import (
    RawWeightedAddress,
    WeightedAddress,
    WeightedRoundRobinDispatcher
)

from .base import Dispatch

__all__ = [
    'RawWeightedAddress',
    'WeightedAddress', 
    'WeightedRoundRobinDispatcher',
    'Dispatch'
]
