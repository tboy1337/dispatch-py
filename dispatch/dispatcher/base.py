"""
Base Dispatch interface.
"""

import abc
from typing import Tuple, Union
import ipaddress

class Dispatch(abc.ABC):
    """Interface for dispatchers that select a local IP address to use for outgoing connections."""

    @abc.abstractmethod
    async def dispatch(
        self, remote_address: Tuple[str, int]
    ) -> Union[ipaddress.IPv4Address, ipaddress.IPv6Address]:
        """
        Select a local IP address to use for an outgoing connection.
        
        Args:
            remote_address: A tuple of (host, port) representing the remote address
            
        Returns:
            An IP address to bind the outgoing connection to
        """
        pass
