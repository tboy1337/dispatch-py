"""
SOCKS protocol implementation.
"""

import asyncio
import ipaddress
import socket
import struct
from typing import Callable, Dict, List, Optional, Tuple, Union, cast
import enum
import logging

from .dispatcher import Dispatch
from .net import create_bound_socket

# Constants for SOCKS protocol
SOCKS_VERSION_4 = 4
SOCKS_VERSION_5 = 5

# SOCKS5 auth methods
SOCKS5_AUTH_NONE = 0x00
SOCKS5_AUTH_GSSAPI = 0x01
SOCKS5_AUTH_USERNAME_PASSWORD = 0x02
SOCKS5_AUTH_NO_ACCEPTABLE = 0xFF

# SOCKS commands
SOCKS_CMD_CONNECT = 0x01
SOCKS_CMD_BIND = 0x02
SOCKS_CMD_UDP_ASSOCIATE = 0x03

# SOCKS5 address types
SOCKS5_ADDR_IPV4 = 0x01
SOCKS5_ADDR_DOMAIN = 0x03
SOCKS5_ADDR_IPV6 = 0x04

# SOCKS5 reply codes
SOCKS5_REPLY_SUCCESS = 0x00
SOCKS5_REPLY_GENERAL_FAILURE = 0x01
SOCKS5_REPLY_CONNECTION_NOT_ALLOWED = 0x02
SOCKS5_REPLY_NETWORK_UNREACHABLE = 0x03
SOCKS5_REPLY_HOST_UNREACHABLE = 0x04
SOCKS5_REPLY_CONNECTION_REFUSED = 0x05
SOCKS5_REPLY_TTL_EXPIRED = 0x06
SOCKS5_REPLY_COMMAND_NOT_SUPPORTED = 0x07
SOCKS5_REPLY_ADDRESS_TYPE_NOT_SUPPORTED = 0x08

# HTTP methods for detection
HTTP_METHODS = ["GET", "HEAD", "POST", "PUT", "DELETE", "CONNECT", "OPTIONS", "TRACE", "PATCH"]

# Set up logging
logger = logging.getLogger(__name__)

class SocksError(Exception):
    """Base exception for SOCKS protocol errors."""
    pass

class SocksVersionError(SocksError):
    """Exception for SOCKS version errors."""
    def __init__(self, version_byte: int):
        self.version_byte = version_byte
        super().__init__(f"Invalid SOCKS version: {version_byte}")

class SocksCommandNotSupportedError(SocksError):
    """Exception for unsupported SOCKS commands."""
    def __init__(self, command: int, version: int):
        self.command = command
        self.version = version
        super().__init__(f"Unsupported SOCKS{version} command: {command}")

class SocksAddressTypeNotSupportedError(SocksError):
    """Exception for unsupported address types."""
    def __init__(self, addr_type: int):
        self.addr_type = addr_type
        super().__init__(f"Unsupported address type: {addr_type}")

class SocksAuthMethodNotSupportedError(SocksError):
    """Exception for unsupported authentication methods."""
    def __init__(self, methods: List[int]):
        self.methods = methods
        super().__init__(f"No supported authentication methods among: {methods}")

class HostUnreachableError(SocksError):
    """Exception for host unreachable errors."""
    def __init__(self, host: str, port: int):
        self.host = host
        self.port = port
        super().__init__(f"Host unreachable: {host}:{port}")

async def read_exact(reader: asyncio.StreamReader, n: int) -> bytes:
    """
    Read exactly n bytes from the reader.
    
    Args:
        reader: The stream reader to read from
        n: The number of bytes to read
        
    Returns:
        The bytes read
        
    Raises:
        asyncio.IncompleteReadError: If EOF is reached before n bytes are read
    """
    data = await reader.readexactly(n)
    return data

class SocksHandshake:
    """
    Handles the SOCKS protocol handshake.
    """
    
    def __init__(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter, dispatcher: Dispatch):
        """
        Initialize the SOCKS handshake.
        
        Args:
            reader: The stream reader
            writer: The stream writer
            dispatcher: The dispatcher to use for selecting local addresses
        """
        self.reader = reader
        self.writer = writer
        self.dispatcher = dispatcher
    
    async def handshake(self) -> Tuple[asyncio.StreamReader, asyncio.StreamWriter]:
        """
        Perform the SOCKS handshake.
        
        Returns:
            A tuple of (reader, writer) for the connection to the target
            
        Raises:
            SocksError: If an error occurs during the handshake
        """
        try:
            # Read the first byte to determine the SOCKS version
            version_byte = await read_exact(self.reader, 1)
            version = version_byte[0]
            
            if version == SOCKS_VERSION_5:
                return await self._handle_socks5()
            elif version == SOCKS_VERSION_4:
                return await self._handle_socks4(version_byte)
            else:
                # Could be an HTTP request, check for known HTTP methods
                if version in map(ord, 'GHPDCOT'):  # First letters of HTTP methods
                    await self._handle_http_request(version_byte)
                
                raise SocksVersionError(version)
        
        except (asyncio.IncompleteReadError, ConnectionError) as e:
            raise SocksError(f"Connection error during handshake: {e}")
    
    async def _handle_http_request(self, first_byte: bytes) -> None:
        """
        Handle a potential HTTP request (better error message).
        
        Args:
            first_byte: The first byte already read
            
        Raises:
            SocksError: With a descriptive message about HTTP requests
        """
        # Try to read more to confirm it's an HTTP request
        try:
            buffer = bytearray(first_byte)
            chunk = await self.reader.read(1024)
            buffer.extend(chunk)
            
            text = buffer.decode('utf-8', errors='replace')
            for method in HTTP_METHODS:
                if text.startswith(method):
                    raise SocksError(
                        f"Received HTTP request instead of SOCKS handshake. "
                        f"This is a SOCKS proxy, not an HTTP proxy."
                    )
        except Exception:
            # If we can't decode as text, just continue with the original error
            pass
    
    async def _handle_socks5(self) -> Tuple[asyncio.StreamReader, asyncio.StreamWriter]:
        """
        Handle a SOCKS5 handshake.
        
        Returns:
            A tuple of (reader, writer) for the connection to the target
        """
        # Read auth methods
        nmethods = (await read_exact(self.reader, 1))[0]
        methods = await read_exact(self.reader, nmethods)
        
        # Check if no auth is supported
        if SOCKS5_AUTH_NONE not in methods:
            # Send auth method not supported
            self.writer.write(bytes([SOCKS_VERSION_5, SOCKS5_AUTH_NO_ACCEPTABLE]))
            await self.writer.drain()
            raise SocksAuthMethodNotSupportedError(list(methods))
        
        # Send auth method response (no auth)
        self.writer.write(bytes([SOCKS_VERSION_5, SOCKS5_AUTH_NONE]))
        await self.writer.drain()
        
        # Read the request
        version, cmd, reserved, addr_type = struct.unpack('!BBBB', await read_exact(self.reader, 4))
        
        if version != SOCKS_VERSION_5:
            raise SocksVersionError(version)
        
        if cmd != SOCKS_CMD_CONNECT:
            # Send command not supported
            self.writer.write(bytes([
                SOCKS_VERSION_5, 
                SOCKS5_REPLY_COMMAND_NOT_SUPPORTED,
                0,  # Reserved
                SOCKS5_ADDR_IPV4,
                0, 0, 0, 0,  # IPv4 address (0.0.0.0)
                0, 0  # Port (0)
            ]))
            await self.writer.drain()
            raise SocksCommandNotSupportedError(cmd, 5)
        
        # Parse address
        host = None
        port = None
        
        if addr_type == SOCKS5_ADDR_IPV4:
            # IPv4 address
            addr_bytes = await read_exact(self.reader, 4)
            port_bytes = await read_exact(self.reader, 2)
            
            host = str(ipaddress.IPv4Address(addr_bytes))
            port = struct.unpack('!H', port_bytes)[0]
        
        elif addr_type == SOCKS5_ADDR_DOMAIN:
            # Domain name
            domain_len = (await read_exact(self.reader, 1))[0]
            domain = await read_exact(self.reader, domain_len)
            port_bytes = await read_exact(self.reader, 2)
            
            host = domain.decode('utf-8')
            port = struct.unpack('!H', port_bytes)[0]
        
        elif addr_type == SOCKS5_ADDR_IPV6:
            # IPv6 address
            addr_bytes = await read_exact(self.reader, 16)
            port_bytes = await read_exact(self.reader, 2)
            
            host = str(ipaddress.IPv6Address(addr_bytes))
            port = struct.unpack('!H', port_bytes)[0]
        
        else:
            # Send address type not supported
            self.writer.write(bytes([
                SOCKS_VERSION_5, 
                SOCKS5_REPLY_ADDRESS_TYPE_NOT_SUPPORTED,
                0,  # Reserved
                SOCKS5_ADDR_IPV4,
                0, 0, 0, 0,  # IPv4 address (0.0.0.0)
                0, 0  # Port (0)
            ]))
            await self.writer.drain()
            raise SocksAddressTypeNotSupportedError(addr_type)
        
        # Connect to the target
        try:
            # Resolve the host if it's a domain name
            remote_addr = (host, port)
            if addr_type == SOCKS5_ADDR_DOMAIN:
                try:
                    infos = await asyncio.get_event_loop().getaddrinfo(host, port, 
                                                             type=socket.SOCK_STREAM)
                    if not infos:
                        raise HostUnreachableError(host, port)
                    
                    # Get the first result
                    remote_addr = infos[0][4]
                except Exception as e:
                    # Send host unreachable
                    self.writer.write(bytes([
                        SOCKS_VERSION_5, 
                        SOCKS5_REPLY_HOST_UNREACHABLE,
                        0,  # Reserved
                        SOCKS5_ADDR_IPV4,
                        0, 0, 0, 0,  # IPv4 address (0.0.0.0)
                        0, 0  # Port (0)
                    ]))
                    await self.writer.drain()
                    raise HostUnreachableError(host, port) from e
            
            # Get local address from dispatcher
            local_addr = await self.dispatcher.dispatch(remote_addr)
            
            # Create a socket bound to the local address
            sock = create_bound_socket(local_addr)
            
            # Connect to the target
            await asyncio.get_event_loop().sock_connect(sock, remote_addr)
            
            # Convert to StreamReader/StreamWriter
            target_reader, target_writer = await asyncio.open_connection(sock=sock)
            
            # Send success response
            # We need to determine the bound address and port
            bound_addr = sock.getsockname()
            bound_host, bound_port = bound_addr
            
            reply = bytearray([SOCKS_VERSION_5, SOCKS5_REPLY_SUCCESS, 0])  # Version, status, reserved
            
            # Add the bound address
            if isinstance(local_addr, ipaddress.IPv4Address):
                reply.append(SOCKS5_ADDR_IPV4)
                reply.extend(ipaddress.IPv4Address(bound_host).packed)
            else:
                reply.append(SOCKS5_ADDR_IPV6)
                reply.extend(ipaddress.IPv6Address(bound_host).packed)
            
            # Add the bound port
            reply.extend(struct.pack('!H', bound_port))
            
            self.writer.write(reply)
            await self.writer.drain()
            
            return target_reader, target_writer
        
        except Exception as e:
            # Send general failure
            self.writer.write(bytes([
                SOCKS_VERSION_5, 
                SOCKS5_REPLY_GENERAL_FAILURE,
                0,  # Reserved
                SOCKS5_ADDR_IPV4,
                0, 0, 0, 0,  # IPv4 address (0.0.0.0)
                0, 0  # Port (0)
            ]))
            await self.writer.drain()
            raise SocksError(f"Failed to connect to target: {e}") from e
    
    async def _handle_socks4(self, version_byte: bytes) -> Tuple[asyncio.StreamReader, asyncio.StreamWriter]:
        """
        Handle a SOCKS4 handshake.
        
        Args:
            version_byte: The first byte already read
            
        Returns:
            A tuple of (reader, writer) for the connection to the target
        """
        # Read command and port
        cmd, port_hi, port_lo = struct.unpack('!BBB', await read_exact(self.reader, 3))
        port = (port_hi << 8) | port_lo
        
        if cmd != SOCKS_CMD_CONNECT:
            # Send command not supported
            self.writer.write(bytes([0, 0x5B, 0, 0, 0, 0, 0, 0]))
            await self.writer.drain()
            raise SocksCommandNotSupportedError(cmd, 4)
        
        # Read IP address
        ip_bytes = await read_exact(self.reader, 4)
        
        # Read user ID (null-terminated string)
        user_id = bytearray()
        while True:
            b = await read_exact(self.reader, 1)
            if b[0] == 0:
                break
            user_id.extend(b)
        
        # Check if this is a SOCKS4a request (IP starts with 0.0.0.X where X is non-zero)
        is_socks4a = ip_bytes[0] == 0 and ip_bytes[1] == 0 and ip_bytes[2] == 0 and ip_bytes[3] != 0
        
        host = None
        if is_socks4a:
            # Read domain name (null-terminated string)
            domain = bytearray()
            while True:
                b = await read_exact(self.reader, 1)
                if b[0] == 0:
                    break
                domain.extend(b)
            
            host = domain.decode('utf-8')
        else:
            # Use the IP address
            host = str(ipaddress.IPv4Address(ip_bytes))
        
        # Connect to the target
        try:
            # Resolve the host if it's a domain name
            remote_addr = (host, port)
            if is_socks4a:
                try:
                    infos = await asyncio.get_event_loop().getaddrinfo(host, port, type=socket.SOCK_STREAM)
                    if not infos:
                        raise HostUnreachableError(host, port)
                    
                    # Get the first result
                    remote_addr = infos[0][4]
                except Exception as e:
                    # Send request rejected or failed
                    self.writer.write(bytes([0, 0x5B, 0, 0, 0, 0, 0, 0]))
                    await self.writer.drain()
                    raise HostUnreachableError(host, port) from e
            
            # Get local address from dispatcher
            local_addr = await self.dispatcher.dispatch(remote_addr)
            
            # For SOCKS4, we only support IPv4
            if isinstance(local_addr, ipaddress.IPv6Address):
                raise SocksError("SOCKS4 only supports IPv4 addresses")
            
            # Create a socket bound to the local address
            sock = create_bound_socket(local_addr)
            
            # Connect to the target
            await asyncio.get_event_loop().sock_connect(sock, remote_addr)
            
            # Convert to StreamReader/StreamWriter
            target_reader, target_writer = await asyncio.open_connection(sock=sock)
            
            # Send success response
            self.writer.write(bytes([0, 0x5A, 0, 0, 0, 0, 0, 0]))
            await self.writer.drain()
            
            return target_reader, target_writer
        
        except Exception as e:
            # Send request rejected or failed
            self.writer.write(bytes([0, 0x5B, 0, 0, 0, 0, 0, 0]))
            await self.writer.drain()
            raise SocksError(f"Failed to connect to target: {e}") from e 