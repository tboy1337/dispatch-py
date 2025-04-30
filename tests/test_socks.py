import pytest
import asyncio
import ipaddress
import socket
import struct
from unittest.mock import Mock, patch, AsyncMock, MagicMock

from dispatch.socks import (
    SocksHandshake, SocksVersionError, SocksCommandNotSupportedError,
    SocksAddressTypeNotSupportedError, SocksAuthMethodNotSupportedError,
    HostUnreachableError, SOCKS_VERSION_4, SOCKS_VERSION_5, 
    SOCKS5_AUTH_NONE, SOCKS_CMD_CONNECT, SOCKS5_ADDR_IPV4, SOCKS5_ADDR_DOMAIN,
    SOCKS5_ADDR_IPV6, SOCKS5_REPLY_SUCCESS
)

class TestSocks:
    @pytest.fixture
    def mock_dispatcher(self):
        """Mock the dispatch interface."""
        dispatcher = Mock()
        dispatcher.dispatch = AsyncMock(return_value=ipaddress.IPv4Address('192.168.1.10'))
        return dispatcher

    @pytest.fixture
    def mock_socket_creator(self):
        """Mock the socket creation function."""
        with patch('dispatch.socks.create_bound_socket') as mock_create:
            # Create the mock socket with necessary methods for async context management
            mock_socket = MagicMock()
            
            # Prepare mock reader and writer
            mock_reader = AsyncMock()
            mock_writer = AsyncMock()
            
            # Make the socket connection return the mock reader and writer
            mock_open_connection = AsyncMock(return_value=(mock_reader, mock_writer))
            
            with patch('asyncio.open_connection', mock_open_connection):
                yield mock_create, mock_reader, mock_writer
    
    @pytest.mark.asyncio
    async def test_socks5_handshake_connect(self, mock_dispatcher, mock_socket_creator):
        """Test successful SOCKS5 handshake with CONNECT command."""
        mock_create, mock_reader, mock_writer = mock_socket_creator
        
        # Create client side reader and writer
        client_reader = AsyncMock()
        client_writer = AsyncMock()
        
        # Configure client requests for SOCKS5 negotiation
        # 1. Version + Auth methods
        client_reader.readexactly.side_effect = [
            # First read: SOCKS version
            bytes([SOCKS_VERSION_5]),
            # Second read: Number of auth methods
            bytes([1]),
            # Third read: Auth methods
            bytes([SOCKS5_AUTH_NONE]),
            # Fourth read: Version + Command + Reserved + Address type
            bytes([SOCKS_VERSION_5, SOCKS_CMD_CONNECT, 0, SOCKS5_ADDR_IPV4]),
            # Fifth read: IPv4 address
            socket.inet_aton('8.8.8.8'),
            # Sixth read: Port
            struct.pack('!H', 80)
        ]
        
        # Initialize the handshake
        handshake = SocksHandshake(client_reader, client_writer, mock_dispatcher)
        
        # Run the handshake
        target_reader, target_writer = await handshake.handshake()
        
        # Verify the client writer received the correct responses
        # Check auth methods negotiation response
        client_writer.write.assert_any_call(bytes([SOCKS_VERSION_5, SOCKS5_AUTH_NONE]))
        
        # Check if we got the connect success response with the expected format
        success_response_args = client_writer.write.call_args_list[1][0][0]
        # Version, success reply, reserved, address type
        assert success_response_args[:4] == bytes([SOCKS_VERSION_5, SOCKS5_REPLY_SUCCESS, 0, SOCKS5_ADDR_IPV4])
        
        # Verify the dispatcher was called correctly
        mock_dispatcher.dispatch.assert_called_once_with(('8.8.8.8', 80))
        
        # Verify the connection was opened
        assert target_reader is mock_reader
        assert target_writer is mock_writer

    @pytest.mark.asyncio
    async def test_socks5_domain_name_resolution(self, mock_dispatcher, mock_socket_creator):
        """Test SOCKS5 handshake with domain name resolution."""
        mock_create, mock_reader, mock_writer = mock_socket_creator
        
        client_reader = AsyncMock()
        client_writer = AsyncMock()
        
        # Mock for DNS resolution
        mock_getaddrinfo = AsyncMock(return_value=[
            (socket.AF_INET, socket.SOCK_STREAM, 0, '', ('8.8.8.8', 80))
        ])
        
        # Configure client requests for SOCKS5 with domain name
        domain_name = b'example.com'
        domain_len = len(domain_name)
        
        client_reader.readexactly.side_effect = [
            bytes([SOCKS_VERSION_5]),
            bytes([1]),
            bytes([SOCKS5_AUTH_NONE]),
            bytes([SOCKS_VERSION_5, SOCKS_CMD_CONNECT, 0, SOCKS5_ADDR_DOMAIN]),
            bytes([domain_len]),  # Domain name length
            domain_name,  # Domain name
            struct.pack('!H', 80)  # Port
        ]
        
        # Initialize the handshake with patched getaddrinfo
        with patch('asyncio.get_event_loop') as mock_loop:
            mock_loop.return_value.getaddrinfo = mock_getaddrinfo
            
            handshake = SocksHandshake(client_reader, client_writer, mock_dispatcher)
            target_reader, target_writer = await handshake.handshake()
        
        # Verify the client writer received correct responses
        client_writer.write.assert_any_call(bytes([SOCKS_VERSION_5, SOCKS5_AUTH_NONE]))
        
        # DNS resolution should have been called
        mock_getaddrinfo.assert_called_once_with(
            'example.com', 80, type=socket.SOCK_STREAM
        )
        
        # Dispatcher should have been called with the resolved IP
        mock_dispatcher.dispatch.assert_called_once_with(('8.8.8.8', 80))
        
        # Connection should have been opened
        assert target_reader is mock_reader
        assert target_writer is mock_writer

    @pytest.mark.asyncio
    async def test_socks5_ipv6_address(self, mock_dispatcher, mock_socket_creator):
        """Test SOCKS5 handshake with IPv6 address."""
        mock_create, mock_reader, mock_writer = mock_socket_creator
        
        client_reader = AsyncMock()
        client_writer = AsyncMock()
        
        # Mock the dispatcher to return an IPv6 address
        mock_dispatcher.dispatch.return_value = ipaddress.IPv6Address('2001:db8::1')
        
        # Configure client requests for SOCKS5 with IPv6
        ipv6_bytes = socket.inet_pton(socket.AF_INET6, '2001:db8::2')
        
        client_reader.readexactly.side_effect = [
            bytes([SOCKS_VERSION_5]),
            bytes([1]),
            bytes([SOCKS5_AUTH_NONE]),
            bytes([SOCKS_VERSION_5, SOCKS_CMD_CONNECT, 0, SOCKS5_ADDR_IPV6]),
            ipv6_bytes,  # IPv6 address
            struct.pack('!H', 80)  # Port
        ]
        
        # Initialize the handshake
        handshake = SocksHandshake(client_reader, client_writer, mock_dispatcher)
        target_reader, target_writer = await handshake.handshake()
        
        # Verify dispatcher was called with IPv6 address
        mock_dispatcher.dispatch.assert_called_once_with(('2001:db8::2', 80))
        
        # Check if response included IPv6 address type
        success_response_args = client_writer.write.call_args_list[1][0][0]
        # Version, success reply, reserved, address type (IPv6)
        assert success_response_args[:4] == bytes([SOCKS_VERSION_5, SOCKS5_REPLY_SUCCESS, 0, SOCKS5_ADDR_IPV6])

    @pytest.mark.asyncio
    async def test_socks_version_error(self):
        """Test handling of invalid SOCKS version."""
        client_reader = AsyncMock()
        client_writer = AsyncMock()
        mock_dispatcher = Mock()
        
        # Send invalid version (e.g., 3)
        client_reader.readexactly.return_value = bytes([3])
        
        handshake = SocksHandshake(client_reader, client_writer, mock_dispatcher)
        
        with pytest.raises(SocksVersionError):
            await handshake.handshake()

    @pytest.mark.asyncio
    async def test_socks5_auth_method_not_supported(self):
        """Test handling of unsupported authentication methods."""
        client_reader = AsyncMock()
        client_writer = AsyncMock()
        mock_dispatcher = Mock()
        
        # Configure to send SOCKS5 but only with username/password auth (no AUTH_NONE)
        client_reader.readexactly.side_effect = [
            bytes([SOCKS_VERSION_5]),
            bytes([1]),
            bytes([0x02])  # Username/password auth only
        ]
        
        # Make drain awaitable
        client_writer.drain = AsyncMock()
        
        handshake = SocksHandshake(client_reader, client_writer, mock_dispatcher)
        
        with pytest.raises(SocksAuthMethodNotSupportedError):
            await handshake.handshake()
        
        # Verify the client gets the proper error response
        client_writer.write.assert_called_with(bytes([SOCKS_VERSION_5, 0xFF]))

    @pytest.mark.asyncio
    async def test_socks5_command_not_supported(self):
        """Test handling of unsupported SOCKS commands."""
        client_reader = AsyncMock()
        client_writer = AsyncMock()
        mock_dispatcher = Mock()
        
        # Configure to send SOCKS5 with BIND command (which is not supported)
        client_reader.readexactly.side_effect = [
            bytes([SOCKS_VERSION_5]),
            bytes([1]),
            bytes([SOCKS5_AUTH_NONE]),
            bytes([SOCKS_VERSION_5, 0x02, 0, SOCKS5_ADDR_IPV4])  # 0x02 = BIND
        ]
        
        # Make drain awaitable
        client_writer.drain = AsyncMock()
        
        handshake = SocksHandshake(client_reader, client_writer, mock_dispatcher)
        
        with pytest.raises(SocksCommandNotSupportedError):
            await handshake.handshake()

    @pytest.mark.asyncio
    async def test_socks5_address_type_not_supported(self):
        """Test handling of unsupported address types."""
        client_reader = AsyncMock()
        client_writer = AsyncMock()
        mock_dispatcher = Mock()
        
        # Configure to send SOCKS5 with invalid address type (e.g., 0x05)
        client_reader.readexactly.side_effect = [
            bytes([SOCKS_VERSION_5]),
            bytes([1]),
            bytes([SOCKS5_AUTH_NONE]),
            bytes([SOCKS_VERSION_5, SOCKS_CMD_CONNECT, 0, 0x05])  # 0x05 = invalid addr type
        ]
        
        # Make drain awaitable
        client_writer.drain = AsyncMock()
        
        handshake = SocksHandshake(client_reader, client_writer, mock_dispatcher)
        
        with pytest.raises(SocksAddressTypeNotSupportedError):
            await handshake.handshake() 