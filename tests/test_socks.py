"""
Tests for dispatch.socks module.
"""

import asyncio
import ipaddress
import socket
import struct
from unittest.mock import Mock, patch, AsyncMock

import pytest

from dispatch.socks import (
    SocksHandshake,
    SocksError,
    SocksVersionError,
    SocksCommandNotSupportedError,
    SocksAddressTypeNotSupportedError,
    SocksAuthMethodNotSupportedError,
    HostUnreachableError,
    read_exact,
    SOCKS_VERSION_4,
    SOCKS_VERSION_5,
    SOCKS5_AUTH_NONE,
    SOCKS5_AUTH_NO_ACCEPTABLE,
    SOCKS_CMD_CONNECT,
    SOCKS_CMD_BIND,
    SOCKS5_ADDR_IPV4,
    SOCKS5_ADDR_DOMAIN,
    SOCKS5_ADDR_IPV6,
    SOCKS5_REPLY_SUCCESS,
    SOCKS5_REPLY_COMMAND_NOT_SUPPORTED,
    SOCKS5_REPLY_ADDRESS_TYPE_NOT_SUPPORTED,
    SOCKS5_REPLY_HOST_UNREACHABLE,
    SOCKS5_REPLY_GENERAL_FAILURE
)


class TestSocksError:
    """Tests for SOCKS exception classes."""

    def test_socks_error_base(self) -> None:
        """Test basic SocksError."""
        error = SocksError("Test error")
        assert str(error) == "Test error"
        assert isinstance(error, Exception)

    def test_socks_version_error(self) -> None:
        """Test SocksVersionError."""
        error = SocksVersionError(6)
        assert error.version_byte == 6
        assert "Invalid SOCKS version: 6" in str(error)

    def test_socks_command_not_supported_error(self) -> None:
        """Test SocksCommandNotSupportedError."""
        error = SocksCommandNotSupportedError(2, 5)
        assert error.command == 2
        assert error.version == 5
        assert "Unsupported SOCKS5 command: 2" in str(error)

    def test_socks_address_type_not_supported_error(self) -> None:
        """Test SocksAddressTypeNotSupportedError."""
        error = SocksAddressTypeNotSupportedError(5)
        assert error.addr_type == 5
        assert "Unsupported address type: 5" in str(error)

    def test_socks_auth_method_not_supported_error(self) -> None:
        """Test SocksAuthMethodNotSupportedError."""
        methods = [1, 2, 3]
        error = SocksAuthMethodNotSupportedError(methods)
        assert error.methods == methods
        assert "No supported authentication methods among: [1, 2, 3]" in str(error)

    def test_host_unreachable_error(self) -> None:
        """Test HostUnreachableError."""
        error = HostUnreachableError("example.com", 80)
        assert error.host == "example.com"
        assert error.port == 80
        assert "Host unreachable: example.com:80" in str(error)


class TestReadExact:
    """Tests for read_exact function."""

    @pytest.mark.asyncio
    async def test_read_exact_success(self) -> None:
        """Test reading exact number of bytes successfully."""
        reader = Mock()
        reader.readexactly = AsyncMock(return_value=b"hello")

        result = await read_exact(reader, 5)

        assert result == b"hello"
        reader.readexactly.assert_called_once_with(5)

    @pytest.mark.asyncio
    async def test_read_exact_incomplete_read_error(self) -> None:
        """Test handling of IncompleteReadError."""
        reader = Mock()
        reader.readexactly = AsyncMock(side_effect=asyncio.IncompleteReadError(b"hi", 5))

        with pytest.raises(asyncio.IncompleteReadError):
            await read_exact(reader, 5)


class TestSocksHandshake:
    """Tests for SocksHandshake class."""

    def setup_method(self) -> None:
        """Set up test fixtures."""
        self.reader = Mock()  # pylint: disable=attribute-defined-outside-init
        self.writer = Mock()  # pylint: disable=attribute-defined-outside-init
        self.writer.write = Mock()
        self.writer.drain = AsyncMock()
        self.dispatcher = Mock()  # pylint: disable=attribute-defined-outside-init
        self.dispatcher.dispatch = AsyncMock(return_value=ipaddress.IPv4Address('192.168.1.100'))

        self.handshake = SocksHandshake(self.reader, self.writer, self.dispatcher)  # pylint: disable=attribute-defined-outside-init

    @pytest.mark.asyncio
    async def test_handshake_socks5_success(self) -> None:
        """Test successful SOCKS5 handshake."""
        # Mock the handshake sequence
        self.reader.readexactly = AsyncMock(side_effect=[
            b'\x05',  # SOCKS version 5
            b'\x01',  # 1 auth method
            b'\x00',  # No auth
            # SOCKS5 request
            struct.pack('!BBBB', 5, 1, 0, 1),  # Version, Connect, Reserved, IPv4
            b'\xc0\xa8\x01\x64',  # IP 192.168.1.100
            b'\x00\x50'  # Port 80
        ])

        # Mock socket creation and connection
        with patch('dispatch.socks.create_bound_socket') as mock_create_socket, \
             patch('asyncio.get_event_loop') as mock_loop, \
             patch('asyncio.open_connection') as mock_open_conn:

            mock_socket = Mock()
            mock_socket.getsockname.return_value = ('192.168.1.100', 12345)
            mock_create_socket.return_value = mock_socket

            mock_loop.return_value.sock_connect = AsyncMock()

            target_reader = Mock()
            target_writer = Mock()
            mock_open_conn.return_value = (target_reader, target_writer)

            result = await self.handshake.handshake()

            assert result == (target_reader, target_writer)

            # Verify responses were sent
            assert self.writer.write.call_count >= 2  # Auth response + success response

    @pytest.mark.asyncio
    async def test_handshake_socks4_success(self) -> None:
        """Test successful SOCKS4 handshake."""
        self.reader.readexactly = AsyncMock(side_effect=[
            b'\x04',  # SOCKS version 4
            b'\x01\x00\x50',  # Connect command, port 80
            b'\xc0\xa8\x01\x64',  # IP 192.168.1.100
            b'\x00'  # Empty user ID
        ])

        with patch('dispatch.socks.create_bound_socket') as mock_create_socket, \
             patch('asyncio.get_event_loop') as mock_loop, \
             patch('asyncio.open_connection') as mock_open_conn:

            mock_socket = Mock()
            mock_socket.getsockname.return_value = ('192.168.1.100', 12345)
            mock_create_socket.return_value = mock_socket

            mock_loop.return_value.sock_connect = AsyncMock()

            target_reader = Mock()
            target_writer = Mock()
            mock_open_conn.return_value = (target_reader, target_writer)

            result = await self.handshake.handshake()

            assert result == (target_reader, target_writer)

    @pytest.mark.asyncio
    async def test_handshake_invalid_version(self) -> None:
        """Test handshake with invalid SOCKS version."""
        self.reader.readexactly = AsyncMock(return_value=b'\x06')  # Invalid version

        with pytest.raises(SocksVersionError, match="Invalid SOCKS version: 6"):
            await self.handshake.handshake()

    @pytest.mark.asyncio
    async def test_handshake_http_request_detection(self) -> None:
        """Test detection of HTTP request instead of SOCKS."""
        self.reader.readexactly = AsyncMock(return_value=b'G')  # Start of GET
        self.reader.read = AsyncMock(return_value=b'ET / HTTP/1.1\r\n')

        with pytest.raises(
            SocksError,
            match="Received HTTP request instead of SOCKS handshake|Invalid SOCKS version"
        ):
            await self.handshake.handshake()

    @pytest.mark.asyncio
    async def test_handshake_connection_error(self) -> None:
        """Test handshake connection error."""
        self.reader.readexactly = AsyncMock(side_effect=ConnectionError("Connection lost"))

        with pytest.raises(SocksError, match="Connection error during handshake"):
            await self.handshake.handshake()

    @pytest.mark.asyncio
    async def test_socks5_unsupported_auth_method(self) -> None:
        """Test SOCKS5 with unsupported auth method."""
        self.reader.readexactly = AsyncMock(side_effect=[
            b'\x05',  # SOCKS version 5
            b'\x01',  # 1 auth method
            b'\x02',  # Username/password auth (not supported)
        ])

        with pytest.raises(SocksAuthMethodNotSupportedError):
            await self.handshake.handshake()

        # Should have sent "no acceptable methods" response
        self.writer.write.assert_called_with(bytes([SOCKS_VERSION_5, SOCKS5_AUTH_NO_ACCEPTABLE]))

    @pytest.mark.asyncio
    async def test_socks5_unsupported_command(self) -> None:
        """Test SOCKS5 with unsupported command."""
        self.reader.readexactly = AsyncMock(side_effect=[
            b'\x05',  # SOCKS version 5
            b'\x01',  # 1 auth method
            b'\x00',  # No auth
            struct.pack('!BBBB', 5, 2, 0, 1),  # Version, Bind (unsupported), Reserved, IPv4
        ])

        with pytest.raises(SocksCommandNotSupportedError):
            await self.handshake.handshake()

    @pytest.mark.asyncio
    async def test_socks5_unsupported_address_type(self) -> None:
        """Test SOCKS5 with unsupported address type."""
        self.reader.readexactly = AsyncMock(side_effect=[
            b'\x05',  # SOCKS version 5
            b'\x01',  # 1 auth method
            b'\x00',  # No auth
            struct.pack('!BBBB', 5, 1, 0, 5),  # Version, Connect, Reserved, Invalid addr type
        ])

        with pytest.raises(SocksAddressTypeNotSupportedError):
            await self.handshake.handshake()

    @pytest.mark.asyncio
    async def test_socks5_domain_name_resolution(self) -> None:
        """Test SOCKS5 with domain name."""
        domain = b'example.com'
        self.reader.readexactly = AsyncMock(side_effect=[
            b'\x05',  # SOCKS version 5
            b'\x01',  # 1 auth method
            b'\x00',  # No auth
            struct.pack('!BBBB', 5, 1, 0, 3),  # Version, Connect, Reserved, Domain
            bytes([len(domain)]),  # Domain length
            domain,  # Domain name
            b'\x00\x50'  # Port 80
        ])

        with patch('asyncio.get_event_loop') as mock_loop, \
             patch('dispatch.socks.create_bound_socket') as mock_create_socket, \
             patch('asyncio.open_connection') as mock_open_conn:

            # Mock domain resolution
            mock_loop.return_value.getaddrinfo = AsyncMock(return_value=[
                (socket.AF_INET, socket.SOCK_STREAM, 6, '', ('192.168.1.50', 80))
            ])
            mock_loop.return_value.sock_connect = AsyncMock()

            mock_socket = Mock()
            mock_socket.getsockname.return_value = ('192.168.1.100', 12345)
            mock_create_socket.return_value = mock_socket

            target_reader = Mock()
            target_writer = Mock()
            mock_open_conn.return_value = (target_reader, target_writer)

            result = await self.handshake.handshake()

            assert result == (target_reader, target_writer)
            mock_loop.return_value.getaddrinfo.assert_called_once_with(
                'example.com', 80, type=socket.SOCK_STREAM
            )

    @pytest.mark.asyncio
    async def test_socks5_domain_resolution_failure(self) -> None:
        """Test SOCKS5 domain resolution failure."""
        domain = b'nonexistent.example'
        self.reader.readexactly = AsyncMock(side_effect=[
            b'\x05',  # SOCKS version 5
            b'\x01',  # 1 auth method
            b'\x00',  # No auth
            struct.pack('!BBBB', 5, 1, 0, 3),  # Version, Connect, Reserved, Domain
            bytes([len(domain)]),  # Domain length
            domain,  # Domain name
            b'\x00\x50'  # Port 80
        ])

        with patch('asyncio.get_event_loop') as mock_loop:
            mock_loop.return_value.getaddrinfo = AsyncMock(
                side_effect=Exception("Resolution failed")
            )

            with pytest.raises(HostUnreachableError):
                await self.handshake.handshake()

            # Should have sent host unreachable response
            expected_response = bytes([
                SOCKS_VERSION_5,
                SOCKS5_REPLY_HOST_UNREACHABLE,
                0,  # Reserved
                SOCKS5_ADDR_IPV4,
                0, 0, 0, 0,  # IPv4 address (0.0.0.0)
                0, 0  # Port (0)
            ])
            self.writer.write.assert_called_with(expected_response)

    @pytest.mark.asyncio
    async def test_socks5_ipv6_address(self) -> None:
        """Test SOCKS5 with IPv6 address."""
        ipv6_addr = ipaddress.IPv6Address('2001:db8::1')
        self.reader.readexactly = AsyncMock(side_effect=[
            b'\x05',  # SOCKS version 5
            b'\x01',  # 1 auth method
            b'\x00',  # No auth
            struct.pack('!BBBB', 5, 1, 0, 4),  # Version, Connect, Reserved, IPv6
            ipv6_addr.packed,  # IPv6 address
            b'\x00\x50'  # Port 80
        ])

        # Configure dispatcher to return IPv6 address
        self.dispatcher.dispatch = AsyncMock(return_value=ipaddress.IPv6Address('2001:db8::100'))

        with patch('dispatch.socks.create_bound_socket') as mock_create_socket, \
             patch('asyncio.get_event_loop') as mock_loop, \
             patch('asyncio.open_connection') as mock_open_conn:

            mock_socket = Mock()
            mock_socket.getsockname.return_value = ('2001:db8::100', 12345)
            mock_create_socket.return_value = mock_socket

            mock_loop.return_value.sock_connect = AsyncMock()

            target_reader = Mock()
            target_writer = Mock()
            mock_open_conn.return_value = (target_reader, target_writer)

            result = await self.handshake.handshake()

            assert result == (target_reader, target_writer)

    @pytest.mark.asyncio
    async def test_socks5_connection_failure(self) -> None:
        """Test SOCKS5 connection failure."""
        self.reader.readexactly = AsyncMock(side_effect=[
            b'\x05',  # SOCKS version 5
            b'\x01',  # 1 auth method
            b'\x00',  # No auth
            struct.pack('!BBBB', 5, 1, 0, 1),  # Version, Connect, Reserved, IPv4
            b'\xc0\xa8\x01\x64',  # IP 192.168.1.100
            b'\x00\x50'  # Port 80
        ])

        with patch('dispatch.socks.create_bound_socket') as mock_create_socket, \
             patch('asyncio.get_event_loop') as mock_loop:

            mock_socket = Mock()
            mock_create_socket.return_value = mock_socket

            # Mock connection failure
            mock_loop.return_value.sock_connect = AsyncMock(
                side_effect=OSError("Connection refused")
            )

            with pytest.raises(SocksError, match="Failed to connect to target"):
                await self.handshake.handshake()

    @pytest.mark.asyncio
    async def test_socks4_unsupported_command(self) -> None:
        """Test SOCKS4 with unsupported command."""
        self.reader.readexactly = AsyncMock(side_effect=[
            b'\x04',  # SOCKS version 4
            b'\x02\x00\x50',  # Bind command (unsupported), port 80
        ])

        with pytest.raises(SocksCommandNotSupportedError):
            await self.handshake.handshake()

        # Should have sent rejection response
        self.writer.write.assert_called_with(bytes([0, 0x5B, 0, 0, 0, 0, 0, 0]))

    @pytest.mark.asyncio
    async def test_socks4a_domain_name(self) -> None:
        """Test SOCKS4a with domain name."""
        domain = b'example.com'
        self.reader.readexactly = AsyncMock(side_effect=[
            b'\x04',  # SOCKS version 4
            b'\x01\x00\x50',  # Connect command, port 80
            b'\x00\x00\x00\x01',  # SOCKS4a marker IP (0.0.0.1)
            b'\x00',  # Empty user ID
            domain,  # Domain name
            b'\x00'  # Domain null terminator
        ])

        with patch('asyncio.get_event_loop') as mock_loop, \
             patch('dispatch.socks.create_bound_socket') as mock_create_socket, \
             patch('asyncio.open_connection') as mock_open_conn:

            # Mock domain resolution
            mock_loop.return_value.getaddrinfo = AsyncMock(return_value=[
                (socket.AF_INET, socket.SOCK_STREAM, 6, '', ('192.168.1.50', 80))
            ])
            mock_loop.return_value.sock_connect = AsyncMock()

            mock_socket = Mock()
            mock_socket.getsockname.return_value = ('192.168.1.100', 12345)
            mock_create_socket.return_value = mock_socket

            target_reader = Mock()
            target_writer = Mock()
            mock_open_conn.return_value = (target_reader, target_writer)

            result = await self.handshake.handshake()

            assert result == (target_reader, target_writer)

    @pytest.mark.asyncio
    async def test_socks4_ipv6_error(self) -> None:
        """Test that SOCKS4 with IPv6 dispatcher raises error."""
        self.reader.readexactly = AsyncMock(side_effect=[
            b'\x04',  # SOCKS version 4
            b'\x01\x00\x50',  # Connect command, port 80
            b'\xc0\xa8\x01\x64',  # IP 192.168.1.100
            b'\x00'  # Empty user ID
        ])

        # Configure dispatcher to return IPv6 (not supported in SOCKS4)
        self.dispatcher.dispatch = AsyncMock(return_value=ipaddress.IPv6Address('2001:db8::1'))

        with pytest.raises(SocksError, match="SOCKS4 only supports IPv4 addresses"):
            await self.handshake.handshake()

    @pytest.mark.asyncio
    async def test_socks4_connection_failure(self) -> None:
        """Test SOCKS4 connection failure."""
        self.reader.readexactly = AsyncMock(side_effect=[
            b'\x04',  # SOCKS version 4
            b'\x01\x00\x50',  # Connect command, port 80
            b'\xc0\xa8\x01\x64',  # IP 192.168.1.100
            b'\x00'  # Empty user ID
        ])

        with patch('dispatch.socks.create_bound_socket') as mock_create_socket, \
             patch('asyncio.get_event_loop') as mock_loop:

            mock_socket = Mock()
            mock_create_socket.return_value = mock_socket

            # Mock connection failure
            mock_loop.return_value.sock_connect = AsyncMock(
                side_effect=OSError("Connection refused")
            )

            with pytest.raises(SocksError, match="Failed to connect to target"):
                await self.handshake.handshake()

    @pytest.mark.asyncio
    async def test_socks4a_resolution_failure(self) -> None:
        """Test SOCKS4a domain resolution failure."""
        domain = b'nonexistent.example'
        self.reader.readexactly = AsyncMock(side_effect=[
            b'\x04',  # SOCKS version 4
            b'\x01\x00\x50',  # Connect command, port 80
            b'\x00\x00\x00\x01',  # SOCKS4a marker IP (0.0.0.1)
            b'\x00',  # Empty user ID
            domain,  # Domain name
            b'\x00'  # Domain null terminator
        ])

        with patch('asyncio.get_event_loop') as mock_loop:
            mock_loop.return_value.getaddrinfo = AsyncMock(
                side_effect=Exception("Resolution failed")
            )

            with pytest.raises(SocksError, match="Failed to connect to target"):
                await self.handshake.handshake()

            # Should have sent rejection response
            self.writer.write.assert_called_with(bytes([0, 0x5B, 0, 0, 0, 0, 0, 0]))


class TestSocksConstants:
    """Tests for SOCKS protocol constants."""

    def test_socks_versions(self) -> None:
        """Test SOCKS version constants."""
        assert SOCKS_VERSION_4 == 4
        assert SOCKS_VERSION_5 == 5

    def test_socks5_auth_methods(self) -> None:
        """Test SOCKS5 authentication method constants."""
        assert SOCKS5_AUTH_NONE == 0x00
        assert SOCKS5_AUTH_NO_ACCEPTABLE == 0xFF

    def test_socks_commands(self) -> None:
        """Test SOCKS command constants."""
        assert SOCKS_CMD_CONNECT == 0x01
        assert SOCKS_CMD_BIND == 0x02

    def test_socks5_address_types(self) -> None:
        """Test SOCKS5 address type constants."""
        assert SOCKS5_ADDR_IPV4 == 0x01
        assert SOCKS5_ADDR_DOMAIN == 0x03
        assert SOCKS5_ADDR_IPV6 == 0x04

    def test_socks5_reply_codes(self) -> None:
        """Test SOCKS5 reply code constants."""
        assert SOCKS5_REPLY_SUCCESS == 0x00
        assert SOCKS5_REPLY_COMMAND_NOT_SUPPORTED == 0x07
        assert SOCKS5_REPLY_ADDRESS_TYPE_NOT_SUPPORTED == 0x08
        assert SOCKS5_REPLY_HOST_UNREACHABLE == 0x04
        assert SOCKS5_REPLY_GENERAL_FAILURE == 0x01


class TestSocksIntegration:
    """Integration tests for SOCKS protocol handling."""

    @pytest.mark.asyncio
    async def test_complete_socks5_flow(self) -> None:
        """Test complete SOCKS5 connection flow."""
        reader = Mock()
        writer = Mock()
        writer.write = Mock()
        writer.drain = AsyncMock()

        dispatcher = Mock()
        dispatcher.dispatch = AsyncMock(return_value=ipaddress.IPv4Address('192.168.1.100'))

        # Create handshake handler
        handshake = SocksHandshake(reader, writer, dispatcher)

        # Mock complete SOCKS5 handshake sequence
        reader.readexactly = AsyncMock(side_effect=[
            b'\x05',  # SOCKS version 5
            b'\x01',  # 1 auth method
            b'\x00',  # No auth
            struct.pack('!BBBB', 5, 1, 0, 3),  # Version, Connect, Reserved, Domain
            b'\x0b',  # Domain length (11)
            b'example.com',  # Domain name
            b'\x00\x50'  # Port 80
        ])

        with patch('asyncio.get_event_loop') as mock_loop, \
             patch('dispatch.socks.create_bound_socket') as mock_create_socket, \
             patch('asyncio.open_connection') as mock_open_conn:

            # Mock successful domain resolution
            mock_loop.return_value.getaddrinfo = AsyncMock(return_value=[
                (socket.AF_INET, socket.SOCK_STREAM, 6, '', ('93.184.216.34', 80))
            ])
            mock_loop.return_value.sock_connect = AsyncMock()

            mock_socket = Mock()
            mock_socket.getsockname.return_value = ('192.168.1.100', 12345)
            mock_create_socket.return_value = mock_socket

            target_reader = Mock()
            target_writer = Mock()
            mock_open_conn.return_value = (target_reader, target_writer)

            # Perform handshake
            result = await handshake.handshake()

            # Verify results
            assert result == (target_reader, target_writer)

            # Verify dispatcher was called (may be called multiple times during resolution)
            assert dispatcher.dispatch.call_count >= 1
            # Check that it was called with the resolved address
            dispatcher.dispatch.assert_any_call(('93.184.216.34', 80))

            # Verify auth response was sent
            auth_response_call = writer.write.call_args_list[0]
            assert auth_response_call[0][0] == bytes([SOCKS_VERSION_5, SOCKS5_AUTH_NONE])

            # Verify success response was sent
            success_response_call = writer.write.call_args_list[1]
            success_response = success_response_call[0][0]
            assert success_response[0] == SOCKS_VERSION_5
            assert success_response[1] == SOCKS5_REPLY_SUCCESS
