"""
Tests for dispatch.net module.
"""

import ipaddress
import socket
from unittest.mock import Mock, patch

import pytest

from dispatch.net import create_bound_socket, get_address_family


class TestCreateBoundSocket:
    """Tests for create_bound_socket function."""

    def test_create_ipv4_socket(self) -> None:
        """Test creating a socket bound to IPv4 address."""
        ip = ipaddress.IPv4Address('192.168.1.100')

        with patch('socket.socket') as mock_socket_class:
            mock_sock = Mock()
            mock_socket_class.return_value = mock_sock

            result = create_bound_socket(ip)

            # Verify socket creation
            mock_socket_class.assert_called_once_with(socket.AF_INET, socket.SOCK_STREAM)
            mock_sock.bind.assert_called_once_with(('192.168.1.100', 0))
            assert result is mock_sock

    def test_create_ipv6_socket(self) -> None:
        """Test creating a socket bound to IPv6 address."""
        ip = ipaddress.IPv6Address('2001:db8::1')

        with patch('socket.socket') as mock_socket_class:
            mock_sock = Mock()
            mock_socket_class.return_value = mock_sock

            result = create_bound_socket(ip)

            # Verify socket creation
            mock_socket_class.assert_called_once_with(socket.AF_INET6, socket.SOCK_STREAM)
            mock_sock.bind.assert_called_once_with(('2001:db8::1', 0))
            assert result is mock_sock

    def test_create_udp_socket(self) -> None:
        """Test creating a UDP socket."""
        ip = ipaddress.IPv4Address('10.0.0.1')

        with patch('socket.socket') as mock_socket_class:
            mock_sock = Mock()
            mock_socket_class.return_value = mock_sock

            result = create_bound_socket(ip, socket.SOCK_DGRAM)

            # Verify socket creation
            mock_socket_class.assert_called_once_with(socket.AF_INET, socket.SOCK_DGRAM)
            mock_sock.bind.assert_called_once_with(('10.0.0.1', 0))
            assert result is mock_sock

    def test_socket_binding_error(self) -> None:
        """Test handling of socket binding errors."""
        ip = ipaddress.IPv4Address('192.168.1.100')

        with patch('socket.socket') as mock_socket_class:
            mock_sock = Mock()
            mock_sock.bind.side_effect = OSError("Address already in use")
            mock_socket_class.return_value = mock_sock

            with pytest.raises(OSError, match="Address already in use"):
                create_bound_socket(ip)


class TestGetAddressFamily:
    """Tests for get_address_family function."""

    def test_ipv4_address_family(self) -> None:
        """Test getting address family for IPv4 address."""
        ip = ipaddress.IPv4Address('192.168.1.1')
        result = get_address_family(ip)
        assert result == socket.AF_INET

    def test_ipv6_address_family(self) -> None:
        """Test getting address family for IPv6 address."""
        ip = ipaddress.IPv6Address('2001:db8::1')
        result = get_address_family(ip)
        assert result == socket.AF_INET6

    def test_various_ipv4_addresses(self) -> None:
        """Test getting address family for various IPv4 addresses."""
        addresses = [
            '127.0.0.1',
            '10.0.0.1',
            '172.16.0.1',
            '192.168.0.1',
            '8.8.8.8'
        ]

        for addr_str in addresses:
            ip = ipaddress.IPv4Address(addr_str)
            result = get_address_family(ip)
            assert result == socket.AF_INET

    def test_various_ipv6_addresses(self) -> None:
        """Test getting address family for various IPv6 addresses."""
        addresses = [
            '::1',
            '2001:db8::1',
            'fe80::1',
            '::ffff:192.168.1.1',
            '2001:4860:4860::8888'
        ]

        for addr_str in addresses:
            ip = ipaddress.IPv6Address(addr_str)
            result = get_address_family(ip)
            assert result == socket.AF_INET6


class TestNetIntegration:
    """Integration tests for net module."""

    def test_socket_bind_ipv4(self) -> None:
        """Test actual socket creation and binding for IPv4 (if interface available)."""
        try:
            # Try to bind to localhost
            ip = ipaddress.IPv4Address('127.0.0.1')
            sock = create_bound_socket(ip)

            # Verify socket properties
            assert sock.family == socket.AF_INET
            assert sock.type == socket.SOCK_STREAM

            # Verify it's actually bound
            bound_addr = sock.getsockname()
            assert bound_addr[0] == '127.0.0.1'
            assert bound_addr[1] > 0  # Some port was assigned

            sock.close()

        except OSError:
            # If binding fails (e.g., no IPv4 localhost), skip the test
            pytest.skip("Cannot bind to 127.0.0.1")

    def test_socket_bind_ipv6(self) -> None:
        """Test actual socket creation and binding for IPv6 (if interface available)."""
        try:
            # Try to bind to IPv6 localhost
            ip = ipaddress.IPv6Address('::1')
            sock = create_bound_socket(ip)

            # Verify socket properties
            assert sock.family == socket.AF_INET6
            assert sock.type == socket.SOCK_STREAM

            # Verify it's actually bound
            bound_addr = sock.getsockname()
            assert bound_addr[0] == '::1'
            assert bound_addr[1] > 0  # Some port was assigned

            sock.close()

        except OSError:
            # If binding fails (e.g., no IPv6 support), skip the test
            pytest.skip("Cannot bind to ::1 (IPv6 may not be available)")

    def test_multiple_socket_creation(self) -> None:
        """Test creating multiple sockets with different ports."""
        ip = ipaddress.IPv4Address('127.0.0.1')

        try:
            sockets = []
            for _ in range(3):
                sock = create_bound_socket(ip)
                sockets.append(sock)

            # Verify all sockets have different ports
            ports = [sock.getsockname()[1] for sock in sockets]
            assert len(set(ports)) == len(ports)  # All ports should be unique

            # Clean up
            for sock in sockets:
                sock.close()

        except OSError:
            pytest.skip("Cannot create multiple sockets on 127.0.0.1")


@pytest.mark.parametrize("ip_str,expected_family", [
    ('192.168.1.1', socket.AF_INET),
    ('10.0.0.1', socket.AF_INET),
    ('127.0.0.1', socket.AF_INET),
    ('2001:db8::1', socket.AF_INET6),
    ('::1', socket.AF_INET6),
    ('fe80::1', socket.AF_INET6),
])
def test_address_family_param(ip_str: str, expected_family: int) -> None:
    """Parametrized test for address family detection."""
    ip = ipaddress.ip_address(ip_str)
    result = get_address_family(ip)
    assert result == expected_family
