import pytest
import ipaddress
import socket
from unittest.mock import patch, Mock

from dispatch.net import create_bound_socket, get_address_family

class TestNetUtilities:
    def test_get_address_family_ipv4(self):
        """Test that get_address_family returns AF_INET for IPv4 addresses."""
        # Create an IPv4 address
        ipv4 = ipaddress.IPv4Address('192.168.1.10')
        
        # Check that the address family is AF_INET
        assert get_address_family(ipv4) == socket.AF_INET
    
    def test_get_address_family_ipv6(self):
        """Test that get_address_family returns AF_INET6 for IPv6 addresses."""
        # Create an IPv6 address
        ipv6 = ipaddress.IPv6Address('2001:db8::1')
        
        # Check that the address family is AF_INET6
        assert get_address_family(ipv6) == socket.AF_INET6
    
    def test_create_bound_socket_ipv4(self):
        """Test that create_bound_socket creates and binds an IPv4 socket correctly."""
        # Create an IPv4 address
        ipv4 = ipaddress.IPv4Address('192.168.1.10')
        
        # Mock socket creation and binding
        mock_socket = Mock()
        with patch('socket.socket', return_value=mock_socket) as mock_socket_create:
            # Call create_bound_socket
            result = create_bound_socket(ipv4)
            
            # Verify socket was created with correct family and type
            mock_socket_create.assert_called_once_with(socket.AF_INET, socket.SOCK_STREAM)
            
            # Verify socket was bound to the correct address
            mock_socket.bind.assert_called_once_with(('192.168.1.10', 0))
            
            # Verify the function returned the socket
            assert result == mock_socket
    
    def test_create_bound_socket_ipv6(self):
        """Test that create_bound_socket creates and binds an IPv6 socket correctly."""
        # Create an IPv6 address
        ipv6 = ipaddress.IPv6Address('2001:db8::1')
        
        # Mock socket creation and binding
        mock_socket = Mock()
        with patch('socket.socket', return_value=mock_socket) as mock_socket_create:
            # Call create_bound_socket
            result = create_bound_socket(ipv6)
            
            # Verify socket was created with correct family and type
            mock_socket_create.assert_called_once_with(socket.AF_INET6, socket.SOCK_STREAM)
            
            # Verify socket was bound to the correct address
            mock_socket.bind.assert_called_once_with(('2001:db8::1', 0))
            
            # Verify the function returned the socket
            assert result == mock_socket
    
    def test_create_bound_socket_with_socket_type(self):
        """Test that create_bound_socket respects the socket_type parameter."""
        # Create an IPv4 address
        ipv4 = ipaddress.IPv4Address('192.168.1.10')
        
        # Mock socket creation and binding
        mock_socket = Mock()
        with patch('socket.socket', return_value=mock_socket) as mock_socket_create:
            # Call create_bound_socket with SOCK_DGRAM
            result = create_bound_socket(ipv4, socket_type=socket.SOCK_DGRAM)
            
            # Verify socket was created with correct family and type
            mock_socket_create.assert_called_once_with(socket.AF_INET, socket.SOCK_DGRAM)
            
            # Verify socket was bound to the correct address
            mock_socket.bind.assert_called_once_with(('192.168.1.10', 0))
            
            # Verify the function returned the socket
            assert result == mock_socket 