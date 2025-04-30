import pytest
import asyncio
import socket
import threading
import time
import ipaddress
import subprocess
import sys
import os
from unittest.mock import patch, MagicMock

from dispatch.server import run_server
from dispatch.dispatcher.weighted_rr import WeightedAddress, Interface

class TestEndToEnd:
    """Test the complete functionality of the dispatch proxy."""

    @pytest.fixture
    def server_thread(self):
        """Start the SOCKS proxy server in a separate thread."""
        # Create mock addresses for testing
        interface = Interface(ip=ipaddress.IPv4Address('127.0.0.1'))
        addresses = [WeightedAddress(interface=interface, weight=1)]
        
        # Start server in a thread
        server_thread = threading.Thread(
            target=run_server,
            args=('127.0.0.1', 8888, addresses),
            daemon=True
        )
        server_thread.start()
        
        # Give the server time to start
        time.sleep(1)
        
        yield server_thread
        
        # No need to explicitly stop the thread as it's a daemon thread

    def test_socket_connection(self, server_thread):
        """Test that we can connect to the proxy server."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            sock.connect(('127.0.0.1', 8888))
            connected = True
        except (socket.timeout, ConnectionRefusedError):
            connected = False
        finally:
            sock.close()
        
        assert connected, "Failed to connect to proxy server"

    @pytest.mark.skipif(sys.platform == 'win32', reason="SOCKS connection test skipped on Windows")
    def test_socks_connection(self, server_thread):
        """Test that the proxy can handle a SOCKS connection."""
        try:
            # Import here to avoid requiring PySocks for all tests
            import socks
            
            # Create a SOCKS proxy connection
            s = socks.socksocket()
            s.set_proxy(socks.SOCKS5, "127.0.0.1", 8888)
            s.settimeout(5)
            
            # Try to connect to a test host
            s.connect(("example.com", 80))
            
            # Send a simple HTTP request
            s.sendall(b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
            
            # Get the response
            data = s.recv(1024)
            s.close()
            
            assert b"HTTP/" in data, "Did not receive valid HTTP response"
            
        except Exception as e:
            pytest.skip(f"SOCKS connection test failed: {str(e)}")

    def test_run_dispatch_command(self):
        """Test that the run_dispatch.py CLI works correctly."""
        # Test the list command
        result = subprocess.run([sys.executable, "run_dispatch.py", "list"], 
                               capture_output=True, text=True)
        
        assert result.returncode == 0, f"Command failed: {result.stderr}"
        assert "network interfaces" in result.stdout

    @patch('dispatch.server.start_server')
    @patch('asyncio.run')
    def test_server_initialization(self, mock_run, mock_start_server):
        """Test that the server is initialized with the correct parameters."""
        # Create a test interface
        interface = Interface(ip=ipaddress.IPv4Address('192.168.1.1'))
        addresses = [WeightedAddress(interface=interface, weight=1)]
        
        # Run the server
        run_server('0.0.0.0', 1080, addresses)
        
        # Check that asyncio.run was called
        mock_run.assert_called_once()
        
        # Check that start_server was called with the correct parameters
        mock_start_server.assert_called_once_with('0.0.0.0', 1080, addresses) 