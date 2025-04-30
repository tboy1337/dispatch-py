import pytest
import asyncio
import socket
from unittest.mock import AsyncMock, patch, MagicMock
import ipaddress

from dispatch.server import pipe, handle_client
from dispatch.dispatcher.weighted_rr import WeightedAddress, Interface, WeightedRoundRobinDispatcher

class TestErrorHandling:
    """Test error handling in the dispatch proxy."""
    
    @pytest.mark.asyncio
    async def test_pipe_connection_error(self):
        """Test that pipe handles connection errors gracefully."""
        # Set up reader and writer mocks
        reader = AsyncMock()
        writer = AsyncMock()
        
        # Make reader raise ConnectionRefusedError
        reader.read.side_effect = ConnectionRefusedError("Connection refused")
        
        # Run pipe function - it should handle the error without propagating it
        await pipe(reader, writer)
        
        # Verify no write was attempted
        writer.write.assert_not_called()
    
    @pytest.mark.asyncio
    async def test_pipe_timeout(self):
        """Test that pipe handles timeout errors gracefully."""
        # Set up reader and writer mocks
        reader = AsyncMock()
        writer = AsyncMock()
        
        # Make reader raise asyncio.TimeoutError
        reader.read.side_effect = asyncio.TimeoutError("Read timed out")
        
        # Run pipe function - it should handle the error without propagating it
        await pipe(reader, writer)
        
        # Verify no write was attempted
        writer.write.assert_not_called()
    
    @pytest.mark.asyncio
    async def test_handle_client_handshake_error(self):
        """Test that handle_client handles handshake errors gracefully."""
        # Setup mocks
        client_reader = AsyncMock()
        client_writer = AsyncMock()
        client_writer.get_extra_info.return_value = ('127.0.0.1', 12345)
        
        # Create a mock dispatcher
        mock_dispatcher = AsyncMock()
        
        # Create a mock handshake that raises an exception
        mock_handshake = AsyncMock()
        mock_handshake.handshake.side_effect = ValueError("Invalid handshake data")
        
        # Patch the SocksHandshake class
        with patch('dispatch.server.SocksHandshake', return_value=mock_handshake):
            # Run handle_client which should handle the error
            await handle_client(client_reader, client_writer, mock_dispatcher)
            
            # Verify connection was closed properly
            client_writer.close.assert_called_once()
            client_writer.wait_closed.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_dispatcher_invalid_interface(self):
        """Test that dispatcher handles invalid interfaces gracefully."""
        # Create an interface with invalid IP to trigger failure
        with pytest.raises(ValueError):
            # This should fail because you can't create an IPv4Address with an invalid IP
            Interface(ip=ipaddress.IPv4Address('999.999.999.999'))
    
    @pytest.mark.asyncio
    async def test_dispatcher_empty_addresses(self):
        """Test that dispatcher handles empty address list correctly."""
        # Try to create a dispatcher with no addresses
        with pytest.raises(ValueError):
            WeightedRoundRobinDispatcher([])
    
    @pytest.mark.asyncio
    async def test_client_disconnect_during_handshake(self):
        """Test handling a client disconnecting during handshake."""
        # Setup mocks
        client_reader = AsyncMock()
        client_writer = AsyncMock()
        client_writer.get_extra_info.return_value = ('127.0.0.1', 12345)
        
        # Make reader return empty data to simulate disconnect
        client_reader.read.return_value = b''
        
        # Create a mock dispatcher
        mock_dispatcher = AsyncMock()
        
        # Patch the SocksHandshake class to use our reader/writer
        mock_handshake = MagicMock()
        mock_handshake.handshake = AsyncMock()
        mock_handshake.handshake.side_effect = ConnectionResetError("Client disconnected")
        
        with patch('dispatch.server.SocksHandshake', return_value=mock_handshake):
            # Run handle_client which should handle the error
            await handle_client(client_reader, client_writer, mock_dispatcher)
            
            # Verify connection was closed properly
            client_writer.close.assert_called_once()
            client_writer.wait_closed.assert_called_once() 