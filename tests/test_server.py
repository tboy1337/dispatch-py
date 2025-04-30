import pytest
import asyncio
from unittest.mock import Mock, AsyncMock, patch, MagicMock
import ipaddress

from dispatch.server import pipe, handle_client, start_server, run_server
from dispatch.dispatcher.weighted_rr import WeightedAddress, Interface

class TestServer:
    @pytest.mark.asyncio
    async def test_pipe_data_flow(self):
        """Test that pipe correctly transfers data from reader to writer."""
        # Setup mock reader and writer
        reader = AsyncMock()
        writer = AsyncMock()
        
        # Configure reader to return data once then empty (end of stream)
        reader.read.side_effect = [b'test data', b'']
        
        # Run the pipe function
        await pipe(reader, writer)
        
        # Verify data was written correctly
        writer.write.assert_called_once_with(b'test data')
        writer.drain.assert_called_once()

    @pytest.mark.asyncio
    async def test_pipe_handles_connection_reset(self):
        """Test that pipe handles connection reset exceptions gracefully."""
        # Setup mock reader and writer
        reader = AsyncMock()
        writer = AsyncMock()
        
        # Make reader raise ConnectionResetError
        reader.read.side_effect = ConnectionResetError("Connection reset by peer")
        
        # Run the pipe function - should not raise an exception
        await pipe(reader, writer)
        
        # Verify no data was written
        writer.write.assert_not_called()

    @pytest.mark.asyncio
    async def test_handle_client_successful_connection(self):
        """Test that handle_client correctly processes a successful connection."""
        # Setup mocks
        client_reader = AsyncMock()
        client_writer = AsyncMock()
        client_writer.get_extra_info.return_value = ('127.0.0.1', 12345)
        
        # Create a mock dispatcher
        mock_dispatcher = AsyncMock()
        
        # Create a mock handshake
        mock_handshake = AsyncMock()
        mock_target_reader = AsyncMock()
        mock_target_writer = AsyncMock()
        mock_target_writer.get_extra_info.return_value = ('8.8.8.8', 80)
        mock_handshake.handshake.return_value = (mock_target_reader, mock_target_writer)
        
        # Patch the SocksHandshake class
        with patch('dispatch.server.SocksHandshake', return_value=mock_handshake):
            # Patch asyncio.create_task to capture the created tasks
            with patch('asyncio.create_task') as mock_create_task:
                # Patch asyncio.wait to simulate task completion
                with patch('asyncio.wait') as mock_wait:
                    # Configure wait to return completed tasks
                    mock_task1 = AsyncMock()
                    mock_task2 = AsyncMock()
                    mock_wait.return_value = ([mock_task1], [mock_task2])
                    
                    # Run the handle_client function
                    await handle_client(client_reader, client_writer, mock_dispatcher)
                    
                    # Verify SocksHandshake was created and handshake was called
                    mock_handshake.handshake.assert_called_once()
                    
                    # Verify pipes were created
                    assert mock_create_task.call_count == 2
                    
                    # Verify wait was called with the tasks
                    mock_wait.assert_called_once()
                    
                    # Verify the client connection was closed
                    client_writer.close.assert_called_once()
                    client_writer.wait_closed.assert_called_once()

    @pytest.mark.asyncio
    async def test_start_server(self):
        """Test that start_server correctly initializes and starts the server."""
        # Setup test data
        host = '127.0.0.1'
        port = 1080
        
        # Create mock addresses
        interface = Interface(ip=ipaddress.IPv4Address('192.168.1.10'))
        addresses = [WeightedAddress(interface=interface, weight=1)]
        
        # Patch asyncio.start_server
        mock_server = AsyncMock()
        mock_server.sockets = [Mock()]
        mock_server.sockets[0].getsockname.return_value = ('127.0.0.1', 1080)
        
        with patch('asyncio.start_server', return_value=mock_server):
            # Patch WeightedRoundRobinDispatcher
            with patch('dispatch.server.WeightedRoundRobinDispatcher') as mock_dispatcher_class:
                # Patch server.serve_forever to prevent the function from running indefinitely
                mock_server.serve_forever = AsyncMock(side_effect=asyncio.CancelledError)
                
                # Run start_server with expected exception
                with pytest.raises(asyncio.CancelledError):
                    await start_server(host, port, addresses)
                
                # Verify dispatcher was created
                mock_dispatcher_class.assert_called_once_with(addresses)
                
                # Verify server was started
                mock_server.__aenter__.assert_called_once()

    def test_run_server(self):
        """Test that run_server correctly calls asyncio.run with start_server."""
        # Setup test data
        host = '127.0.0.1'
        port = 1080
        
        # Create mock addresses
        interface = Interface(ip=ipaddress.IPv4Address('192.168.1.10'))
        addresses = [WeightedAddress(interface=interface, weight=1)]
        
        # Patch asyncio.run
        with patch('asyncio.run') as mock_run:
            # Mock start_server
            with patch('dispatch.server.start_server') as mock_start_server:
                # Run run_server
                run_server(host, port, addresses)
                
                # Verify asyncio.run was called
                mock_run.assert_called_once()
                
                # Verify start_server was called with the correct arguments
                mock_start_server.assert_called_once_with(host, port, addresses) 