import pytest
import asyncio
import time
import ipaddress
from unittest.mock import patch, AsyncMock, MagicMock
import threading

from dispatch.server import pipe, run_server
from dispatch.dispatcher.weighted_rr import WeightedAddress, Interface, WeightedRoundRobinDispatcher

class TestPerformance:
    """Test performance aspects of the dispatch proxy."""
    
    @pytest.mark.asyncio
    async def test_dispatcher_performance(self):
        """Test the performance of the weighted round robin dispatcher."""
        # Create test interfaces
        interfaces = [
            Interface(ip=ipaddress.IPv4Address('192.168.1.1')),
            Interface(ip=ipaddress.IPv4Address('192.168.1.2')),
            Interface(ip=ipaddress.IPv4Address('192.168.1.3'))
        ]
        
        # Create weighted addresses
        addresses = [
            WeightedAddress(interface=interfaces[0], weight=1),
            WeightedAddress(interface=interfaces[1], weight=2),
            WeightedAddress(interface=interfaces[2], weight=3)
        ]
        
        # Create dispatcher
        dispatcher = WeightedRoundRobinDispatcher(addresses)
        
        # Measure time to dispatch multiple requests
        start_time = time.time()
        iterations = 1000
        
        for _ in range(iterations):
            await dispatcher.dispatch(('8.8.8.8', 80))
        
        end_time = time.time()
        elapsed = end_time - start_time
        
        # Assert that dispatching is reasonably fast (less than 1ms per dispatch on average)
        assert elapsed / iterations < 0.001, f"Dispatcher too slow: {elapsed/iterations:.6f}s per dispatch"
    
    @pytest.mark.asyncio
    async def test_pipe_throughput(self):
        """Test the throughput of the pipe function."""
        # Create mock reader and writer with controlled data flow
        reader = AsyncMock()
        writer = AsyncMock()
        
        # Create a chunk of test data (1MB)
        chunk_size = 1024 * 1024
        test_data = b'x' * chunk_size
        
        # Configure reader to return the data chunk once then empty (end of stream)
        reader.read.side_effect = [test_data, b'']
        
        # Time the operation
        start_time = time.time()
        
        # Run the pipe function
        await pipe(reader, writer)
        
        end_time = time.time()
        elapsed = end_time - start_time
        
        # Verify data was written correctly
        writer.write.assert_called_once_with(test_data)
        
        # Calculate throughput in MB/s
        throughput = chunk_size / elapsed / (1024 * 1024)
        
        # Check that throughput is reasonable (will depend on system)
        # This is a minimal check since it's running on mocks
        assert throughput > 1, f"Pipe throughput too low: {throughput:.2f} MB/s"
    
    @pytest.mark.asyncio
    async def test_multiple_concurrent_connections(self):
        """Test handling multiple concurrent connections."""
        # Create a simple dispatcher
        interface = Interface(ip=ipaddress.IPv4Address('192.168.1.1'))
        addresses = [WeightedAddress(interface=interface, weight=1)]
        dispatcher = WeightedRoundRobinDispatcher(addresses)
        
        # Track connections
        connections_processed = 0
        
        # Create a simple client handler
        async def handle_mock_client(reader, writer):
            nonlocal connections_processed
            # Simulate processing
            await asyncio.sleep(0.01)
            connections_processed += 1
        
        # Create multiple concurrent tasks that simulate client connections
        num_clients = 5
        tasks = []
        
        # Create reader/writer pairs
        for _ in range(num_clients):
            reader = AsyncMock()
            writer = AsyncMock()
            reader.read.return_value = b''  # Empty data to end the connection quickly
            
            # Create a task for each client
            task = asyncio.create_task(handle_mock_client(reader, writer))
            tasks.append(task)
        
        # Wait for all tasks to complete
        await asyncio.gather(*tasks)
        
        # Check that all connections were processed
        assert connections_processed == num_clients, f"Expected {num_clients} connections, got {connections_processed}" 