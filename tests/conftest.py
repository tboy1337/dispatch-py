"""
Pytest configuration and fixtures for dispatch-py tests.
"""

import asyncio
import ipaddress
import logging
import socket
import threading
from typing import List, Iterator, Any, Dict
from unittest.mock import Mock, patch

import pytest
import netifaces

from dispatch.dispatcher.base import Dispatch
from dispatch.dispatcher.weighted_rr import (
    WeightedAddress, RawWeightedAddress, Interface
)


@pytest.fixture
def event_loop() -> Iterator[asyncio.AbstractEventLoop]:
    """Create an event loop for async tests."""
    loop = asyncio.new_event_loop()
    yield loop
    loop.close()


@pytest.fixture
def mock_interfaces() -> Dict[str, Any]:  # type: ignore[explicit-any]
    """Mock network interfaces for testing."""
    return {
        'eth0': {
            netifaces.AF_INET: [
                {'addr': '192.168.1.100'}
            ],
            netifaces.AF_INET6: [
                {'addr': '2001:db8::1'}
            ]
        },
        'wlan0': {
            netifaces.AF_INET: [
                {'addr': '10.0.0.50'}
            ]
        },
        'lo': {
            netifaces.AF_INET: [
                {'addr': '127.0.0.1'}
            ],
            netifaces.AF_INET6: [
                {'addr': '::1'}
            ]
        }
    }


@pytest.fixture
def mock_netifaces(mock_interfaces: Dict[str, Any]) -> Iterator[None]:  # type: ignore[explicit-any]  # pylint: disable=redefined-outer-name
    """Mock netifaces module."""
    with patch('netifaces.interfaces') as mock_interfaces_func, \
         patch('netifaces.ifaddresses') as mock_ifaddresses:

        mock_interfaces_func.return_value = list(mock_interfaces.keys())
        mock_ifaddresses.side_effect = lambda iface: mock_interfaces.get(iface, {})

        yield


@pytest.fixture
def sample_raw_addresses() -> List[RawWeightedAddress]:
    """Sample raw weighted addresses for testing."""
    return [
        RawWeightedAddress(interface='192.168.1.100', weight=3),
        RawWeightedAddress(interface='10.0.0.50', weight=2)
    ]


@pytest.fixture
def sample_weighted_addresses() -> List[WeightedAddress]:
    """Sample weighted addresses for testing."""
    return [
        WeightedAddress(
            interface=Interface(ip=ipaddress.IPv4Address('192.168.1.100')),
            weight=3
        ),
        WeightedAddress(
            interface=Interface(ip=ipaddress.IPv4Address('10.0.0.50')),
            weight=2
        )
    ]


@pytest.fixture
def mock_dispatcher() -> Mock:
    """Mock dispatcher for testing."""
    dispatcher = Mock(spec=Dispatch)
    async def mock_dispatch(  # type: ignore[explicit-any]
        *args: Any, **kwargs: Any
    ) -> ipaddress.IPv4Address:
        return ipaddress.IPv4Address('192.168.1.100')
    dispatcher.dispatch = mock_dispatch
    return dispatcher


@pytest.fixture
def mock_socket() -> Iterator[Mock]:
    """Mock socket for testing."""
    with patch('socket.socket') as mock_sock:
        mock_instance = Mock()
        mock_instance.getsockname.return_value = ('192.168.1.100', 12345)
        mock_instance.connect.return_value = None
        mock_sock.return_value = mock_instance
        yield mock_instance


@pytest.fixture
def free_port() -> int:
    """Get a free port for testing."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(('127.0.0.1', 0))
        return sock.getsockname()[1]


@pytest.fixture
def mock_asyncio_server() -> Iterator[Mock]:
    """Mock asyncio server for testing."""
    with patch('asyncio.start_server') as mock_start:
        mock_server = Mock()  # pylint: disable=redefined-outer-name
        mock_server.sockets = [Mock()]
        mock_server.sockets[0].getsockname.return_value = ('127.0.0.1', 1080)
        async def mock_serve_forever() -> None:
            pass
        async def mock_aenter(self: Any) -> Mock:  # type: ignore[explicit-any]
            return self
        async def mock_aexit(self: Any, *args: Any) -> None:  # type: ignore[explicit-any]
            pass

        mock_server.serve_forever = mock_serve_forever
        mock_server.__aenter__ = mock_aenter
        mock_server.__aexit__ = mock_aexit

        async def mock_start_server(  # type: ignore[explicit-any]
            *args: Any, **kwargs: Any
        ) -> Mock:
            return mock_server
        mock_start.return_value = mock_start_server(*[], **{})
        yield mock_server


@pytest.fixture
def mock_stream_reader() -> Mock:
    """Mock asyncio StreamReader."""
    reader = Mock()
    async def mock_read(size: int) -> bytes:
        return b''
    async def mock_readexactly(size: int) -> bytes:
        return b'\x00' * size
    reader.read = mock_read
    reader.readexactly = mock_readexactly
    return reader


@pytest.fixture
def mock_stream_writer() -> Mock:
    """Mock asyncio StreamWriter."""
    writer = Mock()
    writer.write = Mock()
    async def mock_drain() -> None:
        pass
    writer.drain = mock_drain
    writer.close = Mock()
    async def mock_wait_closed() -> None:
        pass
    writer.wait_closed = mock_wait_closed
    writer.get_extra_info = Mock(return_value=('127.0.0.1', 12345))
    return writer


@pytest.fixture
def mock_open_connection() -> Iterator[None]:
    """Mock asyncio open_connection."""
    with patch('asyncio.open_connection') as mock_conn:
        reader = Mock()
        writer = Mock()
        writer.get_extra_info = Mock(return_value=('192.168.1.100', 80))
        async def mock_open_connection(*args: Any, **kwargs: Any) -> tuple[Mock, Mock]:  # type: ignore[explicit-any]  # pylint: disable=redefined-outer-name
            return (reader, writer)
        mock_conn.return_value = mock_open_connection(*[], **{})
        yield


class MockServer:
    """Mock TCP server for testing SOCKS connections."""

    def __init__(self, host: str = '127.0.0.1', port: int = 0) -> None:
        """Initialize mock server."""
        self.host = host
        self.port = port
        self.socket: socket.socket = None  # type: ignore
        self.thread: threading.Thread = None  # type: ignore
        self.running = False
        self.connections: List[socket.socket] = []

    def start(self) -> None:
        """Start the mock server."""
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.socket.bind((self.host, self.port))
        self.port = self.socket.getsockname()[1]  # Get actual port if 0 was used
        self.socket.listen(5)

        self.running = True
        self.thread = threading.Thread(target=self._server_loop)
        self.thread.daemon = True
        self.thread.start()

    def stop(self) -> None:
        """Stop the mock server."""
        if self.running:
            self.running = False
            if self.socket:
                self.socket.close()
            if self.thread:
                self.thread.join(timeout=1.0)

            # Close all connections
            for conn in self.connections:
                try:
                    conn.close()
                except (socket.error, OSError):
                    pass
            self.connections.clear()

    def _server_loop(self) -> None:
        """Server loop to accept connections."""
        try:
            while self.running:
                try:
                    conn, _ = self.socket.accept()  # addr not used
                    self.connections.append(conn)
                    # Echo any data received
                    threading.Thread(
                        target=self._handle_connection,
                        args=(conn,),
                        daemon=True
                    ).start()
                except OSError:
                    break
        except (socket.error, OSError):
            pass

    def _handle_connection(self, conn: socket.socket) -> None:
        """Handle a client connection."""
        try:
            while self.running:
                data = conn.recv(1024)
                if not data:
                    break
                conn.send(data)  # Echo back
        except (socket.error, OSError, ConnectionError):
            pass
        finally:
            try:
                conn.close()
            except (socket.error, OSError):
                pass


@pytest.fixture
def mock_server() -> Iterator[MockServer]:
    """Fixture providing a mock TCP server."""
    server = MockServer()
    server.start()
    try:
        yield server
    finally:
        server.stop()


@pytest.fixture(autouse=True)
def cleanup_logging() -> Iterator[None]:
    """Clean up logging handlers after each test."""
    yield
    # Remove any handlers that might have been added during tests
    root_logger = logging.getLogger()
    for handler in root_logger.handlers[:]:
        root_logger.removeHandler(handler)

    # Reset the dispatch logger
    dispatch_logger = logging.getLogger('dispatch')
    for handler in dispatch_logger.handlers[:]:
        dispatch_logger.removeHandler(handler)
