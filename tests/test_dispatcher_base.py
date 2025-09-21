"""
Tests for dispatch.dispatcher.base module.
"""

import abc
import asyncio
import ipaddress
from typing import Tuple, Union
import pytest

from dispatch.dispatcher.base import Dispatch


class ConcreteDispatch(Dispatch):
    """Concrete implementation of Dispatch for testing."""

    def __init__(self, ip_address: Union[ipaddress.IPv4Address, ipaddress.IPv6Address]) -> None:
        """Initialize with a fixed IP address."""
        self.ip_address = ip_address
        self.dispatch_count = 0

    async def dispatch(
        self, remote_address: Tuple[str, int]
    ) -> Union[ipaddress.IPv4Address, ipaddress.IPv6Address]:
        """Return the configured IP address."""
        self.dispatch_count += 1
        return self.ip_address


class TestDispatchInterface:
    """Tests for the Dispatch abstract base class."""

    def test_dispatch_is_abstract(self) -> None:
        """Test that Dispatch class is abstract and cannot be instantiated."""
        with pytest.raises(TypeError, match="Can't instantiate abstract class"):
            Dispatch()  # type: ignore  # pylint: disable=abstract-class-instantiated

    def test_dispatch_method_is_abstract(self) -> None:
        """Test that dispatch method is abstract."""
        assert hasattr(Dispatch.dispatch, '__isabstractmethod__')
        assert Dispatch.dispatch.__isabstractmethod__ is True  # pylint: disable=no-member

    def test_concrete_implementation(self) -> None:
        """Test that concrete implementation can be instantiated."""
        ip = ipaddress.IPv4Address('192.168.1.100')
        dispatcher = ConcreteDispatch(ip)
        assert isinstance(dispatcher, Dispatch)

    @pytest.mark.asyncio
    async def test_concrete_dispatch_method(self) -> None:
        """Test that concrete dispatch method works correctly."""
        ip = ipaddress.IPv4Address('192.168.1.100')
        dispatcher = ConcreteDispatch(ip)

        result = await dispatcher.dispatch(('example.com', 80))
        assert result == ip
        assert dispatcher.dispatch_count == 1

    @pytest.mark.asyncio
    async def test_dispatch_with_different_addresses(self) -> None:
        """Test dispatch with different remote addresses."""
        ip = ipaddress.IPv6Address('2001:db8::1')
        dispatcher = ConcreteDispatch(ip)

        test_addresses = [
            ('example.com', 80),
            ('google.com', 443),
            ('192.168.1.1', 22),
            ('2001:db8::2', 8080)
        ]

        for addr in test_addresses:
            result = await dispatcher.dispatch(addr)
            assert result == ip

        assert dispatcher.dispatch_count == len(test_addresses)

    def test_abc_registration(self) -> None:
        """Test that ABC registration works correctly."""
        assert abc.ABC in Dispatch.__mro__
        assert len(Dispatch.__abstractmethods__) == 1
        assert 'dispatch' in Dispatch.__abstractmethods__


class FailingDispatch(Dispatch):
    """Dispatcher that raises exceptions for testing error handling."""

    def __init__(self, exception_to_raise: Exception) -> None:
        """Initialize with exception to raise."""
        self.exception_to_raise = exception_to_raise

    async def dispatch(
        self, remote_address: Tuple[str, int]
    ) -> Union[ipaddress.IPv4Address, ipaddress.IPv6Address]:
        """Raise the configured exception."""
        raise self.exception_to_raise


class TestDispatchErrorHandling:
    """Tests for error handling in dispatch implementations."""

    @pytest.mark.asyncio
    async def test_dispatch_raises_value_error(self) -> None:
        """Test dispatch implementation that raises ValueError."""
        dispatcher = FailingDispatch(ValueError("No addresses available"))

        with pytest.raises(ValueError, match="No addresses available"):
            await dispatcher.dispatch(('example.com', 80))

    @pytest.mark.asyncio
    async def test_dispatch_raises_runtime_error(self) -> None:
        """Test dispatch implementation that raises RuntimeError."""
        dispatcher = FailingDispatch(RuntimeError("Network error"))

        with pytest.raises(RuntimeError, match="Network error"):
            await dispatcher.dispatch(('example.com', 80))

    @pytest.mark.asyncio
    async def test_dispatch_raises_connection_error(self) -> None:
        """Test dispatch implementation that raises ConnectionError."""
        dispatcher = FailingDispatch(ConnectionError("Connection failed"))

        with pytest.raises(ConnectionError, match="Connection failed"):
            await dispatcher.dispatch(('example.com', 80))


class AsyncDispatch(Dispatch):
    """Dispatcher that simulates async behavior."""

    def __init__(
        self,
        ip_address: Union[ipaddress.IPv4Address, ipaddress.IPv6Address],
        delay: float = 0.1
    ) -> None:
        """Initialize with IP address and delay."""
        self.ip_address = ip_address
        self.delay = delay

    async def dispatch(
        self, remote_address: Tuple[str, int]
    ) -> Union[ipaddress.IPv4Address, ipaddress.IPv6Address]:
        """Return IP address after a delay."""
        await asyncio.sleep(self.delay)
        return self.ip_address


class TestAsyncDispatch:
    """Tests for async behavior in dispatch implementations."""

    @pytest.mark.asyncio
    async def test_async_dispatch_with_delay(self) -> None:
        """Test async dispatch with delay."""
        ip = ipaddress.IPv4Address('10.0.0.1')
        dispatcher = AsyncDispatch(ip, delay=0.01)

        start_time = asyncio.get_event_loop().time()
        result = await dispatcher.dispatch(('example.com', 80))
        end_time = asyncio.get_event_loop().time()

        assert result == ip
        assert end_time - start_time >= 0.01

    @pytest.mark.asyncio
    async def test_concurrent_dispatches(self) -> None:
        """Test concurrent dispatch calls."""
        ip = ipaddress.IPv4Address('10.0.0.1')
        dispatcher = AsyncDispatch(ip, delay=0.01)

        # Create multiple concurrent dispatch tasks
        tasks = [
            dispatcher.dispatch(('example.com', 80)),
            dispatcher.dispatch(('google.com', 443)),
            dispatcher.dispatch(('github.com', 22))
        ]

        start_time = asyncio.get_event_loop().time()
        results = await asyncio.gather(*tasks)
        end_time = asyncio.get_event_loop().time()

        # All results should be the same IP
        assert all(result == ip for result in results)

        # Time should be close to single delay (concurrent execution)
        assert end_time - start_time < 0.05  # Should be much less than 3 * delay

    @pytest.mark.asyncio
    async def test_cancellation_handling(self) -> None:
        """Test that dispatch can be cancelled."""
        ip = ipaddress.IPv4Address('10.0.0.1')
        dispatcher = AsyncDispatch(ip, delay=0.5)  # Longer delay

        task = asyncio.create_task(dispatcher.dispatch(('example.com', 80)))

        # Cancel the task after a short delay
        await asyncio.sleep(0.01)
        task.cancel()

        with pytest.raises(asyncio.CancelledError):
            await task


class StatefulDispatch(Dispatch):
    """Dispatcher that maintains state between calls."""

    def __init__(
        self, addresses: list[Union[ipaddress.IPv4Address, ipaddress.IPv6Address]]
    ) -> None:
        """Initialize with list of addresses."""
        self.addresses = addresses
        self.current_index = 0
        self.call_count = 0

    async def dispatch(
        self, remote_address: Tuple[str, int]
    ) -> Union[ipaddress.IPv4Address, ipaddress.IPv6Address]:
        """Return next address in rotation."""
        if not self.addresses:
            raise ValueError("No addresses available")

        result = self.addresses[self.current_index]
        self.current_index = (self.current_index + 1) % len(self.addresses)
        self.call_count += 1
        return result


class TestStatefulDispatch:
    """Tests for stateful dispatch behavior."""

    @pytest.mark.asyncio
    async def test_round_robin_behavior(self) -> None:
        """Test round-robin address selection."""
        addresses = [
            ipaddress.IPv4Address('192.168.1.1'),
            ipaddress.IPv4Address('192.168.1.2'),
            ipaddress.IPv4Address('192.168.1.3')
        ]
        dispatcher = StatefulDispatch(addresses)

        # First round
        result1 = await dispatcher.dispatch(('example.com', 80))
        result2 = await dispatcher.dispatch(('example.com', 80))
        result3 = await dispatcher.dispatch(('example.com', 80))

        assert result1 == addresses[0]
        assert result2 == addresses[1]
        assert result3 == addresses[2]

        # Should wrap around
        result4 = await dispatcher.dispatch(('example.com', 80))
        assert result4 == addresses[0]

    @pytest.mark.asyncio
    async def test_empty_addresses_raises_error(self) -> None:
        """Test that empty addresses list raises error."""
        dispatcher = StatefulDispatch([])

        with pytest.raises(ValueError, match="No addresses available"):
            await dispatcher.dispatch(('example.com', 80))

    @pytest.mark.asyncio
    async def test_state_tracking(self) -> None:
        """Test that state is properly tracked."""
        addresses = [
            ipaddress.IPv4Address('192.168.1.1'),
            ipaddress.IPv4Address('192.168.1.2')
        ]
        dispatcher = StatefulDispatch(addresses)

        # Make several calls
        for _ in range(5):  # i not used
            await dispatcher.dispatch(('example.com', 80))

        assert dispatcher.call_count == 5
        assert dispatcher.current_index == 1  # Should be at index 1 after 5 calls (0,1,0,1,0)
