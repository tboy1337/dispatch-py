"""
Tests for dispatch.dispatcher.weighted_rr module.
"""

import asyncio
import ipaddress
import socket
from typing import Dict, List, Any
from unittest.mock import patch, AsyncMock

import pytest
import netifaces

from dispatch.dispatcher.weighted_rr import (
    RawWeightedAddress,
    Interface,
    WeightedAddress,
    WeightedIp,
    State,
    WeightedRoundRobinDispatcher
)


class TestRawWeightedAddress:
    """Tests for RawWeightedAddress class."""

    def test_create_with_defaults(self) -> None:
        """Test creating RawWeightedAddress with default weight."""
        addr = RawWeightedAddress(interface='eth0')
        assert addr.interface == 'eth0'
        assert addr.weight == 1

    def test_create_with_custom_weight(self) -> None:
        """Test creating RawWeightedAddress with custom weight."""
        addr = RawWeightedAddress(interface='192.168.1.1', weight=5)
        assert addr.interface == '192.168.1.1'
        assert addr.weight == 5

    def test_from_str_interface_only(self) -> None:
        """Test parsing interface name only."""
        addr = RawWeightedAddress.from_str('eth0')
        assert addr.interface == 'eth0'
        assert addr.weight == 1

    def test_from_str_with_weight(self) -> None:
        """Test parsing interface name with weight."""
        addr = RawWeightedAddress.from_str('192.168.1.1/3')
        assert addr.interface == '192.168.1.1'
        assert addr.weight == 3

    def test_from_str_zero_weight_raises_error(self) -> None:
        """Test that zero weight raises ValueError."""
        with pytest.raises(ValueError, match="Weight must be positive, got 0"):
            RawWeightedAddress.from_str('eth0/0')

    def test_from_str_negative_weight_raises_error(self) -> None:
        """Test that negative weight raises ValueError."""
        with pytest.raises(ValueError, match="Weight must be positive, got -1"):
            RawWeightedAddress.from_str('eth0/-1')

    def test_from_str_invalid_weight_raises_error(self) -> None:
        """Test that non-integer weight raises ValueError."""
        with pytest.raises(ValueError):
            RawWeightedAddress.from_str('eth0/abc')

    def test_from_str_multiple_slashes(self) -> None:
        """Test parsing with multiple slashes (only first two parts used)."""
        addr = RawWeightedAddress.from_str('eth0/3/extra')
        assert addr.interface == 'eth0'
        assert addr.weight == 3


class TestInterface:
    """Tests for Interface class."""

    def test_create_named_interface(self) -> None:
        """Test creating a named interface."""
        ipv4 = ipaddress.IPv4Address('192.168.1.100')
        ipv6 = ipaddress.IPv6Address('2001:db8::1')

        iface = Interface(name='eth0', ipv4=ipv4, ipv6=ipv6)

        assert iface.name == 'eth0'
        assert iface.ipv4 == ipv4
        assert iface.ipv6 == ipv6
        assert iface.ip is None
        assert iface.is_named is True
        assert iface.is_direct_ip is False

    def test_create_direct_ip_interface(self) -> None:
        """Test creating a direct IP interface."""
        ip = ipaddress.IPv4Address('10.0.0.1')

        iface = Interface(ip=ip)

        assert iface.name is None
        assert iface.ipv4 is None
        assert iface.ipv6 is None
        assert iface.ip == ip
        assert iface.is_named is False
        assert iface.is_direct_ip is True

    def test_create_empty_interface(self) -> None:
        """Test creating interface with no parameters."""
        iface = Interface()

        assert iface.name is None
        assert iface.ipv4 is None
        assert iface.ipv6 is None
        assert iface.ip is None
        assert iface.is_named is False
        assert iface.is_direct_ip is False


class TestWeightedAddress:
    """Tests for WeightedAddress class."""

    def test_str_representation_named_interface(self) -> None:
        """Test string representation of named interface."""
        ipv4 = ipaddress.IPv4Address('192.168.1.100')
        ipv6 = ipaddress.IPv6Address('2001:db8::1')
        iface = Interface(name='eth0', ipv4=ipv4, ipv6=ipv6)
        addr = WeightedAddress(interface=iface, weight=3)

        result = str(addr)
        assert 'eth0/3' in result
        assert '192.168.1.100' in result
        assert '2001:db8::1' in result

    def test_str_representation_named_interface_ipv4_only(self) -> None:
        """Test string representation of named interface with IPv4 only."""
        ipv4 = ipaddress.IPv4Address('192.168.1.100')
        iface = Interface(name='eth0', ipv4=ipv4)
        addr = WeightedAddress(interface=iface, weight=2)

        result = str(addr)
        assert result == 'eth0/2 (192.168.1.100)'

    def test_str_representation_direct_ip(self) -> None:
        """Test string representation of direct IP."""
        ip = ipaddress.IPv4Address('10.0.0.1')
        iface = Interface(ip=ip)
        addr = WeightedAddress(interface=iface, weight=5)

        result = str(addr)
        assert result == '10.0.0.1/5'

    def test_str_representation_unknown_interface(self) -> None:
        """Test string representation of unknown interface."""
        iface = Interface()
        addr = WeightedAddress(interface=iface, weight=1)

        result = str(addr)
        assert result == 'Unknown interface/1'


class TestWeightedAddressResolve:
    """Tests for WeightedAddress.resolve method."""

    @pytest.fixture
    def mock_interfaces(self) -> Dict[str, Any]:  # type: ignore[explicit-any]
        """Mock network interfaces."""
        return {
            'eth0': {
                netifaces.AF_INET: [{'addr': '192.168.1.100'}],
                netifaces.AF_INET6: [{'addr': '2001:db8::1'}]
            },
            'wlan0': {
                netifaces.AF_INET: [{'addr': '10.0.0.50'}]
            },
            'lo': {
                netifaces.AF_INET: [{'addr': '127.0.0.1'}],
                netifaces.AF_INET6: [{'addr': '::1'}]
            }
        }

    def test_resolve_interface_by_name(  # type: ignore[explicit-any]
        self, mock_interfaces: Dict[str, Any]
    ) -> None:
        """Test resolving interface by name."""
        raw_addresses = [RawWeightedAddress(interface='eth0', weight=3)]

        with patch('netifaces.interfaces', return_value=['eth0', 'wlan0', 'lo']), \
             patch('netifaces.ifaddresses', side_effect=lambda name: mock_interfaces.get(name, {})):

            result = WeightedAddress.resolve(raw_addresses)

            assert len(result) == 1
            addr = result[0]
            assert addr.interface.name == 'eth0'
            assert addr.interface.ipv4 == ipaddress.IPv4Address('192.168.1.100')
            assert addr.interface.ipv6 == ipaddress.IPv6Address('2001:db8::1')
            assert addr.weight == 3

    def test_resolve_interface_ipv4_only(  # type: ignore[explicit-any]
        self, mock_interfaces: Dict[str, Any]
    ) -> None:
        """Test resolving interface with IPv4 only."""
        raw_addresses = [RawWeightedAddress(interface='wlan0', weight=2)]

        with patch('netifaces.interfaces', return_value=['eth0', 'wlan0', 'lo']), \
             patch('netifaces.ifaddresses', side_effect=lambda name: mock_interfaces.get(name, {})):

            result = WeightedAddress.resolve(raw_addresses)

            assert len(result) == 1
            addr = result[0]
            assert addr.interface.name == 'wlan0'
            assert addr.interface.ipv4 == ipaddress.IPv4Address('10.0.0.50')
            assert addr.interface.ipv6 is None
            assert addr.weight == 2

    def test_resolve_direct_ipv4_address(self) -> None:
        """Test resolving direct IPv4 address."""
        raw_addresses = [RawWeightedAddress(interface='192.168.1.200', weight=1)]

        with patch('netifaces.interfaces', return_value=[]), \
             patch('netifaces.ifaddresses', return_value={}):

            result = WeightedAddress.resolve(raw_addresses)

            assert len(result) == 1
            addr = result[0]
            assert addr.interface.ip == ipaddress.IPv4Address('192.168.1.200')
            assert addr.interface.is_direct_ip is True
            assert addr.weight == 1

    def test_resolve_direct_ipv6_address(self) -> None:
        """Test resolving direct IPv6 address."""
        raw_addresses = [RawWeightedAddress(interface='2001:db8::100', weight=4)]

        with patch('netifaces.interfaces', return_value=[]), \
             patch('netifaces.ifaddresses', return_value={}):

            result = WeightedAddress.resolve(raw_addresses)

            assert len(result) == 1
            addr = result[0]
            assert addr.interface.ip == ipaddress.IPv6Address('2001:db8::100')
            assert addr.interface.is_direct_ip is True
            assert addr.weight == 4

    def test_resolve_loopback_address_raises_error(self) -> None:
        """Test that loopback addresses raise ValueError."""
        raw_addresses = [RawWeightedAddress(interface='127.0.0.1', weight=1)]

        with patch('netifaces.interfaces', return_value=[]), \
             patch('netifaces.ifaddresses', return_value={}):

            with pytest.raises(ValueError, match="loopback address|Failed to parse"):
                WeightedAddress.resolve(raw_addresses)

    def test_resolve_nonexistent_interface_raises_error(self) -> None:
        """Test that non-existent interface raises ValueError."""
        raw_addresses = [RawWeightedAddress(interface='nonexistent', weight=1)]

        with patch('netifaces.interfaces', return_value=[]), \
             patch('netifaces.ifaddresses', return_value={}):

            with pytest.raises(ValueError, match="Failed to parse 'nonexistent'"):
                WeightedAddress.resolve(raw_addresses)

    def test_resolve_interface_no_addresses_raises_error(self) -> None:
        """Test that interface with no addresses raises ValueError."""
        raw_addresses = [RawWeightedAddress(interface='empty', weight=1)]

        with patch('netifaces.interfaces', return_value=['empty']), \
             patch('netifaces.ifaddresses', return_value={}):

            with pytest.raises(
                ValueError, match="No IP addresses found for network interface 'empty'"
            ):
                WeightedAddress.resolve(raw_addresses)

    def test_resolve_multiple_addresses(  # type: ignore[explicit-any]
        self, mock_interfaces: Dict[str, Any]
    ) -> None:
        """Test resolving multiple addresses."""
        raw_addresses = [
            RawWeightedAddress(interface='eth0', weight=3),
            RawWeightedAddress(interface='192.168.1.200', weight=2)
        ]

        with patch('netifaces.interfaces', return_value=['eth0', 'wlan0', 'lo']), \
             patch('netifaces.ifaddresses', side_effect=lambda name: mock_interfaces.get(name, {})):

            result = WeightedAddress.resolve(raw_addresses)

            assert len(result) == 2

            # First address (eth0)
            assert result[0].interface.name == 'eth0'
            assert result[0].weight == 3

            # Second address (direct IP)
            assert result[1].interface.ip == ipaddress.IPv4Address('192.168.1.200')
            assert result[1].weight == 2

    def test_resolve_filters_loopback_from_interfaces(self) -> None:
        """Test that loopback addresses are filtered from interfaces."""
        mock_interfaces_with_loopback = {
            'eth0': {
                netifaces.AF_INET: [
                    {'addr': '192.168.1.100'},
                    {'addr': '127.0.0.1'}  # Should be filtered out
                ],
                netifaces.AF_INET6: [
                    {'addr': '2001:db8::1'},
                    {'addr': '::1'}  # Should be filtered out
                ]
            }
        }

        raw_addresses = [RawWeightedAddress(interface='eth0', weight=1)]

        with patch('netifaces.interfaces', return_value=['eth0']), \
             patch('netifaces.ifaddresses', return_value=mock_interfaces_with_loopback['eth0']):

            result = WeightedAddress.resolve(raw_addresses)

            assert len(result) == 1
            addr = result[0]
            # Should get non-loopback addresses
            assert addr.interface.ipv4 == ipaddress.IPv4Address('192.168.1.100')
            assert addr.interface.ipv6 == ipaddress.IPv6Address('2001:db8::1')

    def test_resolve_handles_ipv6_scope_id(self) -> None:
        """Test that IPv6 scope IDs are properly handled."""
        mock_interfaces_with_scope = {
            'eth0': {
                netifaces.AF_INET6: [
                    {'addr': '2001:db8::1%eth0'}  # With scope ID
                ]
            }
        }

        raw_addresses = [RawWeightedAddress(interface='eth0', weight=1)]

        with patch('netifaces.interfaces', return_value=['eth0']), \
             patch('netifaces.ifaddresses', return_value=mock_interfaces_with_scope['eth0']):

            result = WeightedAddress.resolve(raw_addresses)

            assert len(result) == 1
            addr = result[0]
            # Scope ID should be removed
            assert addr.interface.ipv6 == ipaddress.IPv6Address('2001:db8::1')


class TestState:
    """Tests for State class."""

    def test_create_state(self) -> None:
        """Test creating a State instance."""
        ips = [
            WeightedIp(ip=ipaddress.IPv4Address('192.168.1.1'), weight=3),
            WeightedIp(ip=ipaddress.IPv4Address('192.168.1.2'), weight=2)
        ]

        state = State(ips)

        assert state.ips == ips
        assert state.ip_idx == 0
        assert state.count == 0

    def test_empty_state(self) -> None:
        """Test creating empty state."""
        state = State([])

        assert state.ips == []
        assert state.ip_idx == 0
        assert state.count == 0


class TestWeightedIp:
    """Tests for WeightedIp class."""

    def test_create_ipv4_weighted_ip(self) -> None:
        """Test creating WeightedIp with IPv4."""
        ip = ipaddress.IPv4Address('192.168.1.1')
        weighted_ip = WeightedIp(ip=ip, weight=3)

        assert weighted_ip.ip == ip
        assert weighted_ip.weight == 3

    def test_create_ipv6_weighted_ip(self) -> None:
        """Test creating WeightedIp with IPv6."""
        ip = ipaddress.IPv6Address('2001:db8::1')
        weighted_ip = WeightedIp(ip=ip, weight=5)

        assert weighted_ip.ip == ip
        assert weighted_ip.weight == 5


class TestWeightedRoundRobinDispatcher:
    """Tests for WeightedRoundRobinDispatcher class."""

    def test_create_dispatcher_empty_raises_error(self) -> None:
        """Test that creating dispatcher with empty addresses raises ValueError."""
        with pytest.raises(ValueError, match="No addresses provided for dispatcher"):
            WeightedRoundRobinDispatcher([])

    def test_create_dispatcher_with_addresses(
        self, sample_weighted_addresses: List[WeightedAddress]
    ) -> None:
        """Test creating dispatcher with valid addresses."""
        dispatcher = WeightedRoundRobinDispatcher(sample_weighted_addresses)

        assert len(dispatcher.ipv4.ips) == 2  # Both are IPv4
        assert len(dispatcher.ipv6.ips) == 0

    def test_create_dispatcher_mixed_ip_versions(self) -> None:
        """Test creating dispatcher with mixed IPv4 and IPv6 addresses."""
        addresses = [
            WeightedAddress(
                interface=Interface(ip=ipaddress.IPv4Address('192.168.1.1')),
                weight=3
            ),
            WeightedAddress(
                interface=Interface(ip=ipaddress.IPv6Address('2001:db8::1')),
                weight=2
            )
        ]

        dispatcher = WeightedRoundRobinDispatcher(addresses)

        assert len(dispatcher.ipv4.ips) == 1
        assert len(dispatcher.ipv6.ips) == 1

    def test_create_dispatcher_with_named_interfaces(self) -> None:
        """Test creating dispatcher with named interfaces."""
        addresses = [
            WeightedAddress(
                interface=Interface(
                    name='eth0',
                    ipv4=ipaddress.IPv4Address('192.168.1.1'),
                    ipv6=ipaddress.IPv6Address('2001:db8::1')
                ),
                weight=3
            )
        ]

        dispatcher = WeightedRoundRobinDispatcher(addresses)

        # Named interface should contribute to both IPv4 and IPv6
        assert len(dispatcher.ipv4.ips) == 1
        assert len(dispatcher.ipv6.ips) == 1

    @pytest.mark.asyncio
    async def test_dispatch_ipv4_address(
        self, sample_weighted_addresses: List[WeightedAddress]
    ) -> None:
        """Test dispatching to IPv4 address."""
        dispatcher = WeightedRoundRobinDispatcher(sample_weighted_addresses)

        # Mock hostname resolution to return IPv4
        with patch('asyncio.get_event_loop') as mock_loop:
            mock_loop.return_value.getaddrinfo = AsyncMock(return_value=[
                (socket.AF_INET, socket.SOCK_STREAM, 6, '', ('192.168.1.50', 80))
            ])

            result = await dispatcher.dispatch(('example.com', 80))

            assert isinstance(result, ipaddress.IPv4Address)
            assert result in [
                ipaddress.IPv4Address('192.168.1.100'),
                ipaddress.IPv4Address('10.0.0.50')
            ]

    @pytest.mark.asyncio
    async def test_dispatch_direct_ipv4(
        self, sample_weighted_addresses: List[WeightedAddress]
    ) -> None:
        """Test dispatching with direct IPv4 address."""
        dispatcher = WeightedRoundRobinDispatcher(sample_weighted_addresses)

        result = await dispatcher.dispatch(('192.168.1.50', 80))

        assert isinstance(result, ipaddress.IPv4Address)

    @pytest.mark.asyncio
    async def test_dispatch_no_ipv6_raises_error(
        self, sample_weighted_addresses: List[WeightedAddress]
    ) -> None:
        """Test that dispatching IPv6 with no IPv6 addresses raises error."""
        dispatcher = WeightedRoundRobinDispatcher(sample_weighted_addresses)

        with pytest.raises(ValueError, match="No IPv6 address available for dispatching"):
            await dispatcher.dispatch(('2001:db8::1', 80))

    @pytest.mark.asyncio
    async def test_dispatch_hostname_resolution_failure(
        self, sample_weighted_addresses: List[WeightedAddress]
    ) -> None:
        """Test that hostname resolution failure raises error."""
        dispatcher = WeightedRoundRobinDispatcher(sample_weighted_addresses)

        with patch('asyncio.get_event_loop') as mock_loop:
            mock_loop.return_value.getaddrinfo.side_effect = Exception("Resolution failed")

            with pytest.raises(ValueError, match="Failed to resolve hostname: example.com"):
                await dispatcher.dispatch(('example.com', 80))

    @pytest.mark.asyncio
    async def test_weighted_round_robin_behavior(
        self, sample_weighted_addresses: List[WeightedAddress]
    ) -> None:
        """Test weighted round-robin behavior."""
        dispatcher = WeightedRoundRobinDispatcher(sample_weighted_addresses)

        # First address has weight 3, second has weight 2
        expected_sequence = [
            ipaddress.IPv4Address('192.168.1.100'),  # weight 3, count 1
            ipaddress.IPv4Address('192.168.1.100'),  # weight 3, count 2
            ipaddress.IPv4Address('192.168.1.100'),  # weight 3, count 3, switch
            ipaddress.IPv4Address('10.0.0.50'),      # weight 2, count 1
            ipaddress.IPv4Address('10.0.0.50'),      # weight 2, count 2, switch
            ipaddress.IPv4Address('192.168.1.100'),  # back to first
        ]

        results = []
        for _ in range(6):
            result = await dispatcher.dispatch(('192.168.1.1', 80))
            results.append(result)

        assert results == expected_sequence

    @pytest.mark.asyncio
    async def test_concurrent_dispatch_thread_safety(
        self, sample_weighted_addresses: List[WeightedAddress]
    ) -> None:
        """Test that concurrent dispatches are thread-safe."""
        dispatcher = WeightedRoundRobinDispatcher(sample_weighted_addresses)

        # Create multiple concurrent dispatch tasks
        tasks = [
            dispatcher.dispatch(('192.168.1.1', 80))
            for _ in range(10)
        ]

        results = await asyncio.gather(*tasks)

        # All results should be valid IP addresses
        assert all(isinstance(result, ipaddress.IPv4Address) for result in results)

        # Should get results from both addresses
        unique_results = set(results)
        assert len(unique_results) <= 2  # At most 2 different addresses
