import pytest
import ipaddress
import netifaces
from dispatch.dispatcher.weighted_rr import RawWeightedAddress, WeightedAddress, WeightedRoundRobinDispatcher, Interface
import asyncio

# Mock netifaces for interface resolution
def mock_netifaces(monkeypatch):
    class MockNetifaces:
        # Use the actual constants from netifaces
        AF_INET = netifaces.AF_INET
        AF_INET6 = netifaces.AF_INET6
        
        @staticmethod
        def interfaces():
            return ['eth0', 'wlan0']
        
        @staticmethod
        def ifaddresses(iface):
            if iface == 'eth0':
                return {
                    MockNetifaces.AF_INET: [{'addr': '192.168.1.10'}],
                    MockNetifaces.AF_INET6: [{'addr': 'fe80::1'}]
                }
            if iface == 'wlan0':
                return {
                    MockNetifaces.AF_INET: [{'addr': '192.168.1.20'}],
                    MockNetifaces.AF_INET6: [{'addr': 'fe80::2'}]
                }
            return {}
    
    # Mock the entire netifaces module
    monkeypatch.setattr('netifaces.interfaces', MockNetifaces.interfaces)
    monkeypatch.setattr('netifaces.ifaddresses', MockNetifaces.ifaddresses)
    monkeypatch.setattr('netifaces.AF_INET', MockNetifaces.AF_INET)
    monkeypatch.setattr('netifaces.AF_INET6', MockNetifaces.AF_INET6)

@pytest.mark.asyncio
async def test_weighted_round_robin_ipv4(monkeypatch):
    mock_netifaces(monkeypatch)
    
    # Create direct interface objects to avoid parsing issues
    eth0 = Interface(name='eth0', ipv4=ipaddress.IPv4Address('192.168.1.10'), ipv6=ipaddress.IPv6Address('fe80::1'))
    wlan0 = Interface(name='wlan0', ipv4=ipaddress.IPv4Address('192.168.1.20'), ipv6=ipaddress.IPv6Address('fe80::2'))
    
    # Create weighted addresses directly
    addresses = [
        WeightedAddress(interface=eth0, weight=2),
        WeightedAddress(interface=wlan0, weight=1)
    ]
    
    dispatcher = WeightedRoundRobinDispatcher(addresses)
    
    # Should cycle: eth0, eth0, wlan0, eth0, eth0, wlan0 ...
    results = []
    for _ in range(6):
        ip = await dispatcher.dispatch(('8.8.8.8', 80))
        results.append(str(ip))
    
    assert results == ['192.168.1.10', '192.168.1.10', '192.168.1.20', 
                       '192.168.1.10', '192.168.1.10', '192.168.1.20']

@pytest.mark.asyncio
async def test_weighted_round_robin_ipv6(monkeypatch):
    mock_netifaces(monkeypatch)
    
    # Create direct interface objects to avoid parsing issues
    eth0 = Interface(name='eth0', ipv4=ipaddress.IPv4Address('192.168.1.10'), ipv6=ipaddress.IPv6Address('fe80::1'))
    wlan0 = Interface(name='wlan0', ipv4=ipaddress.IPv4Address('192.168.1.20'), ipv6=ipaddress.IPv6Address('fe80::2'))
    
    # Create weighted addresses directly with different weights
    addresses = [
        WeightedAddress(interface=eth0, weight=1),
        WeightedAddress(interface=wlan0, weight=2)
    ]
    
    dispatcher = WeightedRoundRobinDispatcher(addresses)
    
    # Should cycle: eth0, wlan0, wlan0, eth0, wlan0, wlan0 ...
    results = []
    for _ in range(6):
        ip = await dispatcher.dispatch(('2001:4860:4860::8888', 80))
        results.append(str(ip))
    
    assert results == ['fe80::1', 'fe80::2', 'fe80::2', 
                       'fe80::1', 'fe80::2', 'fe80::2']

@pytest.mark.asyncio
async def test_direct_ip_addresses(monkeypatch):
    # Test with direct IP addresses instead of interfaces
    ip1 = Interface(ip=ipaddress.IPv4Address('192.168.1.100'))
    ip2 = Interface(ip=ipaddress.IPv4Address('192.168.1.101'))
    
    addresses = [
        WeightedAddress(interface=ip1, weight=1),
        WeightedAddress(interface=ip2, weight=1)
    ]
    
    dispatcher = WeightedRoundRobinDispatcher(addresses)
    
    # Should alternate between the two IPs
    results = []
    for _ in range(4):
        ip = await dispatcher.dispatch(('8.8.8.8', 80))
        results.append(str(ip))
    
    assert results == ['192.168.1.100', '192.168.1.101', 
                       '192.168.1.100', '192.168.1.101']

@pytest.mark.asyncio
async def test_invalid_interface(monkeypatch):
    mock_netifaces(monkeypatch)
    raw = [RawWeightedAddress('nonexistent', 1)]
    with pytest.raises(ValueError):
        WeightedAddress.resolve(raw)

@pytest.mark.asyncio
async def test_loopback_rejected(monkeypatch):
    class MockLoopbackNetifaces:
        # Use the actual constants from netifaces
        AF_INET = netifaces.AF_INET
        AF_INET6 = netifaces.AF_INET6
        
        @staticmethod
        def interfaces():
            return ['lo']
        
        @staticmethod
        def ifaddresses(iface):
            return {
                MockLoopbackNetifaces.AF_INET: [{'addr': '127.0.0.1'}], 
                MockLoopbackNetifaces.AF_INET6: [{'addr': '::1'}]
            }
    
    monkeypatch.setattr('netifaces.interfaces', MockLoopbackNetifaces.interfaces)
    monkeypatch.setattr('netifaces.ifaddresses', MockLoopbackNetifaces.ifaddresses)
    monkeypatch.setattr('netifaces.AF_INET', MockLoopbackNetifaces.AF_INET)
    monkeypatch.setattr('netifaces.AF_INET6', MockLoopbackNetifaces.AF_INET6)
    
    raw = [RawWeightedAddress('lo', 1)]
    with pytest.raises(ValueError):
        WeightedAddress.resolve(raw) 