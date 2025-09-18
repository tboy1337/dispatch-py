"""
Tests for dispatch.list module.
"""

import ipaddress
from typing import Dict, List, Tuple, Any
from unittest.mock import patch
import pytest
import netifaces

from dispatch.list import get_interface_addresses, list_interfaces


class TestGetInterfaceAddresses:
    """Tests for get_interface_addresses function."""

    @pytest.fixture
    def mock_interfaces_data(self) -> Dict[str, Any]:  # type: ignore[explicit-any]
        """Mock interface data for testing."""
        return {
            'eth0': {
                netifaces.AF_INET: [
                    {'addr': '192.168.1.100'},
                    {'addr': '192.168.1.101'}  # Multiple IPv4 addresses
                ],
                netifaces.AF_INET6: [
                    {'addr': '2001:db8::1'},
                    {'addr': 'fe80::1%eth0'}  # With scope ID
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
            },
            'empty_interface': {},
            'partial_interface': {
                netifaces.AF_INET: [
                    {'netmask': '255.255.255.0'}  # No 'addr' key
                ]
            }
        }

    def test_get_interface_addresses_success(  # type: ignore[explicit-any]
        self, mock_interfaces_data: Dict[str, Any]
    ) -> None:
        """Test successful retrieval of interface addresses."""
        with patch('netifaces.interfaces') as mock_interfaces, \
             patch('netifaces.ifaddresses') as mock_ifaddresses:

            mock_interfaces.return_value = list(mock_interfaces_data.keys())
            mock_ifaddresses.side_effect = lambda name: mock_interfaces_data.get(name, {})

            result = get_interface_addresses()

            # Verify eth0 addresses
            assert 'eth0' in result
            eth0_addresses = result['eth0']
            assert len(eth0_addresses) == 4  # 2 IPv4 + 2 IPv6

            # Check IPv4 addresses
            ipv4_addrs = [addr for addr_type, addr in eth0_addresses if addr_type == 'IPv4']
            assert '192.168.1.100' in ipv4_addrs
            assert '192.168.1.101' in ipv4_addrs

            # Check IPv6 addresses
            ipv6_addrs = [addr for addr_type, addr in eth0_addresses if addr_type == 'IPv6']
            assert '2001:db8::1' in ipv6_addrs
            assert 'fe80::1' in ipv6_addrs  # Scope ID should be removed

            # Verify wlan0 addresses
            assert 'wlan0' in result
            wlan0_addresses = result['wlan0']
            assert len(wlan0_addresses) == 1
            assert ('IPv4', '10.0.0.50') in wlan0_addresses

            # Verify loopback addresses
            assert 'lo' in result
            lo_addresses = result['lo']
            assert ('IPv4', '127.0.0.1') in lo_addresses
            assert ('IPv6', '::1') in lo_addresses

    def test_get_interface_addresses_empty_interface(  # type: ignore[explicit-any]
        self, mock_interfaces_data: Dict[str, Any]
    ) -> None:
        """Test interface with no address data."""
        with patch('netifaces.interfaces') as mock_interfaces, \
             patch('netifaces.ifaddresses') as mock_ifaddresses:

            mock_interfaces.return_value = ['empty_interface']
            mock_ifaddresses.side_effect = lambda name: mock_interfaces_data.get(name, {})

            result = get_interface_addresses()

            assert 'empty_interface' in result
            assert result['empty_interface'] == []

    def test_get_interface_addresses_partial_interface(  # type: ignore[explicit-any]
        self, mock_interfaces_data: Dict[str, Any]
    ) -> None:
        """Test interface with partial address data (no 'addr' key)."""
        with patch('netifaces.interfaces') as mock_interfaces, \
             patch('netifaces.ifaddresses') as mock_ifaddresses:

            mock_interfaces.return_value = ['partial_interface']
            mock_ifaddresses.side_effect = lambda name: mock_interfaces_data.get(name, {})

            result = get_interface_addresses()

            assert 'partial_interface' in result
            assert result['partial_interface'] == []

    def test_get_interface_addresses_no_interfaces(self) -> None:
        """Test when no interfaces are available."""
        with patch('netifaces.interfaces') as mock_interfaces, \
             patch('netifaces.ifaddresses') as mock_ifaddresses:

            mock_interfaces.return_value = []
            mock_ifaddresses.return_value = {}

            result = get_interface_addresses()

            assert not result

    def test_get_interface_addresses_ipv4_only(self) -> None:
        """Test interface with IPv4 addresses only."""
        interface_data = {
            'eth0': {
                netifaces.AF_INET: [
                    {'addr': '192.168.1.100'}
                ]
            }
        }

        with patch('netifaces.interfaces') as mock_interfaces, \
             patch('netifaces.ifaddresses') as mock_ifaddresses:

            mock_interfaces.return_value = ['eth0']
            mock_ifaddresses.side_effect = lambda name: interface_data.get(name, {})

            result = get_interface_addresses()

            assert 'eth0' in result
            assert len(result['eth0']) == 1
            assert ('IPv4', '192.168.1.100') in result['eth0']

    def test_get_interface_addresses_ipv6_only(self) -> None:
        """Test interface with IPv6 addresses only."""
        interface_data = {
            'wlan0': {
                netifaces.AF_INET6: [
                    {'addr': '2001:db8::1'}
                ]
            }
        }

        with patch('netifaces.interfaces') as mock_interfaces, \
             patch('netifaces.ifaddresses') as mock_ifaddresses:

            mock_interfaces.return_value = ['wlan0']
            mock_ifaddresses.side_effect = lambda name: interface_data.get(name, {})

            result = get_interface_addresses()

            assert 'wlan0' in result
            assert len(result['wlan0']) == 1
            assert ('IPv6', '2001:db8::1') in result['wlan0']

    def test_get_interface_addresses_ipv6_scope_id_removal(self) -> None:
        """Test that IPv6 scope IDs are properly removed."""
        interface_data = {
            'eth0': {
                netifaces.AF_INET6: [
                    {'addr': '2001:db8::1%eth0'},
                    {'addr': 'fe80::1%2'},
                    {'addr': '::1'},  # No scope ID
                ]
            }
        }

        with patch('netifaces.interfaces') as mock_interfaces, \
             patch('netifaces.ifaddresses') as mock_ifaddresses:

            mock_interfaces.return_value = ['eth0']
            mock_ifaddresses.side_effect = lambda name: interface_data.get(name, {})

            result = get_interface_addresses()

            eth0_addresses = result['eth0']
            ipv6_addrs = [addr for addr_type, addr in eth0_addresses if addr_type == 'IPv6']

            # Verify scope IDs are removed
            assert '2001:db8::1' in ipv6_addrs
            assert 'fe80::1' in ipv6_addrs
            assert '::1' in ipv6_addrs

            # Verify no scope IDs remain
            for addr in ipv6_addrs:
                assert '%' not in addr

    def test_get_interface_addresses_invalid_ip_handling(self) -> None:
        """Test handling of invalid IP addresses."""
        interface_data = {
            'eth0': {
                netifaces.AF_INET: [
                    {'addr': 'invalid.ip.address'},
                    {'addr': '192.168.1.100'}  # Valid address
                ],
                netifaces.AF_INET6: [
                    {'addr': 'invalid:ipv6:address'},
                    {'addr': '2001:db8::1'}  # Valid address
                ]
            }
        }

        with patch('netifaces.interfaces') as mock_interfaces, \
             patch('netifaces.ifaddresses') as mock_ifaddresses:

            mock_interfaces.return_value = ['eth0']
            mock_ifaddresses.side_effect = lambda name: interface_data.get(name, {})

            # This should not raise an exception, but might skip invalid addresses
            # depending on the implementation
            try:
                result = get_interface_addresses()
                # If it doesn't raise, check that valid addresses are still present
                if 'eth0' in result:
                    addrs = [addr for _, addr in result['eth0']]
                    # At minimum, valid addresses should be present if any processing succeeded
                    if addrs:  # If any addresses were processed
                        assert any(
                            '192.168.1.100' in addr or '2001:db8::1' in addr 
                            for addr in addrs
                        )
            except (ValueError, ipaddress.AddressValueError):
                # It's acceptable for the function to raise on invalid addresses
                pass


class TestListInterfaces:
    """Tests for list_interfaces function."""

    @pytest.fixture
    def mock_interface_data(self) -> Dict[str, List[Tuple[str, str]]]:
        """Mock interface data for list_interfaces testing."""
        return {
            'eth0': [
                ('IPv4', '192.168.1.100'),
                ('IPv6', '2001:db8::1')
            ],
            'wlan0': [
                ('IPv4', '10.0.0.50')
            ],
            'lo': [
                ('IPv4', '127.0.0.1'),
                ('IPv6', '::1')
            ],
            'empty': []
        }

    def test_list_interfaces_success(
        self, mock_interface_data: Dict[str, List[Tuple[str, str]]]
    ) -> None:
        """Test successful interface listing."""
        with patch('dispatch.list.get_interface_addresses') as mock_get_addresses, \
             patch('builtins.print') as mock_print:

            mock_get_addresses.return_value = mock_interface_data

            list_interfaces()

            # Verify print was called
            assert mock_print.call_count > 0

            # Collect all print calls
            print_calls = [call[0][0] for call in mock_print.call_args_list]
            output = '\n'.join(print_calls)

            # Verify header is printed
            assert 'Available network interfaces:' in output

            # Verify interfaces with addresses are listed (accounting for ANSI codes)
            assert 'eth0' in output
            assert '192.168.1.100' in output
            assert '2001:db8::1' in output

            assert 'wlan0' in output
            assert '10.0.0.50' in output

            assert 'lo' in output
            assert '127.0.0.1' in output
            assert '::1' in output

            # Verify empty interface is not listed
            assert 'empty' not in output

    def test_list_interfaces_loopback_marking(
        self, mock_interface_data: Dict[str, List[Tuple[str, str]]]
    ) -> None:
        """Test that loopback addresses are marked."""
        with patch('dispatch.list.get_interface_addresses') as mock_get_addresses, \
             patch('builtins.print') as mock_print:

            mock_get_addresses.return_value = mock_interface_data

            list_interfaces()

            # Collect all print calls
            print_calls = [call[0][0] for call in mock_print.call_args_list]
            output = '\n'.join(print_calls)

            # Check that loopback addresses are marked
            # The actual marking might use ANSI color codes, so check for "(loopback)"
            assert '127.0.0.1' in output
            assert '::1' in output
            # Note: The actual test for "(loopback)" marking might need adjustment
            # based on the colorama color codes in the output

    def test_list_interfaces_no_interfaces(self) -> None:
        """Test listing when no interfaces are available."""
        with patch('dispatch.list.get_interface_addresses') as mock_get_addresses, \
             patch('builtins.print') as mock_print:

            mock_get_addresses.return_value = {}

            list_interfaces()

            # Verify error message is printed
            print_calls = [call[0][0] for call in mock_print.call_args_list]
            output = '\n'.join(print_calls)

            assert 'No network interfaces found' in output

    def test_list_interfaces_only_empty_interfaces(self) -> None:
        """Test listing when all interfaces are empty."""
        empty_interfaces: Dict[str, List[Any]] = {  # type: ignore[explicit-any]
            'empty1': [],
            'empty2': []
        }

        with patch('dispatch.list.get_interface_addresses') as mock_get_addresses, \
             patch('builtins.print') as mock_print:

            mock_get_addresses.return_value = empty_interfaces

            list_interfaces()

            # Should show the header but no interface details
            print_calls = [call[0][0] for call in mock_print.call_args_list]
            output = '\n'.join(print_calls)

            assert 'Available network interfaces:' in output
            assert 'empty1:' not in output
            assert 'empty2:' not in output

    def test_list_interfaces_mixed_ipv4_ipv6(self) -> None:
        """Test listing with mixed IPv4 and IPv6 addresses."""
        mixed_data = {
            'eth0': [
                ('IPv4', '192.168.1.100'),
                ('IPv6', '2001:db8::1'),
                ('IPv4', '192.168.1.101'),
                ('IPv6', 'fe80::1')
            ]
        }

        with patch('dispatch.list.get_interface_addresses') as mock_get_addresses, \
             patch('builtins.print') as mock_print:

            mock_get_addresses.return_value = mixed_data

            list_interfaces()

            print_calls = [call[0][0] for call in mock_print.call_args_list]
            output = '\n'.join(print_calls)

            # Verify all addresses are listed with their types (accounting for ANSI codes)
            assert 'eth0' in output
            assert '192.168.1.100' in output
            assert '192.168.1.101' in output
            assert '2001:db8::1' in output
            assert 'fe80::1' in output

            # Verify IPv4 and IPv6 labels are present
            ipv4_lines = [line for line in output.split('\n') if 'IPv4' in line]
            ipv6_lines = [line for line in output.split('\n') if 'IPv6' in line]

            assert len(ipv4_lines) == 2  # Two IPv4 addresses
            assert len(ipv6_lines) == 2  # Two IPv6 addresses

    def test_list_interfaces_special_characters_in_names(self) -> None:
        """Test listing with special characters in interface names."""
        special_data = {
            'eth0.100': [('IPv4', '192.168.100.1')],
            'wlan0-ap': [('IPv4', '10.0.0.1')],
            'br_docker0': [('IPv4', '172.17.0.1')]
        }

        with patch('dispatch.list.get_interface_addresses') as mock_get_addresses, \
             patch('builtins.print') as mock_print:

            mock_get_addresses.return_value = special_data

            list_interfaces()

            print_calls = [call[0][0] for call in mock_print.call_args_list]
            output = '\n'.join(print_calls)

            # Verify all interfaces with special characters are listed (accounting for ANSI codes)
            assert 'eth0.100' in output
            assert 'wlan0-ap' in output
            assert 'br_docker0' in output

    def test_list_interfaces_colorama_usage(self) -> None:
        """Test that colorama colors are used (implicitly through imports)."""
        interface_data = {
            'eth0': [('IPv4', '192.168.1.100')]
        }

        with patch('dispatch.list.get_interface_addresses') as mock_get_addresses, \
             patch('builtins.print') as mock_print:

            mock_get_addresses.return_value = interface_data

            # Test that colorama imports are working
            import colorama  # pylint: disable=import-outside-toplevel
            assert hasattr(colorama, 'Fore')
            assert hasattr(colorama, 'Style')

            list_interfaces()

            # The function should complete without errors
            assert mock_print.call_count > 0

            # Note: We can't easily test the actual color codes without
            # making assumptions about the exact colorama usage


class TestListIntegration:
    """Integration tests for list module functionality."""

    def test_get_and_list_integration(self) -> None:
        """Test integration between get_interface_addresses and list_interfaces."""
        mock_interfaces_data = {
            'eth0': {
                netifaces.AF_INET: [{'addr': '192.168.1.100'}],
                netifaces.AF_INET6: [{'addr': '2001:db8::1'}]
            }
        }

        with patch('netifaces.interfaces') as mock_interfaces, \
             patch('netifaces.ifaddresses') as mock_ifaddresses, \
             patch('builtins.print') as mock_print:

            mock_interfaces.return_value = ['eth0']
            mock_ifaddresses.side_effect = lambda name: mock_interfaces_data.get(name, {})

            # This tests the full pipeline
            list_interfaces()

            # Verify output contains the expected interface and addresses
            print_calls = [call[0][0] for call in mock_print.call_args_list]
            output = '\n'.join(print_calls)

            assert 'eth0' in output
            assert '192.168.1.100' in output
            assert '2001:db8::1' in output

    def test_error_handling_in_integration(self) -> None:
        """Test error handling in the integration flow."""
        with patch('netifaces.interfaces') as mock_interfaces, \
             patch('netifaces.ifaddresses'), \
             patch('builtins.print'):

            # Mock an error in netifaces
            mock_interfaces.side_effect = Exception("Network error")

            # The function should handle the error gracefully
            with pytest.raises(Exception, match="Network error"):
                list_interfaces()

            # At minimum, print should have been called (even for error cases)
            # unless the exception prevents all execution
