"""
Tests for dispatch.main module.
"""

import ipaddress
import sys
from unittest.mock import Mock, patch

from click.testing import CliRunner

from dispatch.debug import LogStrategy
from dispatch.dispatcher.weighted_rr import WeightedAddress, Interface
from dispatch.main import cli, main


class TestCLIGroup:
    """Tests for the main CLI group."""

    def test_cli_help(self) -> None:
        """Test CLI help output."""
        runner = CliRunner()
        result = runner.invoke(cli, ['--help'])

        assert result.exit_code == 0
        assert 'A SOCKS proxy that balances traffic between network interfaces.' in result.output
        assert '--debug' in result.output
        assert '--version' in result.output
        assert 'Commands:' in result.output
        assert 'list' in result.output
        assert 'start' in result.output

    def test_cli_version(self) -> None:
        """Test CLI version output."""
        runner = CliRunner()
        result = runner.invoke(cli, ['--version'])

        assert result.exit_code == 0
        assert '1.0.1' in result.output

    def test_cli_debug_flag(self) -> None:
        """Test CLI debug flag functionality."""
        runner = CliRunner()

        with patch('dispatch.main.install_logging') as mock_install_logging, \
             patch('dispatch.main.list_interfaces'):
            mock_install_logging.return_value = None

            runner.invoke(cli, ['--debug', 'list'])  # result not used

            # Should call install_logging with STDOUT strategy
            mock_install_logging.assert_called_once_with(LogStrategy.STDOUT)

    def test_cli_no_debug_flag(self) -> None:
        """Test CLI without debug flag (default behavior)."""
        runner = CliRunner()

        with patch('dispatch.main.install_logging') as mock_install_logging, \
             patch('dispatch.main.list_interfaces'):

            mock_install_logging.return_value = '/tmp/logfile.log'

            runner.invoke(cli, ['list'])  # result not used

            # Should call install_logging with FILE strategy (default)
            mock_install_logging.assert_called_once_with(LogStrategy.FILE)

    def test_cli_context_object(self) -> None:
        """Test that CLI context object is properly set."""
        runner = CliRunner()

        with patch('dispatch.main.install_logging') as mock_install_logging, \
             patch('dispatch.main.list_interfaces'):

            mock_install_logging.return_value = '/tmp/logfile.log'

            # Create a custom command to test context
            # Test debug context by checking if the flag affects the logging strategy
            result = runner.invoke(cli, ['--debug', 'list'])

            # Should complete successfully with debug flag
            assert result.exit_code == 0
            mock_install_logging.assert_called_once_with(LogStrategy.STDOUT)


class TestListCommand:
    """Tests for the list command."""

    def test_list_command(self) -> None:
        """Test list command execution."""
        runner = CliRunner()

        with patch('dispatch.main.list_interfaces') as mock_list_interfaces, \
             patch('dispatch.main.install_logging'):

            result = runner.invoke(cli, ['list'])

            assert result.exit_code == 0
            mock_list_interfaces.assert_called_once()

    def test_list_command_help(self) -> None:
        """Test list command help."""
        runner = CliRunner()
        with patch('dispatch.main.install_logging'):
            result = runner.invoke(cli, ['list', '--help'])

            assert result.exit_code == 0
            assert 'Lists all available network interfaces.' in result.output


class TestStartCommand:
    """Tests for the start command."""

    def test_start_command_help(self) -> None:
        """Test start command help."""
        runner = CliRunner()
        result = runner.invoke(cli, ['start', '--help'])

        assert result.exit_code == 0
        assert 'Starts the SOCKS proxy server.' in result.output
        assert '--ip' in result.output
        assert '--port' in result.output
        assert 'ADDRESSES' in result.output

    def test_start_command_success(self) -> None:
        """Test successful start command execution."""
        runner = CliRunner()

        with patch('dispatch.main.install_logging'), \
             patch('dispatch.main.RawWeightedAddress.from_str') as mock_from_str, \
             patch('dispatch.main.WeightedAddress.resolve') as mock_resolve, \
             patch('dispatch.main.run_server') as mock_run_server:

            # Mock address parsing and resolution
            mock_raw_addr1 = Mock()
            mock_raw_addr2 = Mock()
            mock_from_str.side_effect = [mock_raw_addr1, mock_raw_addr2]

            mock_resolved_addr1 = Mock()
            mock_resolved_addr2 = Mock()
            mock_resolve.return_value = [mock_resolved_addr1, mock_resolved_addr2]

            result = runner.invoke(cli, ['start', '192.168.1.100', '10.0.0.50/2'])

            assert result.exit_code == 0

            # Verify address parsing
            assert mock_from_str.call_count == 2
            mock_from_str.assert_any_call('192.168.1.100')
            mock_from_str.assert_any_call('10.0.0.50/2')

            # Verify address resolution
            mock_resolve.assert_called_once_with([mock_raw_addr1, mock_raw_addr2])

            # Verify server start
            mock_run_server.assert_called_once_with(
                '127.0.0.1',  # default IP
                1080,         # default port
                [mock_resolved_addr1, mock_resolved_addr2]
            )

    def test_start_command_custom_ip_port(self) -> None:
        """Test start command with custom IP and port."""
        runner = CliRunner()

        with patch('dispatch.main.install_logging'), \
             patch('dispatch.main.RawWeightedAddress.from_str') as mock_from_str, \
             patch('dispatch.main.WeightedAddress.resolve') as mock_resolve, \
             patch('dispatch.main.run_server') as mock_run_server:

            mock_from_str.return_value = Mock()
            mock_resolve.return_value = [Mock()]

            result = runner.invoke(cli, [
                'start',
                '--ip', '0.0.0.0',
                '--port', '8080',
                '192.168.1.100'
            ])

            assert result.exit_code == 0

            # Verify custom IP and port are used
            mock_run_server.assert_called_once_with('0.0.0.0', 8080, [mock_resolve.return_value[0]])

    def test_start_command_no_addresses_error(self) -> None:
        """Test start command with no addresses."""
        runner = CliRunner()

        with patch('dispatch.main.install_logging'):
            result = runner.invoke(cli, ['start'])

            assert result.exit_code != 0
            assert 'Missing argument' in result.output or 'Error' in result.output

    def test_start_command_address_parse_error(self) -> None:
        """Test start command with invalid address format."""
        runner = CliRunner()

        with patch('dispatch.main.install_logging'), \
             patch('dispatch.main.RawWeightedAddress.from_str') as mock_from_str:

            mock_from_str.side_effect = ValueError("Invalid address format")

            result = runner.invoke(cli, ['start', 'invalid-address'])

            assert result.exit_code == 1
            assert "Error parsing address 'invalid-address'" in result.output

    def test_start_command_address_resolve_error(self) -> None:
        """Test start command with address resolution error."""
        runner = CliRunner()

        with patch('dispatch.main.install_logging'), \
             patch('dispatch.main.RawWeightedAddress.from_str') as mock_from_str, \
             patch('dispatch.main.WeightedAddress.resolve') as mock_resolve:

            mock_from_str.return_value = Mock()
            mock_resolve.side_effect = ValueError("Cannot resolve address")

            result = runner.invoke(cli, ['start', '192.168.1.100'])

            assert result.exit_code == 1
            assert "Error resolving addresses: Cannot resolve address" in result.output

    def test_start_command_multiple_addresses(self) -> None:
        """Test start command with multiple addresses."""
        runner = CliRunner()

        addresses = ['192.168.1.100/3', '10.0.0.50/2', '172.16.0.1']

        with patch('dispatch.main.install_logging'), \
             patch('dispatch.main.RawWeightedAddress.from_str') as mock_from_str, \
             patch('dispatch.main.WeightedAddress.resolve') as mock_resolve, \
             patch('dispatch.main.run_server') as mock_run_server:

            mock_from_str.side_effect = [Mock() for _ in addresses]
            mock_resolve.return_value = [Mock() for _ in addresses]

            result = runner.invoke(cli, ['start'] + addresses)

            assert result.exit_code == 0
            assert mock_from_str.call_count == len(addresses)
            mock_run_server.assert_called_once()

    def test_start_command_context_passing(self) -> None:
        """Test that context is properly passed to start command."""
        runner = CliRunner()

        with patch('dispatch.main.install_logging') as mock_install_logging, \
             patch('dispatch.main.RawWeightedAddress.from_str') as mock_from_str, \
             patch('dispatch.main.WeightedAddress.resolve') as mock_resolve, \
             patch('dispatch.main.run_server'):

            mock_install_logging.return_value = '/tmp/test.log'
            mock_from_str.return_value = Mock()
            mock_resolve.return_value = [Mock()]

            # Test with debug flag
            result = runner.invoke(cli, ['--debug', 'start', '192.168.1.100'])

            assert result.exit_code == 0
            # Debug flag should affect logging strategy
            mock_install_logging.assert_called_once_with(LogStrategy.STDOUT)


class TestMainFunction:
    """Tests for the main function."""

    def test_main_function_calls_cli(self) -> None:
        """Test that main function calls CLI with standalone_mode=False."""
        with patch('dispatch.main.cli') as mock_cli:
            main()
            mock_cli.assert_called_once_with(standalone_mode=False)

    def test_main_function_with_args(self) -> None:
        """Test main function behavior with command line arguments."""
        test_args = ['dispatch', 'list']

        with patch.object(sys, 'argv', test_args), \
             patch('dispatch.main.cli') as mock_cli:

            main()
            mock_cli.assert_called_once_with(standalone_mode=False)


class TestArgumentParsing:
    """Tests for argument parsing and validation."""

    def test_raw_weighted_address_parsing(self) -> None:
        """Test RawWeightedAddress parsing integration."""
        runner = CliRunner()

        with patch('dispatch.main.install_logging'), \
             patch('dispatch.main.WeightedAddress.resolve') as mock_resolve, \
             patch('dispatch.main.run_server'):

            mock_resolve.return_value = [Mock()]

            result = runner.invoke(cli, ['start', '192.168.1.100/5'])

            assert result.exit_code == 0

            # Verify that parsing was attempted (no exception means parsing worked)
            mock_resolve.assert_called_once()
            parsed_addresses = mock_resolve.call_args[0][0]
            assert len(parsed_addresses) == 1

    def test_weighted_address_resolution_integration(self) -> None:
        """Test WeightedAddress resolution integration."""
        runner = CliRunner()

        with patch('dispatch.main.install_logging'), \
             patch('dispatch.main.run_server') as mock_run_server:

            # Let the actual resolution happen (or mock it if needed)
            with patch('dispatch.main.WeightedAddress.resolve') as mock_resolve:
                mock_weighted_addr = WeightedAddress(
                    interface=Interface(ip=ipaddress.IPv4Address('192.168.1.100')),
                    weight=3
                )
                mock_resolve.return_value = [mock_weighted_addr]

                result = runner.invoke(cli, ['start', '192.168.1.100/3'])

                assert result.exit_code == 0
                mock_run_server.assert_called_once()

                # Verify resolved address is passed to server
                args, _ = mock_run_server.call_args  # kwargs not used
                resolved_addresses = args[2]  # Third argument is addresses
                assert len(resolved_addresses) == 1
                assert resolved_addresses[0] == mock_weighted_addr


class TestErrorHandling:
    """Tests for error handling in CLI commands."""

    def test_click_usage_error_handling(self) -> None:
        """Test handling of Click usage errors."""
        runner = CliRunner()

        # Invalid option should produce usage error
        result = runner.invoke(cli, ['--invalid-option'])

        assert result.exit_code != 0
        assert 'Usage:' in result.output or 'Error:' in result.output

    def test_keyboard_interrupt_handling(self) -> None:
        """Test handling of KeyboardInterrupt during server start."""
        runner = CliRunner()

        with patch('dispatch.main.install_logging'), \
             patch('dispatch.main.RawWeightedAddress.from_str') as mock_from_str, \
             patch('dispatch.main.WeightedAddress.resolve') as mock_resolve, \
             patch('dispatch.main.run_server') as mock_run_server:

            mock_from_str.return_value = Mock()
            mock_resolve.return_value = [Mock()]
            mock_run_server.side_effect = KeyboardInterrupt()

            result = runner.invoke(cli, ['start', '192.168.1.100'])

            # Should handle the KeyboardInterrupt gracefully
            # Exit code might vary depending on how Click handles KeyboardInterrupt
            assert result.exit_code in [0, 1, 130]  # Common exit codes for interrupts

    def test_system_exit_handling(self) -> None:
        """Test that sys.exit calls are handled properly."""
        runner = CliRunner()

        with patch('dispatch.main.install_logging'), \
             patch('dispatch.main.RawWeightedAddress.from_str') as mock_from_str:

            mock_from_str.side_effect = ValueError("Parse error")

            result = runner.invoke(cli, ['start', 'bad-address'])

            # Should exit with code 1 due to parse error
            assert result.exit_code == 1


class TestIntegrationScenarios:
    """Integration tests for main CLI functionality."""

    def test_complete_list_workflow(self) -> None:
        """Test complete list command workflow."""
        runner = CliRunner()

        with patch('dispatch.main.install_logging') as mock_install_logging, \
             patch('dispatch.main.list_interfaces') as mock_list_interfaces:

            mock_install_logging.return_value = '/tmp/test.log'

            result = runner.invoke(cli, ['--debug', 'list'])

            assert result.exit_code == 0

            # Verify logging was configured
            mock_install_logging.assert_called_once_with(LogStrategy.STDOUT)

            # Verify list_interfaces was called
            mock_list_interfaces.assert_called_once()

    def test_complete_start_workflow(self) -> None:
        """Test complete start command workflow."""
        runner = CliRunner()

        with patch('dispatch.main.install_logging') as mock_install_logging, \
             patch('dispatch.main.run_server') as mock_run_server:

            mock_install_logging.return_value = '/tmp/test.log'

            # Use realistic address resolution
            with patch('dispatch.main.WeightedAddress.resolve') as mock_resolve:
                mock_addr = WeightedAddress(
                    interface=Interface(ip=ipaddress.IPv4Address('192.168.1.100')),
                    weight=2
                )
                mock_resolve.return_value = [mock_addr]

                result = runner.invoke(cli, [
                    'start',
                    '--ip', '0.0.0.0',
                    '--port', '1080',
                    '192.168.1.100/2'
                ])

                assert result.exit_code == 0

                # Verify complete workflow
                mock_install_logging.assert_called_once_with(LogStrategy.FILE)
                mock_run_server.assert_called_once_with('0.0.0.0', 1080, [mock_addr])

    def test_error_recovery_scenarios(self) -> None:
        """Test various error recovery scenarios."""
        runner = CliRunner()

        # Test multiple error conditions
        error_scenarios = [
            ('invalid/weight/too/many', "Error parsing address"),
            ('192.168.1.100/0', "Weight must be positive"),
            ('192.168.1.100/-1', "Weight must be positive"),
        ]

        for address, expected_error in error_scenarios:
            with patch('dispatch.main.install_logging'):
                result = runner.invoke(cli, ['start', address])

                assert result.exit_code == 1
                assert expected_error in result.output or "Error" in result.output

    def test_cli_context_preservation(self) -> None:
        """Test that CLI context is properly preserved across commands."""
        runner = CliRunner()

        # Test that debug flag affects logging throughout the command chain
        with patch('dispatch.main.install_logging') as mock_install_logging, \
             patch('dispatch.main.list_interfaces'):

            # Test debug flag
            result = runner.invoke(cli, ['--debug', 'list'])
            assert result.exit_code == 0
            mock_install_logging.assert_called_with(LogStrategy.STDOUT)

            # Reset mock
            mock_install_logging.reset_mock()

            # Test without debug flag
            result = runner.invoke(cli, ['list'])
            assert result.exit_code == 0
            mock_install_logging.assert_called_with(LogStrategy.FILE)

    def test_main_function_integration(self) -> None:
        """Test main function integration with actual CLI."""
        with patch.object(sys, 'argv', ['dispatch', '--version']), \
             patch('dispatch.main.cli') as mock_cli:

            main()

            # Verify CLI was called
            mock_cli.assert_called_once_with(standalone_mode=False)
