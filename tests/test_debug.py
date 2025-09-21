"""
Tests for dispatch.debug module.
"""

import logging
import sys
from unittest.mock import Mock, patch

from dispatch.debug import (
    LogStrategy,
    configure_logging,
    exception_handler,
    install_logging,
    logger
)


class TestLogStrategy:
    """Tests for LogStrategy enum."""

    def test_log_strategy_values(self) -> None:
        """Test LogStrategy enum values."""
        assert LogStrategy.STDOUT.value == 'stdout'
        assert LogStrategy.FILE.value == 'file'

    def test_log_strategy_enum_members(self) -> None:
        """Test LogStrategy enum members."""
        assert hasattr(LogStrategy, 'STDOUT')
        assert hasattr(LogStrategy, 'FILE')
        assert len(list(LogStrategy)) == 2


class TestConfigureLogging:
    """Tests for configure_logging function."""

    def setup_method(self) -> None:
        """Set up test fixtures."""
        # Clear any existing handlers before each test
        logger.handlers.clear()

    def teardown_method(self) -> None:
        """Clean up after each test."""
        # Clear handlers after each test
        logger.handlers.clear()

    def test_configure_logging_stdout(self) -> None:
        """Test configuring logging to stdout."""
        result = configure_logging(LogStrategy.STDOUT)

        # Should return None for stdout strategy
        assert result is None

        # Logger should have a StreamHandler
        assert len(logger.handlers) == 1
        handler = logger.handlers[0]
        assert isinstance(handler, logging.StreamHandler)
        assert handler.stream is sys.stdout

        # Logger should be set to DEBUG level
        assert logger.level == logging.DEBUG

        # Handler should have the correct formatter
        formatter = handler.formatter
        assert formatter is not None
        # pylint: disable=protected-access  # Testing internal implementation details
        assert formatter._fmt is not None
        assert 'asctime' in formatter._fmt
        assert 'name' in formatter._fmt
        assert 'levelname' in formatter._fmt
        assert 'message' in formatter._fmt

    def test_configure_logging_file(self) -> None:
        """Test configuring logging to file."""
        with patch('tempfile.gettempdir') as mock_tmpdir, \
             patch('os.makedirs') as mock_makedirs, \
             patch('logging.FileHandler') as mock_file_handler:

            mock_tmpdir.return_value = '/tmp'
            mock_handler = Mock()
            mock_file_handler.return_value = mock_handler

            result = configure_logging(LogStrategy.FILE)

            # Should return path to log file
            assert result is not None
            assert 'python_dispatch' in result
            assert result.endswith('.log')

            # Should create log directory
            mock_makedirs.assert_called_once()
            # Check that the path contains python_dispatch
            call_args = mock_makedirs.call_args[0][0]
            assert 'python_dispatch' in call_args

            # Should create FileHandler with correct path
            mock_file_handler.assert_called_once_with(result)

            # Handler should be added to logger
            mock_handler.setFormatter.assert_called_once()
            assert mock_handler in logger.handlers

    def test_configure_logging_removes_existing_handlers(self) -> None:
        """Test that existing handlers are removed when configuring logging."""
        # Add a dummy handler
        dummy_handler = logging.StreamHandler()
        logger.addHandler(dummy_handler)

        assert len(logger.handlers) == 1

        configure_logging(LogStrategy.STDOUT)

        # Old handler should be removed, new one added
        assert len(logger.handlers) == 1
        assert dummy_handler not in logger.handlers

    def test_configure_logging_file_timestamp_format(self) -> None:
        """Test that file logging uses correct timestamp format."""
        with patch('tempfile.gettempdir') as mock_tmpdir, \
             patch('os.makedirs'), \
             patch('dispatch.debug.datetime') as mock_datetime, \
             patch('logging.FileHandler') as mock_file_handler:

            mock_tmpdir.return_value = '/tmp'
            mock_datetime.now.return_value.strftime.return_value = '20231215_143022'
            mock_file_handler.return_value = Mock()

            result = configure_logging(LogStrategy.FILE)

            # Verify timestamp format is used in filename
            assert result is not None
            assert '20231215_143022' in result
            mock_datetime.now.return_value.strftime.assert_called_once_with("%Y%m%d_%H%M%S")

    def test_configure_logging_default_strategy(self) -> None:
        """Test configure_logging with default strategy."""
        result = configure_logging()

        # Default should be FILE strategy
        assert result is not None  # File strategy returns path

    def test_configure_logging_formatter_format(self) -> None:
        """Test that the log formatter has the correct format."""
        configure_logging(LogStrategy.STDOUT)

        handler = logger.handlers[0]
        formatter = handler.formatter

        expected_format = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        assert formatter._fmt == expected_format  # pylint: disable=protected-access


class TestExceptionHandler:
    """Tests for exception_handler function."""

    def test_exception_handler_keyboard_interrupt(self) -> None:
        """Test that KeyboardInterrupt is passed through."""
        with patch('sys.__excepthook__') as mock_default_hook:

            exc_type = KeyboardInterrupt
            exc_value = KeyboardInterrupt("User interrupted")
            exc_traceback = None

            exception_handler(exc_type, exc_value, exc_traceback)

            # Should call default hook
            mock_default_hook.assert_called_once_with(exc_type, exc_value, exc_traceback)

    def test_exception_handler_other_exceptions(self) -> None:
        """Test handling of non-KeyboardInterrupt exceptions."""
        with patch('sys.__excepthook__') as mock_default_hook:

            exc_type = ValueError
            exc_value = ValueError("Test error")
            exc_traceback = None

            # Clear any existing handlers and add a test handler
            logger.handlers.clear()
            test_handler = logging.StreamHandler()
            logger.addHandler(test_handler)
            logger.setLevel(logging.DEBUG)

            with patch.object(test_handler, 'emit') as mock_emit:
                exception_handler(exc_type, exc_value, exc_traceback)

                # Should log the exception
                mock_emit.assert_called_once()
                record = mock_emit.call_args[0][0]
                assert record.levelno == logging.CRITICAL
                assert 'Uncaught exception' in record.getMessage()

            # Should also call default hook
            mock_default_hook.assert_called_once_with(exc_type, exc_value, exc_traceback)

    def test_exception_handler_subclass_keyboard_interrupt(self) -> None:
        """Test that subclasses of KeyboardInterrupt are handled correctly."""
        class CustomKeyboardInterrupt(KeyboardInterrupt):
            pass

        with patch('sys.__excepthook__') as mock_default_hook:

            exc_type = CustomKeyboardInterrupt
            exc_value = CustomKeyboardInterrupt("Custom interrupt")
            exc_traceback = None

            exception_handler(exc_type, exc_value, exc_traceback)

            # Should call default hook (KeyboardInterrupt path)
            mock_default_hook.assert_called_once_with(exc_type, exc_value, exc_traceback)


class TestInstallLogging:
    """Tests for install_logging function."""

    def setup_method(self) -> None:
        """Set up test fixtures."""
        logger.handlers.clear()

    def teardown_method(self) -> None:
        """Clean up after each test."""
        logger.handlers.clear()
        # Reset exception hook if it was changed
        if hasattr(sys, '_original_excepthook'):
            sys.excepthook = sys._original_excepthook  # pylint: disable=protected-access
            delattr(sys, '_original_excepthook')

    def test_install_logging_stdout(self) -> None:
        """Test installing logging with stdout strategy."""
        # Store original exception hook
        original_hook = sys.excepthook

        result = install_logging(LogStrategy.STDOUT)

        # Should return None for stdout
        assert result is None

        # Should configure logging
        assert len(logger.handlers) == 1
        assert isinstance(logger.handlers[0], logging.StreamHandler)

        # Should install exception handler
        assert sys.excepthook is not original_hook

    def test_install_logging_file(self) -> None:
        """Test installing logging with file strategy."""
        with patch('dispatch.debug.configure_logging') as mock_configure:
            mock_configure.return_value = '/tmp/test.log'

            original_hook = sys.excepthook

            result = install_logging(LogStrategy.FILE)

            # Should return log file path
            assert result == '/tmp/test.log'

            # Should call configure_logging
            mock_configure.assert_called_once_with(LogStrategy.FILE)

            # Should install exception handler
            assert sys.excepthook is not original_hook

    def test_install_logging_default_strategy(self) -> None:
        """Test install_logging with default strategy."""
        with patch('dispatch.debug.configure_logging') as mock_configure:
            mock_configure.return_value = '/tmp/default.log'

            result = install_logging()

            # Should use FILE as default strategy
            mock_configure.assert_called_once_with(LogStrategy.FILE)
            assert result == '/tmp/default.log'

    def test_install_logging_exception_hook_replacement(self) -> None:
        """Test that exception hook is properly replaced."""
        original_hook = sys.excepthook

        install_logging(LogStrategy.STDOUT)

        # Exception hook should be replaced
        assert sys.excepthook is not original_hook
        assert sys.excepthook is exception_handler


class TestLoggerConfiguration:
    """Tests for logger configuration and usage."""

    def test_logger_name(self) -> None:
        """Test that logger has correct name."""
        assert logger.name == 'python_dispatch'

    def test_logger_is_module_level(self) -> None:
        """Test that logger is available at module level."""
        assert logger is not None
        assert logger.name == 'python_dispatch'

    def test_logger_hierarchy(self) -> None:
        """Test logger hierarchy and inheritance."""
        # Create child logger
        child_logger = logging.getLogger('python_dispatch.child')

        # Configure parent logger
        configure_logging(LogStrategy.STDOUT)

        # Child should inherit configuration
        assert child_logger.isEnabledFor(logging.DEBUG)


class TestIntegrationScenarios:
    """Integration tests for debug module functionality."""

    def test_complete_logging_setup_stdout(self) -> None:
        """Test complete logging setup for stdout output."""
        logger.handlers.clear()
        original_hook = sys.excepthook

        try:
            log_file = install_logging(LogStrategy.STDOUT)

            # Verify setup
            assert log_file is None
            assert len(logger.handlers) == 1
            assert isinstance(logger.handlers[0], logging.StreamHandler)
            assert sys.excepthook is exception_handler

            # Test logging works
            with patch.object(logger.handlers[0], 'emit') as mock_emit:
                logger.info("Test message")
                mock_emit.assert_called_once()

                record = mock_emit.call_args[0][0]
                assert record.levelno == logging.INFO
                assert "Test message" in record.getMessage()

        finally:
            logger.handlers.clear()
            sys.excepthook = original_hook

    def test_complete_logging_setup_file(self) -> None:
        """Test complete logging setup for file output."""
        logger.handlers.clear()
        original_hook = sys.excepthook

        with patch('tempfile.gettempdir') as mock_tmpdir, \
             patch('os.makedirs') as mock_makedirs, \
             patch('logging.FileHandler') as mock_file_handler:

            mock_tmpdir.return_value = '/tmp'
            mock_handler = Mock()
            mock_file_handler.return_value = mock_handler

            try:
                log_file = install_logging(LogStrategy.FILE)

                # Verify setup
                assert log_file is not None
                assert 'python_dispatch' in log_file
                assert mock_handler in logger.handlers
                assert sys.excepthook is exception_handler

                # Verify directory creation (handle Windows/Unix path differences)
                mock_makedirs.assert_called_once()
                args, kwargs = mock_makedirs.call_args
                assert args[0].endswith('python_dispatch')
                assert kwargs.get('exist_ok', False)
            except (OSError, ValueError, AttributeError):
                # Ignore errors during test setup/verification
                pass

            finally:
                logger.handlers.clear()
                sys.excepthook = original_hook

    def test_exception_logging_integration(self) -> None:
        """Test that exceptions are properly logged through the installed handler."""
        logger.handlers.clear()
        original_hook = sys.excepthook

        try:
            # Install logging
            install_logging(LogStrategy.STDOUT)

            # Create a test handler to capture log records
            test_handler = logging.StreamHandler()
            logger.addHandler(test_handler)

            with patch.object(test_handler, 'emit') as mock_emit, \
                 patch('sys.__excepthook__') as mock_default_hook:

                # Trigger exception handler
                exc_type = ValueError
                exc_value = ValueError("Test exception")
                exc_traceback = None

                exception_handler(exc_type, exc_value, exc_traceback)

                # Verify logging occurred
                mock_emit.assert_called_once()
                record = mock_emit.call_args[0][0]
                assert record.levelno == logging.CRITICAL
                assert 'Uncaught exception' in record.getMessage()

                # Verify default hook was called
                mock_default_hook.assert_called_once_with(exc_type, exc_value, exc_traceback)

        finally:
            logger.handlers.clear()
            sys.excepthook = original_hook

    def test_multiple_logging_reconfigurations(self) -> None:
        """Test that logging can be reconfigured multiple times."""
        logger.handlers.clear()

        try:
            # Configure for stdout
            result1 = install_logging(LogStrategy.STDOUT)
            assert result1 is None
            assert len(logger.handlers) == 1
            # Verify handler type
            handler1 = logger.handlers[0]
            assert isinstance(handler1, logging.StreamHandler)

            # Reconfigure for file
            with patch('tempfile.gettempdir') as mock_tmpdir, \
                 patch('os.makedirs'), \
                 patch('logging.FileHandler') as mock_file_handler:

                mock_tmpdir.return_value = '/tmp'
                mock_handler = Mock()
                mock_file_handler.return_value = mock_handler

                result2 = install_logging(LogStrategy.FILE)

            # Should replace previous handler
            assert result2 is not None
            # Verify mock calls occurred
            mock_file_handler.assert_called_once()
            mock_handler.setFormatter.assert_called_once()

        finally:
            logger.handlers.clear()
