"""
Debug logging utilities.
"""

import logging
import sys
import os
import tempfile
from enum import Enum
from datetime import datetime
from typing import Union
import types

# Set up logger
logger = logging.getLogger('python_dispatch')

class LogStrategy(Enum):
    """Strategy for log output."""
    STDOUT = 'stdout'
    FILE = 'file'

def configure_logging(strategy: LogStrategy = LogStrategy.FILE) -> Union[str, None]:
    """
    Configure logging based on the selected strategy.
    
    Args:
        strategy: The logging strategy to use
    
    Returns:
        The path to the log file if FILE strategy is used, None otherwise
    """
    logger.setLevel(logging.DEBUG)

    # Create formatter
    formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )

    # Remove existing handlers
    for handler in logger.handlers[:]:
        logger.removeHandler(handler)

    if strategy == LogStrategy.STDOUT:
        # Log to stdout
        handler = logging.StreamHandler(sys.stdout)
        handler.setFormatter(formatter)
        logger.addHandler(handler)
        return None

    # Log to file
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    log_dir = os.path.join(tempfile.gettempdir(), "python_dispatch")
    os.makedirs(log_dir, exist_ok=True)

    log_file = os.path.join(log_dir, f"python_dispatch_{timestamp}.log")

    handler = logging.FileHandler(log_file)
    handler.setFormatter(formatter)
    logger.addHandler(handler)

    return log_file

def exception_handler(
    exc_type: type[BaseException],
    exc_value: BaseException,
    exc_traceback: Union[types.TracebackType, None]
) -> None:
    """
    Custom exception handler to log uncaught exceptions.
    
    Args:
        exc_type: Exception type
        exc_value: Exception value
        exc_traceback: Exception traceback
    """
    if issubclass(exc_type, KeyboardInterrupt):
        # Let KeyboardInterrupt pass through
        sys.__excepthook__(exc_type, exc_value, exc_traceback)
        return

    logger.critical("Uncaught exception", exc_info=(exc_type, exc_value, exc_traceback))

    # Call the default exception handler
    sys.__excepthook__(exc_type, exc_value, exc_traceback)

def install_logging(strategy: LogStrategy = LogStrategy.FILE) -> Union[str, None]:
    """
    Install logging configuration and exception handler.
    
    Args:
        strategy: The logging strategy to use
    
    Returns:
        The path to the log file if FILE strategy is used, None otherwise
    """
    log_file = configure_logging(strategy)

    # Install exception handler
    sys.excepthook = exception_handler

    return log_file
