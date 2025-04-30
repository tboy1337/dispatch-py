import pytest
import sys
import subprocess
from unittest.mock import patch, MagicMock
import importlib
import os

class TestStartProxy:
    """Test the start_proxy.py script."""

    def test_script_execution(self):
        """Test that the proxy script can be executed."""
        # Verify the script exists
        assert os.path.exists("start_proxy.py"), "start_proxy.py doesn't exist"
        
        # Attempt to run it with --help to avoid actually starting the proxy
        result = subprocess.run(
            [sys.executable, "start_proxy.py", "--help"],
            capture_output=True,
            text=True
        )
        
        # Check execution was successful
        assert result.returncode == 0, f"Script execution failed: {result.stderr}"
        # Verify the help text contains expected information
        assert "Usage:" in result.stdout
        assert "socks proxy" in result.stdout.lower()

    @patch('dispatch.main.main')
    def test_main_function_called(self, mock_main):
        """Test that the main function from dispatch.main is called."""
        # Set a return value for the mock
        mock_main.return_value = 0
        
        # Temporarily add the current directory to sys.path to allow importing
        old_path = sys.path.copy()
        sys.path.insert(0, '.')
        
        try:
            # Import the script
            import start_proxy
            
            # Reset the module to simulate running it as main
            importlib.reload(start_proxy)
            
            # Run the if __name__ == '__main__' block
            if hasattr(start_proxy, '_for_test'):
                start_proxy._for_test()
            
            # Verify main was called
            mock_main.assert_called_once()
        finally:
            # Restore the original path
            sys.path = old_path 