#!/usr/bin/env python3
"""
Script to run all simulated network tests for dispatch-py.

This script runs the network simulator and socket patching tests to verify
that dispatch-py works correctly with multiple interfaces.
"""

import os
import sys
import unittest
import logging
import argparse
from typing import List, Dict, Any
import time
import json
import subprocess

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def discover_tests(pattern="test_*.py", test_dir=None, verbose=1):
    """
    Discover and return test suites matching the pattern
    
    Args:
        pattern: Test file pattern to match
        test_dir: Directory to search for tests
        verbose: Verbosity level (0-3)
    
    Returns:
        unittest.TestSuite: The discovered test suite
    """
    if test_dir is None:
        test_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "tests")
    
    logger.info(f"Discovering tests in {test_dir} with pattern {pattern}")
    
    # Create test loader
    loader = unittest.TestLoader()
    
    # If we're looking for a specific file, make sure we have the correct pattern
    if ".py" in pattern:
        pattern = os.path.basename(pattern)
    
    # Discover tests
    suite = loader.discover(test_dir, pattern=pattern)
    
    # Count tests
    test_count = suite.countTestCases()
    logger.info(f"Discovered {test_count} tests matching pattern: {pattern}")
    
    return suite

def run_test_suite(suite, verbose=1, failfast=False):
    """
    Run the test suite
    
    Args:
        suite: TestSuite to run
        verbose: Verbosity level (0-3)
        failfast: Whether to stop on first failure
    
    Returns:
        bool: Whether all tests passed
    """
    logger.info(f"Running test suite with {suite.countTestCases()} tests")
    
    # Create test runner
    runner = unittest.TextTestRunner(verbosity=verbose, failfast=failfast)
    
    # Run the suite
    result = runner.run(suite)
    
    # Return success status
    return result.wasSuccessful()

def run_tests(pattern="test_*.py", verbose=1, failfast=False):
    """
    Run tests matching the pattern
    
    Args:
        pattern: Test file pattern to match
        verbose: Verbosity level (0-3)
        failfast: Whether to stop on first failure
    
    Returns:
        bool: Whether all tests passed
    """
    # Discover tests
    suite = discover_tests(pattern=pattern, verbose=verbose)
    
    # Run tests
    return run_test_suite(suite, verbose=verbose, failfast=failfast)

def run_simulated_network_tests(verbose=1, failfast=False):
    """
    Run just the simulated network tests
    
    Args:
        verbose: Verbosity level (0-3)
        failfast: Whether to stop on first failure
    
    Returns:
        bool: Whether all tests passed
    """
    # Just run the specific simulated network tests
    simulated_test_patterns = [
        "test_network_simulator.py", 
        "test_simulated_multi_interface.py",
        "test_network_simulator_core.py"
    ]
    
    all_passed = True
    
    for pattern in simulated_test_patterns:
        logger.info(f"Running simulated tests with pattern: {pattern}")
        if not run_tests(pattern=pattern, verbose=verbose, failfast=failfast):
            all_passed = False
            if failfast:
                break
    
    return all_passed

def run_standardized_tests(category=None, verbose=1, failfast=False):
    """
    Run tests using the standardized test framework
    
    Args:
        category: Optional test category to run (network, integration, etc.)
        verbose: Verbosity level (0-3)
        failfast: Whether to stop on first failure
    
    Returns:
        bool: Whether all tests passed
    """
    # Define test categories
    test_categories = {
        "network": [
            "test_network_simulator.py",
            "test_multi_interface.py",
            "test_multi_request.py"
        ],
        "integration": [
            "test_end_to_end.py",
            "test_performance.py",
            "test_proxy_connection.py"
        ],
        "core": [
            "test_dispatcher.py",
            "test_socks.py",
            "test_connection.py",
            "test_weighted_rr.py"
        ],
        "error": [
            "test_error_handling.py"
        ]
    }
    
    # If no category specified, run all standardized tests
    if category is None:
        all_passed = True
        
        for cat, patterns in test_categories.items():
            logger.info(f"Running tests for category: {cat}")
            for pattern in patterns:
                if not run_tests(pattern=pattern, verbose=verbose, failfast=failfast):
                    all_passed = False
                    if failfast:
                        return False
        
        return all_passed
    
    # Run tests for the specified category
    if category in test_categories:
        all_passed = True
        
        for pattern in test_categories[category]:
            if not run_tests(pattern=pattern, verbose=verbose, failfast=failfast):
                all_passed = False
                if failfast:
                    return False
        
        return all_passed
    else:
        logger.error(f"Unknown test category: {category}")
        return False

def main():
    """Main function"""
    parser = argparse.ArgumentParser(description="Run simulated network tests for dispatch-py")
    
    # Test selection options
    test_group = parser.add_argument_group("Test Selection")
    test_group.add_argument(
        "--test", "-t", 
        help="Specific test module to run (default: run all simulated tests)",
        default=None
    )
    
    test_group.add_argument(
        "--category", "-c",
        help="Run a specific test category (network, integration, core, error)",
        choices=["network", "integration", "core", "error"],
        default=None
    )
    
    test_group.add_argument(
        "--all", "-a",
        help="Run all tests, not just the simulated network tests",
        action="store_true"
    )
    
    test_group.add_argument(
        "--simulated", "-s",
        help="Run just the simulated network tests",
        action="store_true"
    )
    
    # Test execution options
    execution_group = parser.add_argument_group("Test Execution")
    execution_group.add_argument(
        "--verbose", "-v",
        help="Verbosity level (0-3)",
        type=int,
        default=2
    )
    
    execution_group.add_argument(
        "--fail-fast", "-f",
        help="Stop on first test failure",
        action="store_true"
    )
    
    execution_group.add_argument(
        "--list", "-l",
        help="Just list the tests, don't run them",
        action="store_true"
    )
    
    args = parser.parse_args()
    
    start_time = time.time()
    
    if args.list:
        # Just discover and list the tests
        if args.test:
            test_pattern = args.test
            if not test_pattern.endswith(".py"):
                test_pattern = f"{test_pattern}.py"
            suite = discover_tests(pattern=test_pattern, verbose=args.verbose)
        elif args.simulated:
            logger.info("Discovering simulated network tests")
            # Combine all simulated test patterns
            suite = unittest.TestSuite()
            for pattern in ["test_network_simulator.py", "test_simulated_multi_interface.py"]:
                suite.addTests(discover_tests(pattern=pattern, verbose=args.verbose))
        elif args.category:
            logger.info(f"Discovering tests for category: {args.category}")
            # Handled by run_standardized_tests, but we just want to list
            suite = discover_tests(pattern=f"test_*.py", verbose=args.verbose)
        else:
            logger.info("Discovering all tests")
            suite = discover_tests(pattern=f"test_*.py", verbose=args.verbose)
        
        # List the tests
        for test in unittest.TestLoader().getTestCaseNames(suite.__class__):
            print(test)
        
        return 0
    
    # Run the tests
    success = False
    
    if args.test:
        # Run specific test
        logger.info(f"Running specific test: {args.test}")
        test_pattern = args.test
        if not test_pattern.endswith(".py"):
            test_pattern = f"{test_pattern}.py"
        success = run_tests(pattern=test_pattern, verbose=args.verbose, failfast=args.fail_fast)
    elif args.simulated:
        # Run just the simulated network tests
        logger.info("Running simulated network tests")
        success = run_simulated_network_tests(verbose=args.verbose, failfast=args.fail_fast)
    elif args.category:
        # Run tests in specific category
        logger.info(f"Running tests for category: {args.category}")
        success = run_standardized_tests(category=args.category, verbose=args.verbose, failfast=args.fail_fast)
    elif args.all:
        # Run all tests
        logger.info("Running all tests")
        success = run_tests(pattern="test_*.py", verbose=args.verbose, failfast=args.fail_fast)
    else:
        # Use standardized test framework
        logger.info("Running all standardized tests")
        success = run_standardized_tests(verbose=args.verbose, failfast=args.fail_fast)
    
    end_time = time.time()
    duration = end_time - start_time
    
    if success:
        logger.info(f"All tests completed successfully in {duration:.2f} seconds.")
        return 0
    else:
        logger.error(f"Some tests failed. Test run completed in {duration:.2f} seconds.")
        return 1


if __name__ == "__main__":
    sys.exit(main()) 