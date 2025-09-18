#!/usr/bin/env python3
"""
Main entry point for the SOCKS proxy.
"""

import sys
from typing import List

import click

from .debug import LogStrategy, install_logging
from .dispatcher import RawWeightedAddress, WeightedAddress
from .list import list_interfaces
from .server import run_server

@click.group()
@click.option('--debug', '-d', is_flag=True, help='Write debug logs to stdout instead of a file')
@click.version_option(version='1.0.1')
@click.pass_context
def cli(ctx: click.Context, debug: bool) -> None:
    """A SOCKS proxy that balances traffic between network interfaces."""
    # Initialize context
    ctx.ensure_object(dict)

    # Set debug mode
    ctx.obj['debug'] = debug  # type: ignore[misc]

    # Configure logging
    strategy = LogStrategy.STDOUT if debug else LogStrategy.FILE
    log_file = install_logging(strategy)

    if log_file:
        ctx.obj['log_file'] = log_file  # type: ignore[misc]

@cli.command('list')  # type: ignore[misc]
def list_interfaces_cmd() -> None:
    """Lists all available network interfaces."""
    list_interfaces()

@cli.command()  # type: ignore[misc]
@click.option('--ip', default='127.0.0.1', help='Which IP to accept connections from')
@click.option('--port', default=1080, help='Which port to listen to for connections')
@click.argument('addresses', nargs=-1, required=True)
@click.pass_context
def start(ctx: click.Context, ip: str, port: int, addresses: List[str]) -> None:
    """Starts the SOCKS proxy server."""
    # Parse addresses
    raw_addresses = []
    for addr in addresses:
        try:
            raw_addr = RawWeightedAddress.from_str(addr)
            raw_addresses.append(raw_addr)
        except ValueError as exc:
            click.echo(f"Error parsing address '{addr}': {exc}", err=True)
            sys.exit(1)

    # Resolve addresses
    try:
        resolved_addresses = WeightedAddress.resolve(raw_addresses)
    except ValueError as exc:
        click.echo(f"Error resolving addresses: {exc}", err=True)
        sys.exit(1)

    # Start server
    run_server(ip, port, resolved_addresses)

def main() -> None:
    """Run the CLI."""
    cli(standalone_mode=False)  # pylint: disable=no-value-for-parameter

if __name__ == '__main__':
    main()
