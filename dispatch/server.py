"""
SOCKS proxy server implementation.
"""

import asyncio
import logging
import ipaddress
from typing import List, Tuple, Union

from colorama import Fore, Style

from .dispatcher import WeightedAddress, WeightedRoundRobinDispatcher
from .socks import SocksHandshake, SocksError

# Set up logging
logger = logging.getLogger(__name__)

async def pipe(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    """
    Pipe data from reader to writer.
    
    Args:
        reader: The stream reader
        writer: The stream writer
    """
    try:
        while True:
            data = await reader.read(8192)
            if not data:
                break
                
            writer.write(data)
            await writer.drain()
    except ConnectionResetError:
        # Connection reset by peer - just end the pipe
        pass
    except asyncio.CancelledError:
        # Task cancelled - just end the pipe
        raise
    except Exception as e:
        logger.warning(f"Error in pipe: {e}")

async def handle_client(client_reader: asyncio.StreamReader, 
                        client_writer: asyncio.StreamWriter,
                        dispatcher: WeightedRoundRobinDispatcher) -> None:
    """
    Handle a client connection.
    
    Args:
        client_reader: The client stream reader
        client_writer: The client stream writer
        dispatcher: The dispatcher to use for selecting local addresses
    """
    client_addr = client_writer.get_extra_info('peername')
    
    try:
        # Perform SOCKS handshake
        handshake = SocksHandshake(client_reader, client_writer, dispatcher)
        target_reader, target_writer = await handshake.handshake()
        
        target_addr = target_writer.get_extra_info('peername')
        
        logger.info(f"Connection initiated between {client_addr} and {target_addr}")
        
        # Create pipes in both directions
        client_to_target = asyncio.create_task(pipe(client_reader, target_writer))
        target_to_client = asyncio.create_task(pipe(target_reader, client_writer))
        
        # Wait for either pipe to finish
        done, pending = await asyncio.wait(
            [client_to_target, target_to_client],
            return_when=asyncio.FIRST_COMPLETED
        )
        
        # Cancel the other pipe
        for task in pending:
            task.cancel()
            
        # Handle any exceptions
        for task in done:
            try:
                await task
            except Exception as e:
                logger.warning(f"Error in pipe task: {e}")
        
        logger.info(f"Connection terminated between {client_addr} and {target_addr}")
    
    except SocksError as e:
        logger.warning(f"SOCKS error for {client_addr}: {e}")
    except ConnectionError as e:
        logger.warning(f"Connection error for {client_addr}: {e}")
    except Exception as e:
        logger.warning(f"Unexpected error for {client_addr}: {e}")
    finally:
        # Ensure the client connection is closed
        try:
            client_writer.close()
            await client_writer.wait_closed()
        except Exception:
            pass

async def start_server(host: str, port: int, addresses: List[WeightedAddress]) -> None:
    """
    Start the SOCKS proxy server.
    
    Args:
        host: The host to listen on
        port: The port to listen on
        addresses: The addresses to dispatch connections to
    """
    # Create the dispatcher
    dispatcher = WeightedRoundRobinDispatcher(addresses)
    
    # Start the server
    server = await asyncio.start_server(
        lambda r, w: handle_client(r, w, dispatcher),
        host, 
        port
    )
    
    addr = server.sockets[0].getsockname()
    
    print(f"SOCKS proxy started on {Fore.CYAN}{addr[0]}:{addr[1]}{Style.RESET_ALL}")
    print(
        f"Dispatching to {Fore.CYAN}{len(addresses)}{Style.RESET_ALL} "
        f"{Fore.GREEN}{'addresses' if len(addresses) > 1 else 'address'}{Style.RESET_ALL}:"
    )
    
    for address in addresses:
        print(f"  {Fore.YELLOW}{address}{Style.RESET_ALL}")
    
    async with server:
        await server.serve_forever()

def run_server(host: str, port: int, addresses: List[WeightedAddress]) -> None:
    """
    Run the SOCKS proxy server.
    
    Args:
        host: The host to listen on
        port: The port to listen on
        addresses: The addresses to dispatch connections to
    """
    try:
        asyncio.run(start_server(host, port, addresses))
    except KeyboardInterrupt:
        print(f"\n{Fore.RED}Server stopped{Style.RESET_ALL}")
    except Exception as e:
        print(f"{Fore.RED}Error starting server: {e}{Style.RESET_ALL}") 