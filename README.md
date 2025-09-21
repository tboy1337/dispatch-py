# dispatch-py

A SOCKS proxy that balances traffic between network interfaces.

*Should work on macOS, Windows, and Linux.*

This is a python rewrite of [dispatch](https://github.com/alexkirsz/dispatch) a rust rewrite of [dispatch-proxy](https://github.com/alexkirsz/dispatch-proxy), originally written in CoffeeScript and targeting Node.js.

## What dispatch-py IS and IS NOT

### What dispatch-py IS:

- A SOCKS proxy that distributes **connections** across multiple network interfaces
- A way to utilize multiple internet connections simultaneously (e.g., Ethernet and Wi-Fi)
- Effective for scenarios with multiple concurrent connections (downloads, torrents, browsing)
- A simple solution that works at the application level without special hardware or admin rights

### What dispatch-py IS NOT:

- **NOT** true channel bonding/link aggregation (doesn't combine interfaces at hardware level)
- **NOT** able to increase the speed of a single connection (each connection uses only one interface)
- **NOT** a VPN or IP masking solution (your traffic will still use your actual IP addresses)

## Installation

### From PyPI

```
pip install dispatch-proxy
```

### From source

You'll need Python 3.7 or later.

```
git clone https://github.com/tboy1337/dispatch-py.git
cd dispatch-py
pip install -r requirements.txt
```

## Rationale

You often find yourself with multiple unused internet connections—be it 5G mobile hotspot or a free Wi-Fi network—that your system won't let you use alongside your primary one.

For instance, you might have a cabled and wireless internet access, each separately capped at a specific bandwidth. By combining all of these with dispatch-py and a download manager, you can achieve a higher effective bandwidth!

## How It Works

Whenever the SOCKS proxy server receives a connection request to an address or domain, it selects one of the provided local addresses using the Weighted Round Robin algorithm. All further connection traffic will then go through the interface corresponding to the selected local address.

**Important:** Unlike true channel bonding, each individual connection only uses one interface. The bandwidth improvement comes from distributing multiple connections across multiple interfaces.

**Example:** If you have a 100Mbps Ethernet and a 50Mbps Wi-Fi:
- A single download will max out at either 100Mbps OR 50Mbps (whichever interface it's assigned to)
- Multiple downloads running concurrently can use up to 150Mbps combined

**Beware:** If the requested address or domain resolves to an IPv4 (resp. IPv6) address, an IPv4 (resp. IPv6) local address must be provided.

## Use cases

The possibilities are endless:

- Use it with a download manager or a BitTorrent client, combining multiple connections' bandwidth when downloading single files
- Combine as many interfaces as you have access to into a single load-balanced interface
- Run different apps on separate interfaces with multiple proxies (e.g. for balancing download/upload)
- Create a hotspot proxy at home that connects through Ethernet and your 5G card for all your mobile devices
- etc.

## Usage

```
$ dispatch --help
Usage: dispatch [OPTIONS] COMMAND [ARGS]...

  A SOCKS proxy that balances traffic between network interfaces.

Options:
  -d, --debug    Write debug logs to stdout instead of a file
  --version      Show the version and exit.
  --help         Show this message and exit.

Commands:
  list   Lists all available network interfaces
  start  Starts the SOCKS proxy server.
```

```
$ dispatch start --help
Usage: dispatch start [OPTIONS] ADDRESSES...

  Starts the SOCKS proxy server.

Options:
  --ip TEXT     Which IP to accept connections from
  --port INTEGER  Which port to listen to for connections
  --help          Show this message and exit.
```

## Examples

```
$ dispatch list
```

Lists all available network interfaces.

```
$ dispatch start 10.0.0.0 fdaa:bbcc:ddee:0:1:2:3:4
```

Dispatch incoming connections to local addresses `10.0.0.0` and `fdaa:bbcc:ddee:0:1:2:3:4`.

```
$ dispatch start 10.0.0.0/7 10.0.0.1/3
```

Dispatch incoming connections to `10.0.0.0` 7 times out of 10 and to `10.0.0.1` 3 times out of 10.

## Quick Start

If you don't want to install the package, you can run directly using:

```
python run_dispatch.py list
```

or 

```
python run_dispatch.py start 10.0.0.0
```

## Simulated Network Testing

For testing `dispatch-py` without requiring multiple physical network interfaces, a simulated network testing framework is included. This allows testing the load balancing functionality across multiple virtual interfaces with configurable properties:

- Bandwidth limits
- Latency/ping time
- Packet loss rates
- Interface failures

### Running Simulated Tests

To run the simulated network tests:

```
python run_simulated_tests.py
```

Options:
- `--verbose` / `-v`: Set verbosity level (0-3)
- `--fail-fast` / `-f`: Stop on first test failure  
- `--all` / `-a`: Run all tests, not just the simulated ones
- `--test` / `-t`: Run a specific test module (e.g., `test_network_simulator`)

### How It Works

The simulated network testing works by:

1. Creating virtual network interfaces with configurable properties
2. Patching Python's socket implementation to intercept network operations
3. Routing traffic through the virtual interfaces
4. Applying simulated network conditions (bandwidth, latency, packet loss)
5. Running the dispatch proxy with these virtual interfaces

This allows comprehensive testing of dispatch's behavior with different network conditions without requiring multiple physical connections.

## License
This project is licensed under the terms of the CRL license [LICENSE.md](LICENSE.md).

## Running Tests

To run all tests, use:

```
pytest
```

Ensure all dependencies are installed with:

```
pip install -r requirements.txt
```
