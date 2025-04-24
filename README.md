# dispatch-py

A SOCKS proxy that balances traffic between network interfaces.

*Should work on macOS, Windows, and Linux.*

This is a python rewrite of [dispatch](https://github.com/alexkirsz/dispatch) a rust rewrite of [dispatch-proxy](https://github.com/alexkirsz/dispatch-proxy), originally written in CoffeeScript and targeting Node.js.

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

You often find yourself with multiple unused internet connectionsÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â‚¬Å¡Ã‚Â¬ÃƒÂ¢Ã¢â€šÂ¬Ã‚Âbe it 5G mobile hotspot or a free Wi-Fi networkÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â‚¬Å¡Ã‚Â¬ÃƒÂ¢Ã¢â€šÂ¬Ã‚Âthat your system won't let you use alongside your primary one.

For instance, you might have a cabled and wireless internet access, each separately capped at a specific bandwidth. By combining all of these with dispatch-py and a download manager, you can achieve a higher effective bandwidth!

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

## How It Works

Whenever the SOCKS proxy server receives a connection request to an address or domain, it selects one of the provided local addresses using the Weighted Round Robin algorithm. All further connection traffic will then go through the interface corresponding to the selected local address.

**Beware:** If the requested address or domain resolves to an IPv4 (resp. IPv6) address, an IPv4 (resp. IPv6) local address must be provided.

## License
This project is licensed under the terms of the [MIT License](LICENSE.txt). 