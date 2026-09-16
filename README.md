# PyTrace — Unknown Universe

A Python-based network path discovery utility built to understand how packets travel across networks and why traceroute sometimes shows `* * *`.

**Status:** Early development  
**Language:** Python  
**Focus:** Networking, Packet Analysis, Network Troubleshooting

## Overview

**PyTrace — Unknown Universe** is a Python network path discovery tool that uses ICMP packets with controlled TTL values to discover the network path between a local machine and a destination.

The project was created as a learning-driven implementation of traceroute rather than simply using an existing traceroute command.

The main goal is to understand what happens to a packet at each hop, how TTL works, how routers respond, how round-trip time is measured, and why some hops may appear as:

```text
* * *
```

PyTrace does not assume that a hidden hop exists when no response is received. A timeout is reported honestly as a timeout.

## Why I Built This

While learning networking and cybersecurity, I used the standard `traceroute` command to understand how packets travel through a network.

For example:

```text
traceroute www.google.com

1  192.168.x.x
2  * * *
3  * * *
4  * * *
```

This raised an important question:

> What is actually happening behind those `* * *` entries?

A timeout does not necessarily mean that there is no router at that hop. A router, firewall, ISP device, or network policy may simply refuse to send a response.

Instead of treating traceroute as a black box, I decided to build my own implementation in Python.

That became **PyTrace — Unknown Universe**.

## What Problem Does It Solve?

PyTrace currently provides a simple and transparent implementation of IPv4 ICMP-based path discovery.

It demonstrates:

- DNS resolution
- IPv4 packet construction
- ICMP probing
- TTL-based hop discovery
- Router responses
- Round-trip-time measurement
- Reverse DNS lookup
- Timeout handling
- Destination detection

The project follows an important principle:

```text
No response ≠ No router
```

When a probe receives no usable response within the configured timeout, PyTrace displays:

```text
*       timeout
```

It does not invent an IP address or claim that a router is present without evidence.

## How Traceroute Works

The fundamental mechanism is the **IP Time To Live (TTL)** field.

PyTrace sends probes with increasing TTL values:

```text
TTL = 1
TTL = 2
TTL = 3
TTL = 4
...
```

Conceptually:

```text
Your Computer
     |
     | TTL = 1
     v
  Router 1
     |
     | TTL = 2
     v
  Router 2
     |
     | TTL = 3
     v
  Router 3
     |
     v
 Destination
```

Each router decreases the TTL. If the TTL reaches zero before the packet reaches its destination, the router can send an ICMP response back to the sender.

PyTrace uses these responses to determine the responding hop.

## How PyTrace Sends a Probe

The core packet is constructed using Scapy:

```python
packet = IP(
    dst=destination,
    ttl=ttl
) / ICMP()
```

The packet contains:

```text
IPv4
 ├── Destination IP
 └── TTL

ICMP
 └── Echo Request
```

PyTrace then sends the packet and waits for a response:

```python
reply = sr1(
    packet,
    timeout=timeout,
    verbose=False
)
```

The response source IP is used as the responding hop:

```python
hop_ip = reply.src
```

## Example Output

```text
======================================================================
                 PyTrace — Unknown Universe
                    Network Path Discovery

Target     : google.com
Destination: 172.217.24.142
Max hops   : 30
Timeout    : 2.0s
======================================================================

HOP   IP ADDRESS          RTT         HOSTNAME
----------------------------------------------------------------------
1     192.168.1.1         31.57 ms    -
2     103.135.189.142     20.98 ms    -
3     210.16.86.205       19.89 ms    -
4     210.16.84.33        50.08 ms    -
5     72.14.209.40        24.73 ms    -
6     108.170.227.7       49.06 ms    -
7     142.251.55.91       19.27 ms    -
8     172.217.24.142      16.96 ms    syd09s06-in-f14.1e100.net
----------------------------------------------------------------------
Destination reached.
```

## Understanding the Output

### HOP

The TTL value used for the probe.

```text
1
2
3
...
```

### IP ADDRESS

The IP address of the device that responded to the probe.

### RTT

Round-trip time measured in milliseconds.

Example:

```text
31.57 ms
```

### HOSTNAME

PyTrace attempts a reverse DNS lookup for the responding IP.

If reverse DNS is unavailable:

```text
-
```

## `*` and Timeouts

A `*` or `timeout` means PyTrace did not receive a usable response within the configured timeout.

Possible reasons include:

- ICMP filtering
- Firewall rules
- Router configuration
- Rate limiting
- Network congestion
- Packet loss
- Security policies
- Devices that do not respond to the probe

Therefore:

```text
* = No usable response received
```

It does not mean:

```text
* = No router exists
```

PyTrace intentionally does not fabricate missing hop information.

## Max Hops

The default maximum hop count is:

```text
30
```

PyTrace will try TTL values from `1` through `30`.

It does not mean the network contains 30 routers. If the destination is reached earlier, PyTrace stops.

Change the value:

```bash
python -m pytrace.cli google.com --max-hops 15
```

or:

```bash
python -m pytrace.cli google.com -m 15
```

## Timeout

The default timeout is:

```text
2.0 seconds
```

This is the maximum time PyTrace waits for a response to an individual probe.

Change it with:

```bash
python -m pytrace.cli google.com --timeout 5
```

or:

```bash
python -m pytrace.cli google.com -t 5
```

## Project Architecture

```text
pytrace-unknown-universe/
│
├── pytrace/
│   ├── __init__.py
│   ├── banner.py
│   ├── cli.py
│   ├── traceroute.py
│   └── probes.py
│
├── tests/
│   └── test_traceroute.py
│
├── requirements.txt
├── README.md
├── LICENSE
├── .gitignore
└── pyproject.toml
```

### `banner.py`

Contains the PyTrace terminal banner and branding.

### `cli.py`

Handles:

- Command-line arguments
- Input validation
- Version information
- Starting the traceroute process

### `traceroute.py`

Contains the main tracing logic:

- Destination resolution
- TTL iteration
- Response processing
- Reverse DNS
- Destination detection
- Result display

### `probes.py`

Contains packet-probing functionality:

- IPv4 packet construction
- TTL configuration
- ICMP probing
- RTT measurement
- Packet operation error handling

### `tests/`

Contains automated tests for basic functionality.

## Requirements

- Python 3.9+
- Scapy 2.7.0
- Administrator/root privileges may be required for raw packet operations
- Npcap on Windows
- Linux raw-socket/packet support on Kali Linux

## Installation

### Windows

Clone the repository:

```bash
git clone <your-repository-url>
cd pytrace-unknown-universe
```

Create a virtual environment:

```bash
python -m venv .venv
```

Activate it:

```cmd
.venv\Scripts\activate
```

Install dependencies:

```bash
python -m pip install -r requirements.txt
```

Install PyTrace:

```bash
python -m pip install -e .
```

On Windows, install Npcap for packet-capture/raw-network functionality.

If raw packet operations fail with a permission error, run the terminal or VS Code as Administrator.

### Kali Linux

Clone the repository:

```bash
git clone <your-repository-url>
cd pytrace-unknown-universe
```

Create a virtual environment:

```bash
python3 -m venv .venv
```

Activate it:

```bash
source .venv/bin/activate
```

Install dependencies:

```bash
pip install -r requirements.txt
```

Install PyTrace:

```bash
pip install -e .
```

Run:

```bash
sudo .venv/bin/python -m pytrace.cli google.com
```

## Usage

Basic usage:

```bash
python -m pytrace.cli google.com
```

IPv4 address:

```bash
python -m pytrace.cli 8.8.8.8
```

Set maximum hops:

```bash
python -m pytrace.cli google.com -m 20
```

Set timeout:

```bash
python -m pytrace.cli google.com -t 3
```

Combine options:

```bash
python -m pytrace.cli google.com -m 20 -t 3
```

Show version:

```bash
python -m pytrace.cli --version
```

Show help:

```bash
python -m pytrace.cli --help
```

## Testing

Install pytest:

```bash
python -m pip install pytest
```

Run the tests:

```bash
python -m pytest
```

## Development Story

The project started with a simple question:

> How does traceroute actually discover the path to a destination?

The first step was understanding the networking concepts behind traceroute:

```text
IP
 ↓
TTL
 ↓
ICMP
 ↓
Router
 ↓
ICMP response
 ↓
RTT
```

The next step was implementing the packet manually using Python and Scapy.

During development, practical problems appeared, including Scapy import resolution, Windows raw packet permissions, and package structure.

The project was then separated into modules so that the CLI, traceroute engine, packet-probing logic, banner, and tests have separate responsibilities.

The development process helped connect networking theory with actual packet transmission.

## Current Limitations

The current version:

- Supports IPv4
- Uses ICMP probes
- Performs one probe per TTL
- Reports responding hop IP addresses
- Performs reverse DNS lookup
- Reports timeouts
- Stops when the destination responds

It does not currently:

- Guarantee discovery of every intermediate router
- Bypass firewalls or ICMP filtering
- Reveal devices that intentionally do not respond
- Perform UDP traceroute
- Perform TCP traceroute
- Perform multiple probes per hop
- Explicitly classify every ICMP response type
- Trace IPv6 paths

A timeout should therefore be interpreted as a lack of response, not proof that a hop does not exist.

## Roadmap

Future versions may introduce:

### Multi-Probe Tracing

Send multiple probes for every TTL to provide better information about packet loss and RTT variation.

### UDP Probing

Add UDP-based traceroute functionality.

### TCP Probing

Add TCP probes, including TCP/443, for networks where ICMP or UDP traffic is filtered.

### Response-Type Detection

Explicitly identify responses such as:

```text
ICMP Time Exceeded
ICMP Echo Reply
ICMP Destination Unreachable
Timeout
```

### Packet Loss Measurement

Calculate response rates per hop.

### RTT Statistics

Display:

```text
Minimum RTT
Average RTT
Maximum RTT
Packet Loss
```

### IPv6 Support

Extend the project to support IPv6 path discovery.

### Improved Output

Possible future output formats:

```text
Table
JSON
CSV
```

## Security and Responsible Use

PyTrace is a network diagnostic and educational tool.

Use it only on systems and networks that you are authorized to test.

The project is intended for:

- Networking education
- Cybersecurity learning
- Network troubleshooting
- Lab environments
- Authorized security testing

Do not use it to bypass access controls or probe networks without authorization.

## Technologies Used

```text
Python
Scapy
IPv4
ICMP
DNS
Reverse DNS
TTL
Raw Sockets
pytest
```

## Learning Objectives

PyTrace is a hands-on networking project designed to connect theoretical concepts with actual packet transmission.

```text
OSI Model
    ↓
Network Layer
    ↓
IPv4
    ↓
TTL
    ↓
ICMP
    ↓
Routers
    ↓
DNS
    ↓
Round-Trip Time
    ↓
Packet Loss
```

## Project Philosophy

The name **Unknown Universe** represents the unknown network path between a source and a destination.

A traceroute output may show some devices while other hops remain unknown.

PyTrace follows a simple principle:

> Discover what the network actually tells us, rather than inventing what we cannot observe.

```text
Observed     → Record it
Not observed → Mark it unknown
Never observed → Never fabricate it
```

## License

This project is open source.

See the `LICENSE` file for license information.

## Author

**Balashanmugam R**

Built as a hands-on networking and cybersecurity learning project.

## Project Status

Current version:

```text
0.2.0
```

Current implementation:

```text
IPv4 + ICMP + TTL-based path discovery
```

Future development will focus on improving network-path visibility while maintaining accurate handling of unknown or non-responsive hops.
