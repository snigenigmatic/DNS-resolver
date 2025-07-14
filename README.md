# DNS Resolver

A custom DNS resolver implementation in Python that demonstrates low-level network programming by building and parsing DNS packets from scratch.

## Overview

This project implements a DNS resolver that can:
- Build raw network packets including Ethernet, IP, and UDP headers
- Construct DNS query packets and parse DNS responses
- Use raw sockets for direct packet manipulation when available
- Fall back to standard UDP sockets when necessary
- Cache DNS results to improve performance

## Requirements

- Python 3.12 or higher
- netifaces 0.11.0 or higher
- Root/administrator privileges (when using raw sockets)

## Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/username/DNS-resolver.git
   cd DNS-resolver
   ```

2. Install uv(package manager)
   ```bash
   curl -LsSf https://astral.sh/uv/install.sh | sh

   source $HOME/.local/bin/env
   ```

3. Install dependencies:
   ```bash
   uv sync
   uv lock

   ```

## Usage

### Basic Usage

```python
from dns_resolver import DNSResolver

# Create a resolver instance (needs root/administrator privileges)
resolver = DNSResolver()

try:
    # Resolve a domain
    result = resolver.resolve("google.com")
    
    if result:
        print("Resolution results:")
        for domain, ttl, ip in result:
            print(f"{domain} -> {ip} (TTL: {ttl}s)")
    else:
        print("Failed to resolve domain")
finally:
    # Clean up resources
    resolver.close()
```

### Running the Example Script

The repository includes a script to query specific domains:

```bash
# Must be run with sudo/administrator privileges for raw socket access
sudo python3 query_specific_domains.py
```

## How It Works

The resolver works by:

1. **Creating a Socket**: Attempts to create a raw socket for direct packet manipulation, with fallback to standard UDP sockets
2. **Building DNS Query**: Constructs a DNS query packet with appropriate headers
3. **Sending the Packet**: Sends the packet to a DNS server (default: 8.8.8.8)
4. **Receiving and Parsing Response**: Listens for and parses the DNS server's response
5. **Caching Results**: Stores resolved IPs with their TTL values

## Features

- **Raw Socket Implementation**: Uses AF_PACKET sockets for low-level packet construction
- **Multiple Fallback Methods**: Falls back to standard UDP sockets or system DNS if raw sockets fail
- **DNS Caching**: Caches responses to improve performance
- **Detailed Logging**: Provides debug information about the resolution process
- **Error Handling**: Includes retries and timeout handling
- **Security Measures**: Restricts resolution to specific allowed domains

## Limitations

- Requires root/administrator privileges to use raw sockets
- Currently only supports A record queries (IPv4 addresses)

## Technical Notes

- The resolver attempts to use the most appropriate network interface available
- MAC addresses are resolved using ARP lookups when possible
- DNS packet parsing includes support for compression pointers
- IP and UDP checksums are calculated manually
