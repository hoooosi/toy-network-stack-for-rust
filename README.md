# Simple TCP/IP Stack in Rust

A educational implementation of a basic TCP/IP network stack in Rust. This project demonstrates fundamental networking concepts including IPv4 packet processing, ICMP handling, and TCP connection management.

## Features

- **IPv4 Protocol Support**
  - Packet parsing and validation
  - Header checksum verification
  - Fragment handling (basic)
  - Source address selection
  - Broadcast address detection

- **ICMP Protocol Support**
  - Echo Request/Reply (ping) handling
  - Automatic ICMP response generation

- **TCP Protocol Support**
  - Basic TCP state machine
  - Connection establishment (3-way handshake)
  - Connection termination
  - Packet parsing and validation

- **Network Interface Abstraction**
  - TUN/TAP interface integration
  - Protocol dispatch
  - Packet routing

## Project Structure

```
src/
├── lib.rs              # Library root and public API
├── network/            # Network layer protocols
│   ├── mod.rs
│   ├── ipv4.rs         # IPv4 implementation
│   └── icmp.rs         # ICMP implementation
├── transport/          # Transport layer protocols
│   ├── mod.rs
│   └── tcp.rs          # TCP implementation
└── iface/              # Interface abstraction
    ├── mod.rs
    └── interface.rs    # Network interface and packet processing

examples/
└── simple_tcp_stack.rs # Example TCP/IP stack application
```

## Usage

### Running the Example

1. **Build the project:**
   ```bash
   cargo build
   ```

2. **Run the example (requires root privileges for TUN interface):**
   ```bash
   sudo cargo run --example simple_tcp_stack
   ```

3. **Test ICMP (ping) functionality:**
   ```bash
   ping 10.0.0.1
   ```

4. **Test TCP connectivity:**
   ```bash
   telnet 10.0.0.1 80
   ```

### Using as a Library

Add this to your `Cargo.toml`:

```toml
[dependencies]
simple-tcp = { path = "." }
```

Example usage:

```rust
use simple_tcp::iface::interface::NetworkInterface;
use simple_tcp::network::ipv4::Ipv4Header;

// Create a network interface
let mut net_iface = NetworkInterface::new(
    [192, 168, 1, 1],      // Local IP
    [255, 255, 255, 0],    // Netmask
);

// Process incoming packet
let mut packet_data = /* your packet data */;
if let Some(response) = net_iface.process_ipv4_packet(&mut packet_data) {
    // Send response
    println!("Generated response packet");
}
```

## Architecture

### Network Layer (`src/network/`)

- **IPv4 (`ipv4.rs`)**: Core IPv4 packet processing, header validation, checksum calculation, and fragmentation handling.
- **ICMP (`icmp.rs`)**: ICMP message processing with automatic Echo Request/Reply handling.

### Transport Layer (`src/transport/`)

- **TCP (`tcp.rs`)**: TCP protocol implementation with state machine, connection management, and packet processing.

### Interface Layer (`src/iface/`)

- **Interface (`interface.rs`)**: High-level packet processing, protocol dispatch, and network interface abstraction.

## Key Components

### IPv4 Processing

- Packet validation and header parsing
- Checksum verification
- Protocol dispatch to upper layers
- Source address selection
- Broadcast and multicast handling

### ICMP Handling

- Automatic ping (Echo Request) responses
- ICMP packet generation
- Error message handling (future)

### TCP State Machine

- Connection establishment (SYN, SYN-ACK, ACK)
- Data transfer (basic)
- Connection termination (FIN, ACK)
- State tracking and validation

## Testing

Run the test suite:

```bash
cargo test
```

Run tests with output:

```bash
cargo test -- --nocapture
```

## Requirements

- Rust 1.70 or later
- Linux (for TUN/TAP interface support)
- Root privileges (for network interface creation)

## Dependencies

- `tun-tap`: TUN/TAP interface creation and management
- `byteorder`: Byte order conversion utilities

## Educational Purpose

This project is designed for educational purposes to demonstrate:

- Network protocol implementation
- Packet parsing and generation
- State machine design
- Rust systems programming
- Network interface programming

## Limitations

- Basic implementation suitable for learning
- Limited error handling
- No advanced TCP features (window scaling, congestion control, etc.)
- IPv4 only (no IPv6 support)
- Single-threaded design

## Future Enhancements

- [ ] UDP protocol support
- [ ] IPv6 support
- [ ] Advanced TCP features
- [ ] Routing table support
- [ ] Multi-threading support
- [ ] Performance optimizations
- [ ] Comprehensive error handling

## License

MIT License - see LICENSE file for details.