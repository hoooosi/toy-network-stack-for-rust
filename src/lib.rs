//! A simple TCP/IP stack implementation in Rust
//! 
//! This library provides basic TCP/IP networking functionality including:
//! - IPv4 packet processing
//! - ICMP echo request/reply handling
//! - TCP connection management
//! - Network interface abstraction

pub mod network;
pub mod transport;
pub mod iface;
pub mod socket;

// Re-export commonly used types
pub use network::ipv4::Ipv4Header;
pub use network::icmp::{IcmpHeader, ICMP_TYPE_ECHO_REQUEST, ICMP_TYPE_ECHO_REPLY};
pub use transport::tcp::{TcpHeader, TcpState, Connection};
pub use iface::interface::NetworkInterface;
pub use iface::virtual_network::{VirtualNetwork, VirtualNetworkStats, Packet};