//! Network layer protocols implementation
//! 
//! This module contains implementations for network layer protocols:
//! - IPv4: Internet Protocol version 4
//! - ICMP: Internet Control Message Protocol

pub mod ipv4;
pub mod icmp;

// Re-export commonly used items
pub use ipv4::Ipv4Header;
pub use icmp::{IcmpHeader, ICMP_TYPE_ECHO_REQUEST, ICMP_TYPE_ECHO_REPLY};