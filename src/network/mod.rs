//! Network layer protocols implementation
//!
//! This module contains implementations for network layer protocols:
//! - IPv4: Internet Protocol version 4
//! - ICMP: Internet Control Message Protocol

pub mod icmp;
pub mod ipv4;

// Re-export commonly used items
pub use icmp::{IcmpHeader, ICMP_TYPE_ECHO_REPLY, ICMP_TYPE_ECHO_REQUEST};
pub use ipv4::{Ipv4Header, flags, protocol};

/// Calculate Internet checksum
///
/// Algorithm: Sum data in 16-bit chunks, add carry bits to the sum,
/// and return the one's complement of the result.
/// This is used for both IP and ICMP checksums.
pub fn checksum(data: &[u8]) -> u16 {
    let mut sum = 0u32;

    // Process data in 2-byte chunks
    for chunk in data.chunks_exact(2) {
        sum += u16::from_be_bytes([chunk[0], chunk[1]]) as u32;
    }

    // Handle odd-length data by padding with zero
    if data.len() % 2 != 0 {
        if let Some(&last_byte) = data.last() {
            sum += (last_byte as u32) << 8;
        }
    }

    // Add carry bits
    while (sum >> 16) > 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    // Return one's complement
    !sum as u16
}
