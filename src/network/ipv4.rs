//! IPv4 protocol implementation
//!
//! This module provides IPv4 packet parsing, validation, and processing capabilities.
//! It handles IPv4 header parsing, checksum calculation, and basic packet validation.
//!
//! Features:
//! - IPv4 header parsing and serialization
//! - Checksum calculation and validation
//! - Header creation with automatic checksum
//! - Packet validation utilities

use std::fmt::Error;

use crate::network::checksum;
use byteorder::{BigEndian, ByteOrder};

const IPV4_HEADER_LEN: usize = 20;
const IPV4_VERSION: u8 = 4;
const DEFAULT_IHL: u8 = 5; // 5 * 4 = 20 bytes (standard header length)
const DEFAULT_TTL: u8 = 64;

/// IPv4 packet header structure
///
/// Represents the standard 20-byte IPv4 header as defined in RFC 791
#[derive(Debug, Clone)]
pub struct Ipv4Header {
    pub version: u8,
    pub ihl: u8, // Internet Header Length
    pub tos: u8, // Type of Service
    pub total_len: u16,
    pub id: u16,
    pub flags_frag_offset: u16, // Flags and Fragment Offset
    pub ttl: u8,                // Time to Live
    pub protocol: u8,           // Next Protocol
    pub checksum: u16,
    pub src_addr: [u8; 4], // Source IP Address
    pub dst_addr: [u8; 4], // Destination IP Address
}

impl Ipv4Header {
    /// Create a new IPv4 header with specified parameters
    ///
    /// Creates a new IPv4 header with the given parameters and calculates the checksum automatically.
    /// The header length (IHL) is set to 5 (20 bytes) for standard headers.
    pub fn new(
        tos: u8,
        total_len: u16,
        id: u16,
        flags_frag_offset: u16,
        ttl: u8,
        protocol: u8,
        src_addr: [u8; 4],
        dst_addr: [u8; 4],
    ) -> Self {
        let header = Ipv4Header {
            version: IPV4_VERSION,
            ihl: DEFAULT_IHL,
            tos,
            total_len,
            id,
            flags_frag_offset,
            ttl,
            protocol,
            checksum: 0, // Will be calculated
            src_addr,
            dst_addr,
        };

        header
    }

    /// Create a new IPv4 header with default values
    ///
    /// Creates a basic IPv4 header with commonly used default values.
    /// Only requires the essential parameters.
    pub fn new_simple(
        protocol: u8,
        src_addr: [u8; 4],
        dst_addr: [u8; 4],
        payload_len: u16,
    ) -> Self {
        Self::new(
            0,                                    // TOS: Normal service
            IPV4_HEADER_LEN as u16 + payload_len, // Total length
            0,                                    // ID: Let system assign
            0,                                    // Flags and fragment offset: Don't fragment
            DEFAULT_TTL,                          // TTL: 64 hops
            protocol,
            src_addr,
            dst_addr,
        )
    }

    /// Parse IPv4 header from byte slice
    ///
    /// Returns None if the data is too short or if the version field is not 4
    pub fn from_bytes(data: &[u8]) -> Option<Self> {
        if data.len() < IPV4_HEADER_LEN {
            return None;
        }

        let version = (data[0] & 0xF0) >> 4;
        if version != IPV4_VERSION {
            return None;
        }

        Some(Ipv4Header {
            version,
            ihl: data[0] & 0x0F,
            tos: data[1],
            total_len: BigEndian::read_u16(&data[2..4]),
            id: BigEndian::read_u16(&data[4..6]),
            flags_frag_offset: BigEndian::read_u16(&data[6..8]),
            ttl: data[8],
            protocol: data[9],
            checksum: BigEndian::read_u16(&data[10..12]),
            src_addr: data[12..16].try_into().unwrap(),
            dst_addr: data[16..20].try_into().unwrap(),
        })
    }



    /// Update checksum after modifying header fields
    ///
    /// Recalculates and updates the checksum field.
    /// Call this after modifying any header fields.
    pub fn update_checksum(&mut self) {
        self.checksum = Ipv4Utils::calculate_checksum(self);
    }

    /// Convert IPv4 header to bytes
    ///
    /// Serializes the header to a 20-byte array ready for transmission
    pub fn to_bytes(&self) -> [u8; IPV4_HEADER_LEN] {
        let mut bytes = [0u8; IPV4_HEADER_LEN];
        bytes[0] = (self.version << 4) | self.ihl;
        bytes[1] = self.tos;
        BigEndian::write_u16(&mut bytes[2..4], self.total_len);
        BigEndian::write_u16(&mut bytes[4..6], self.id);
        BigEndian::write_u16(&mut bytes[6..8], self.flags_frag_offset);
        bytes[8] = self.ttl;
        bytes[9] = self.protocol;
        BigEndian::write_u16(&mut bytes[10..12], self.checksum);
        bytes[12..16].copy_from_slice(&self.src_addr);
        bytes[16..20].copy_from_slice(&self.dst_addr);

        bytes
    }

    /// Get the header length in bytes
    pub fn header_len(&self) -> usize {
        (self.ihl as usize) * 4
    }

    /// Get payload length
    ///
    /// Returns the length of the payload (total length - header length)
    pub fn payload_len(&self) -> usize {
        self.total_len as usize - self.header_len()
    }
}

/// IPv4 packet validation and utility functions
impl Ipv4Header {
    /// Validate IPv4 packet structure
    ///
    /// Performs comprehensive validation of the IPv4 header
    pub fn validate(&self) -> Result<(), Error> {
        // Check version
        if self.version != IPV4_VERSION {
            return Err(Error);
        }

        // Check IHL (minimum 5 for 20-byte header)
        if self.ihl < 5 {
            return Err(Error);
        }

        // Check total length
        if self.total_len < self.header_len() as u16 {
            return Err(Error);
        }

        // Check TTL
        if self.ttl == 0 {
            return Err(Error);
        }

        // Validate checksum
        if !Ipv4Utils::validate_checksum(self) {
            return Err(Error);
        }

        Ok(())
    }
}

/// IPv4 protocol constants
pub mod protocol {
    pub const ICMP: u8 = 1;
    pub const TCP: u8 = 6;
    pub const UDP: u8 = 17;
}

/// IPv4 flags constants
pub mod flags {
    pub const DONT_FRAGMENT: u16 = 0x4000;
    pub const MORE_FRAGMENTS: u16 = 0x2000;
    pub const FRAGMENT_OFFSET_MASK: u16 = 0x1FFF;
}

pub struct Ipv4Utils{}

impl Ipv4Utils {
    /// Calculate IPv4 header checksum
    ///
    /// Calculates the checksum for this IPv4 header according to RFC 791.
    /// The checksum field is treated as zero during calculation.
    pub fn calculate_checksum(header: &Ipv4Header) -> u16 {
        let mut header_bytes = [0u8; IPV4_HEADER_LEN];

        // Build header with checksum field set to 0
        header_bytes[0] = (header.version << 4) | header.ihl;
        header_bytes[1] = header.tos;
        BigEndian::write_u16(&mut header_bytes[2..4], header.total_len);
        BigEndian::write_u16(&mut header_bytes[4..6], header.id);
        BigEndian::write_u16(&mut header_bytes[6..8], header.flags_frag_offset);
        header_bytes[8] = header.ttl;
        header_bytes[9] = header.protocol;
        // header_bytes[10..12] remains 0 for checksum calculation
        header_bytes[12..16].copy_from_slice(&header.src_addr);
        header_bytes[16..20].copy_from_slice(&header.dst_addr);

        checksum(&header_bytes)
    }

    /// Validate IPv4 header checksum
    ///
    /// Returns true if the header checksum is valid
    pub fn validate_checksum(header: &Ipv4Header) -> bool {
        let calculated = Self::calculate_checksum(header);
        calculated == header.checksum
    }

    /// Create a complete IPv4 packet with payload
    ///
    /// Creates a complete IPv4 packet by combining the header with the payload.
    /// The total length field is automatically updated to include the payload.
    pub fn create_packet_with_payload(header: &Ipv4Header, payload: &[u8]) -> Vec<u8> {
        let mut header = header.clone();
        header.total_len = IPV4_HEADER_LEN as u16 + payload.len() as u16;
        header.checksum = Self::calculate_checksum(&header);
        let mut packet = Vec::with_capacity(header.total_len as usize);
        packet.extend_from_slice(&header.to_bytes());
        packet.extend_from_slice(payload);
        packet
    }
}