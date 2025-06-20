//! IPv4 protocol implementation
//!
//! This module provides IPv4 packet parsing, validation, and processing capabilities.
//! It handles IPv4 header parsing, checksum calculation, and basic packet validation.

use byteorder::{BigEndian, ByteOrder};

const IPV4_HEADER_LEN: usize = 20;

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
    /// Parse IPv4 header from byte slice
    ///
    /// Returns None if the data is too short or if the version field is not 4
    pub fn from_bytes(data: &[u8]) -> Option<Self> {
        if data.len() < IPV4_HEADER_LEN {
            return None;
        }

        let version = (data[0] & 0xF0) >> 4;
        if version != 4 {
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

    /// Convert IPv4 header to bytes
    pub fn to_bytes_forchecksum(&self) -> Vec<u8> {
        let mut bytes = vec![0u8; 12];
        bytes[0] = (self.version << 4) | self.ihl;
        bytes[1] = self.tos;
        BigEndian::write_u16(&mut bytes[2..4], self.total_len);
        BigEndian::write_u16(&mut bytes[4..6], self.id);
        BigEndian::write_u16(&mut bytes[6..8], self.flags_frag_offset);
        bytes[8] = self.ttl;
        bytes[9] = self.protocol;
        BigEndian::write_u16(&mut bytes[10..12], self.checksum);
        bytes
    }

    /// To bytes
    pub fn to_bytes(&self) -> [u8; 20] {
        let mut bytes = [0u8; 20];
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

    pub fn get_ip_version(data: &[u8]) -> u8 {
        let version = (data[0] & 0xF0) >> 4;
        version
    }
}
