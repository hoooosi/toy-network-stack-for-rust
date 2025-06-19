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
    pub ihl: u8,                    // Internet Header Length
    pub tos: u8,                    // Type of Service
    pub total_len: u16,
    pub id: u16,
    pub flags_frag_offset: u16,     // Flags and Fragment Offset
    pub ttl: u8,                    // Time to Live
    pub protocol: u8,               // Next Protocol
    pub checksum: u16,
    pub src_addr: [u8; 4],          // Source IP Address
    pub dst_addr: [u8; 4],          // Destination IP Address
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

    /// Print IPv4 header information for debugging
    pub fn print(&self) {
        println!(
            "IP Version: {}, Total Length: {}, Source: {:?}, Destination: {:?}, Protocol: {}",
            self.version, self.total_len, self.src_addr, self.dst_addr, self.protocol
        );
    }
    
    /// Get the header length in bytes
    pub fn header_len(&self) -> usize {
        (self.ihl as usize) * 4
    }
    
    /// Check if this is a fragment
    pub fn is_fragment(&self) -> bool {
        (self.flags_frag_offset & 0x1FFF) != 0 || (self.flags_frag_offset & 0x2000) != 0
    }
    
    /// Get the fragment offset
    pub fn fragment_offset(&self) -> u16 {
        (self.flags_frag_offset & 0x1FFF) * 8
    }
}

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_checksum() {
        let data = [0x45, 0x00, 0x00, 0x3c];
        let result = checksum(&data);
        assert_ne!(result, 0); // Should not be zero for this data
    }

    #[test]
    fn test_ipv4_header_parsing() {
        let data = [
            0x45, 0x00, 0x00, 0x3c, // Version, IHL, ToS, Total Length
            0x1c, 0x46, 0x40, 0x00, // ID, Flags+Fragment Offset
            0x40, 0x06, 0xa6, 0xec, // TTL, Protocol, Checksum
            0xc0, 0xa8, 0x01, 0x01, // Source IP: 192.168.1.1
            0xc0, 0xa8, 0x01, 0x02, // Dest IP: 192.168.1.2
        ];
        
        let header = Ipv4Header::from_bytes(&data).unwrap();
        assert_eq!(header.version, 4);
        assert_eq!(header.protocol, 6); // TCP
        assert_eq!(header.src_addr, [192, 168, 1, 1]);
        assert_eq!(header.dst_addr, [192, 168, 1, 2]);
    }
}