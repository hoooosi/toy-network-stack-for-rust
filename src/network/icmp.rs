//! ICMP (Internet Control Message Protocol) implementation
//! 
//! This module provides ICMP packet parsing and processing capabilities.
//! It supports basic ICMP message types including Echo Request and Echo Reply.

use byteorder::{BigEndian, ByteOrder};

/// Minimum ICMP header length in bytes
const ICMP_HEADER_LEN: usize = 8;

/// ICMP message types
pub const ICMP_TYPE_ECHO_REPLY: u8 = 0;
pub const ICMP_TYPE_ECHO_REQUEST: u8 = 8;

/// ICMP packet header structure
/// 
/// Represents the standard 8-byte ICMP header as defined in RFC 792
#[derive(Debug, Clone, Copy)]
pub struct IcmpHeader {
    pub msg_type: u8,      // ICMP message type
    pub msg_code: u8,      // ICMP message code
    pub checksum: u16,     // ICMP checksum
    pub rest: [u8; 4],     // Type-specific data (e.g., identifier and sequence for echo)
}

impl IcmpHeader {
    /// Parse ICMP header from byte slice
    /// 
    /// Returns None if the data is too short to contain a valid ICMP header
    pub fn from_bytes(data: &[u8]) -> Option<Self> {
        if data.len() < ICMP_HEADER_LEN {
            return None;
        }
        
        Some(IcmpHeader {
            msg_type: data[0],
            msg_code: data[1],
            checksum: BigEndian::read_u16(&data[2..4]),
            rest: data[4..8].try_into().unwrap(),
        })
    }
    
    /// Convert ICMP header to bytes
    pub fn to_bytes(&self) -> [u8; 8] {
        let mut bytes = [0u8; 8];
        bytes[0] = self.msg_type;
        bytes[1] = self.msg_code;
        BigEndian::write_u16(&mut bytes[2..4], self.checksum);
        bytes[4..8].copy_from_slice(&self.rest);
        bytes
    }
    
    /// Check if this is an Echo Request message
    pub fn is_echo_request(&self) -> bool {
        self.msg_type == ICMP_TYPE_ECHO_REQUEST
    }
    
    /// Check if this is an Echo Reply message
    pub fn is_echo_reply(&self) -> bool {
        self.msg_type == ICMP_TYPE_ECHO_REPLY
    }
    
    /// Get the identifier field for Echo Request/Reply messages
    pub fn identifier(&self) -> u16 {
        BigEndian::read_u16(&self.rest[0..2])
    }
    
    /// Get the sequence number field for Echo Request/Reply messages
    pub fn sequence(&self) -> u16 {
        BigEndian::read_u16(&self.rest[2..4])
    }
    
    /// Set the identifier field for Echo Request/Reply messages
    pub fn set_identifier(&mut self, id: u16) {
        BigEndian::write_u16(&mut self.rest[0..2], id);
    }
    
    /// Set the sequence number field for Echo Request/Reply messages
    pub fn set_sequence(&mut self, seq: u16) {
        BigEndian::write_u16(&mut self.rest[2..4], seq);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_icmp_header_parsing() {
        let data = [
            ICMP_TYPE_ECHO_REQUEST, 0x00, // Type, Code
            0x00, 0x00,                    // Checksum (will be calculated)
            0x12, 0x34, 0x56, 0x78,       // Identifier and Sequence
        ];
        
        let header = IcmpHeader::from_bytes(&data).unwrap();
        assert_eq!(header.msg_type, ICMP_TYPE_ECHO_REQUEST);
        assert_eq!(header.msg_code, 0);
        assert!(header.is_echo_request());
        assert_eq!(header.identifier(), 0x1234);
        assert_eq!(header.sequence(), 0x5678);
    }
    
    #[test]
    fn test_icmp_header_to_bytes() {
        let header = IcmpHeader {
            msg_type: ICMP_TYPE_ECHO_REPLY,
            msg_code: 0,
            checksum: 0x1234,
            rest: [0x56, 0x78, 0x9a, 0xbc],
        };
        
        let bytes = header.to_bytes();
        assert_eq!(bytes[0], ICMP_TYPE_ECHO_REPLY);
        assert_eq!(bytes[1], 0);
        assert_eq!(BigEndian::read_u16(&bytes[2..4]), 0x1234);
        assert_eq!(&bytes[4..8], &[0x56, 0x78, 0x9a, 0xbc]);
    }
}