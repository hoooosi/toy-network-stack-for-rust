//! UDP (User Datagram Protocol) implementation
//!
//! This module provides UDP packet parsing capabilities.

use byteorder::{BigEndian, ByteOrder};
use std::{collections::VecDeque, fmt};

use crate::iface::IpAddr;
use crate::network::checksum;

/// UDP header length in bytes
const UDP_HEADER_LEN: usize = 8;

/// UDP packet header structure
///
/// Represents the standard 8-byte UDP header as defined in RFC 768
#[derive(Debug, Clone, Copy)]
pub struct UdpHeader {
    pub src_port: u16,
    pub dst_port: u16,
    pub length: u16, // Length of UDP header and data
    pub checksum: u16,
}

impl UdpHeader {
    /// Parse UDP header from byte slice
    ///
    /// Returns None if the data is too short to contain a valid UDP header
    pub fn from_bytes(data: &[u8]) -> Option<Self> {
        if data.len() < UDP_HEADER_LEN {
            return None;
        }

        Some(UdpHeader {
            src_port: BigEndian::read_u16(&data[0..2]),
            dst_port: BigEndian::read_u16(&data[2..4]),
            length: BigEndian::read_u16(&data[4..6]),
            checksum: BigEndian::read_u16(&data[6..8]),
        })
    }

    /// Convert UDP header to bytes
    pub fn to_bytes(&self) -> [u8; 8] {
        let mut bytes = [0u8; 8];
        BigEndian::write_u16(&mut bytes[0..2], self.src_port);
        BigEndian::write_u16(&mut bytes[2..4], self.dst_port);
        BigEndian::write_u16(&mut bytes[4..6], self.length);
        BigEndian::write_u16(&mut bytes[6..8], self.checksum);
        bytes
    }
}

/// Represents a received UDP packet, waiting in a socket's queue.
#[derive(Debug, Clone)]
pub struct UdpPacket {
    pub src_addr: IpAddr,
    pub packet: Vec<u8>,
}

/// Represents a UDP socket.
#[derive(Debug)]
pub struct UdpSocket {
    pub bind_port: u16,
    pub rx_queue: VecDeque<UdpPacket>,
    pub tx_queue: VecDeque<Vec<u8>>,
    pub max_rx_queue_size: usize,
    pub max_tx_queue_size: usize,
}

impl UdpSocket {
    /// Creates a new UDP socket bound to a specific port.
    pub fn new(port: u16) -> Result<Self, UdpError> {
        if port == 0 {
            return Err(UdpError::InvalidPort);
        }
        
        Ok(UdpSocket {
            bind_port: port,
            rx_queue: VecDeque::new(),
            tx_queue: VecDeque::new(),
            max_rx_queue_size: 1024,
            max_tx_queue_size: 1024,
        })
    }

    /// Creates a new UDP socket with custom queue sizes.
    pub fn with_queue_sizes(port: u16, max_rx_size: usize, max_tx_size: usize) -> Result<Self, UdpError> {
        if port == 0 {
            return Err(UdpError::InvalidPort);
        }
        
        Ok(UdpSocket {
            bind_port: port,
            rx_queue: VecDeque::new(),
            tx_queue: VecDeque::new(),
            max_rx_queue_size: max_rx_size,
            max_tx_queue_size: max_tx_size,
        })
    }

    /// Enqueues a packet that has arrived for this socket.
    /// This is called by the network interface.
    pub(crate) fn enqueue_packet(&mut self, packet: UdpPacket) -> Result<(), UdpError> {
        if self.rx_queue.len() >= self.max_rx_queue_size {
            return Err(UdpError::BufferOverflow);
        }
        self.rx_queue.push_back(packet);
        Ok(())
    }

    /// Dequeues a packet for the application to process.
    pub fn recv(&mut self) -> Option<UdpPacket> {
        self.rx_queue.pop_front()
    }

    /// Sends data to the specified destination.
    pub fn send_to(&mut self, data: &[u8], dst_addr: IpAddr, dst_port: u16) -> Result<(), UdpError> {
        if dst_port == 0 {
            return Err(UdpError::InvalidPort);
        }
        
        if self.tx_queue.len() >= self.max_tx_queue_size {
            return Err(UdpError::BufferOverflow);
        }
        
        // Create UDP packet (checksum will be calculated by the network layer)
        let packet = create_raw_udp_packet(self.bind_port, dst_port, data);
        self.tx_queue.push_back(packet);
        
        Ok(())
    }

    /// Gets the next packet from the transmit queue.
    pub(crate) fn dequeue_tx_packet(&mut self) -> Option<Vec<u8>> {
        self.tx_queue.pop_front()
    }

    /// Checks if there are packets waiting to be sent.
    pub fn has_pending_tx(&self) -> bool {
        !self.tx_queue.is_empty()
    }

    /// Gets the number of packets in the receive queue.
    pub fn rx_queue_len(&self) -> usize {
        self.rx_queue.len()
    }

    /// Gets the number of packets in the transmit queue.
    pub fn tx_queue_len(&self) -> usize {
        self.tx_queue.len()
    }
}

/// UDP error types
#[derive(Debug, Clone, PartialEq)]
pub enum UdpError {
    InvalidLength,
    InvalidChecksum,
    InvalidPort,
    BufferOverflow,
    SocketNotBound,
}

impl fmt::Display for UdpError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            UdpError::InvalidLength => write!(f, "Invalid UDP packet length"),
            UdpError::InvalidChecksum => write!(f, "Invalid UDP checksum"),
            UdpError::InvalidPort => write!(f, "Invalid port number"),
            UdpError::BufferOverflow => write!(f, "Buffer overflow"),
            UdpError::SocketNotBound => write!(f, "Socket not bound"),
        }
    }
}

/// Calculate UDP checksum with pseudo header
pub fn calculate_udp_checksum(
    src_ip: &[u8; 4],
    dst_ip: &[u8; 4],
    udp_packet: &[u8],
) -> u16 {
    let udp_len = udp_packet.len() as u16;
    
    // Create pseudo header: src_ip(4) + dst_ip(4) + zero(1) + protocol(1) + udp_len(2) = 12 bytes
    let mut pseudo_header = Vec::with_capacity(12 + udp_packet.len());
    pseudo_header.extend_from_slice(src_ip);
    pseudo_header.extend_from_slice(dst_ip);
    pseudo_header.push(0); // Zero byte
    pseudo_header.push(17); // UDP protocol number
    pseudo_header.extend_from_slice(&udp_len.to_be_bytes());
    pseudo_header.extend_from_slice(udp_packet);
    
    checksum(&pseudo_header)
}

/// Validate UDP packet
pub fn validate_udp_packet(packet: &[u8], src_ip: &[u8; 4], dst_ip: &[u8; 4]) -> Result<(), UdpError> {
    if packet.len() < UDP_HEADER_LEN {
        return Err(UdpError::InvalidLength);
    }
    
    let header = UdpHeader::from_bytes(packet).ok_or(UdpError::InvalidLength)?;
    
    // Validate length
    if header.length as usize != packet.len() {
        return Err(UdpError::InvalidLength);
    }
    
    // Validate checksum (if not zero)
    if header.checksum != 0 {
        let calculated_checksum = calculate_udp_checksum(src_ip, dst_ip, packet);
        if calculated_checksum != 0 {
            return Err(UdpError::InvalidChecksum);
        }
    }
    
    Ok(())
}

/// Creates a new UDP packet with the specified destination port and payload.
pub fn create_raw_udp_packet(src_port: u16, dst_port: u16, payload: &[u8]) -> Vec<u8> {
    const UDP_HEADER_LEN: usize = 8;
    let udp_payload_len = payload.len();
    let total_udp_len = UDP_HEADER_LEN + udp_payload_len;

    let udp_header = UdpHeader {
        src_port,
        dst_port,
        length: total_udp_len as u16,
        checksum: 0,
    };

    let mut udp_packet = Vec::with_capacity(total_udp_len);

    udp_packet.extend_from_slice(&udp_header.to_bytes());
    udp_packet.extend_from_slice(payload);

    udp_packet
}

/// Creates a complete UDP packet with proper checksum
pub fn create_udp_packet_with_checksum(
    src_ip: &[u8; 4],
    dst_ip: &[u8; 4],
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> Vec<u8> {
    let mut packet = create_raw_udp_packet(src_port, dst_port, payload);
    
    // Calculate and set checksum
    let checksum = calculate_udp_checksum(src_ip, dst_ip, &packet);
    BigEndian::write_u16(&mut packet[6..8], checksum);
    
    packet
}
