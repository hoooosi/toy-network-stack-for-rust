//! UDP (User Datagram Protocol) implementation
//!
//! This module provides UDP packet parsing capabilities.

use crate::iface::ip::{IpAddr, OutgoingPacketRequest};
use crate::network::checksum;
use byteorder::{BigEndian, ByteOrder};
use std::collections::VecDeque;
use std::fmt::Error;
use std::sync::mpsc::Sender;

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
    pub packet_sender: Sender<OutgoingPacketRequest>,
    pub rx_queue: VecDeque<UdpPacket>,
}

impl UdpSocket {
    /// Creates a new UDP socket bound to a specific port.
    pub fn new(port: u16, packet_sender: Sender<OutgoingPacketRequest>) -> Result<Self, Error> {
        if port == 0 {
            return Err(Error);
        }

        Ok(UdpSocket {
            bind_port: port,
            packet_sender,
            rx_queue: VecDeque::new(),
        })
    }

    /// Enqueues a packet that has arrived for this socket.
    /// This is called by the network interface.
    pub(crate) fn enqueue_packet(&mut self, packet: UdpPacket) -> Result<(), Error> {
        self.rx_queue.push_back(packet);
        Ok(())
    }

    pub fn send_to(&self, dst_addr: IpAddr, packet: Vec<u8>) -> Result<(), Error> {
        let request = OutgoingPacketRequest::Udp { dst_addr, packet };
        self.packet_sender.send(request).map_err(|_| Error)?;
        Ok(())
    }

    /// Dequeues a packet for the application to process.
    pub fn recv(&mut self) -> Option<UdpPacket> {
        self.rx_queue.pop_front()
    }

    pub fn has_packet(&self) -> bool {
        !self.rx_queue.is_empty()
    }
}

pub struct UdpUtils {}
impl UdpUtils {
    /// Calculate UDP checksum with pseudo header
    pub fn calculate_udp_checksum(src_ip: &IpAddr, dst_ip: &IpAddr, udp_packet: &[u8]) -> u16 {
        let udp_len = udp_packet.len() as u16;

        match (src_ip, dst_ip) {
            (IpAddr::V4(src), IpAddr::V4(dst)) => {
                // Create IPv4 pseudo header: src_ip(4) + dst_ip(4) + zero(1) + protocol(1) + udp_len(2) = 12 bytes
                let mut pseudo_header = Vec::with_capacity(12 + udp_packet.len());
                pseudo_header.extend_from_slice(src);
                pseudo_header.extend_from_slice(dst);
                pseudo_header.push(0); // Zero byte
                pseudo_header.push(17); // UDP protocol number
                pseudo_header.extend_from_slice(&udp_len.to_be_bytes());
                pseudo_header.extend_from_slice(udp_packet);

                checksum(&pseudo_header)
            }
            _ => {
                // Mismatched IP versions, return 0 (invalid)
                0
            }
        }
    }

    /// Validate UDP packet
    pub fn validate_udp_packet(
        src_ip: &IpAddr,
        dst_ip: &IpAddr,
        packet: &[u8],
    ) -> Result<(), Error> {
        if packet.len() < UDP_HEADER_LEN {
            return Err(Error);
        }

        let header = UdpHeader::from_bytes(packet).ok_or(Error)?;

        // Validate length
        if header.length as usize != packet.len() {
            return Err(Error);
        }

        // Validate checksum (if not zero)
        if header.checksum != 0 {
            let calculated_checksum = UdpUtils::calculate_udp_checksum(src_ip, dst_ip, packet);
            if calculated_checksum != 0 {
                return Err(Error);
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
        src_ip: &IpAddr,
        dst_ip: &IpAddr,
        src_port: u16,
        dst_port: u16,
        payload: &[u8],
    ) -> Vec<u8> {
        let mut packet = UdpUtils::create_raw_udp_packet(src_port, dst_port, payload);

        // Calculate and set checksum
        let checksum = UdpUtils::calculate_udp_checksum(src_ip, dst_ip, &packet);
        BigEndian::write_u16(&mut packet[6..8], checksum);

        packet
    }
}
