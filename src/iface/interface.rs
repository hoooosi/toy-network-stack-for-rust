//! Network interface abstraction and packet processing
//! 
//! This module provides the main interface for packet processing, including:
//! - IPv4 packet reception and validation
//! - Protocol dispatch (ICMP, TCP, UDP)
//! - ICMP echo request/reply handling
//! - Source address selection and broadcast address handling

use crate::network::ipv4::{Ipv4Header, checksum};
use crate::network::icmp::{IcmpHeader, ICMP_TYPE_ECHO_REQUEST, ICMP_TYPE_ECHO_REPLY};
use crate::transport::tcp::{TcpHeader, Connection};
use std::collections::HashMap;

/// Network interface for packet processing
pub struct NetworkInterface {
    /// Local IPv4 address
    pub local_addr: [u8; 4],
    /// Network mask
    pub netmask: [u8; 4],
    /// Active TCP connections
    pub tcp_connections: HashMap<u16, Connection>,
    /// Next available connection ID
    pub next_conn_id: u16,
}

impl NetworkInterface {
    /// Create a new network interface with the specified IP address and netmask
    pub fn new(local_addr: [u8; 4], netmask: [u8; 4]) -> Self {
        NetworkInterface {
            local_addr,
            netmask,
            tcp_connections: HashMap::new(),
            next_conn_id: 1,
        }
    }
    
    /// Process incoming IPv4 packet
    /// 
    /// Returns a response packet if one should be sent, None otherwise
    pub fn process_ipv4_packet(&mut self, packet_data: &mut [u8]) -> Option<Vec<u8>> {
        // Parse IPv4 header
        let ip_header = Ipv4Header::from_bytes(packet_data)?;
   
        // Validate packet is for us (unicast to our address or broadcast)
        if !self.is_for_us(&ip_header.dst_addr) {
            return None;
        }
   
        // Validate IPv4 header
        if !self.validate_ipv4_header(&ip_header, packet_data) {
            return None;
        }
        
        let header_len = ip_header.header_len();
        let payload = &packet_data[header_len..];

        // Dispatch based on protocol
        match ip_header.protocol {
            1 => self.process_icmpv4(&ip_header, payload, packet_data),
            6 => self.process_tcp(&ip_header, payload),
            17 => self.process_udp(&ip_header, payload),
            _ => {
                println!("Unsupported protocol: {}", ip_header.protocol);
                None
            }
        }
    }
    
    /// Process ICMPv4 packet
    fn process_icmpv4(&self, ip_header: &Ipv4Header, payload: &[u8], packet_data: &[u8]) -> Option<Vec<u8>> {
        let icmp_header = IcmpHeader::from_bytes(payload)?;

        match icmp_header.msg_type {
            ICMP_TYPE_ECHO_REQUEST => {
                println!("Received ICMP Echo Request, preparing reply...");
                self.icmpv4_reply(ip_header, &icmp_header, packet_data)
            }
            _ => {
                println!("Unsupported ICMP type: {}", icmp_header.msg_type);
                None
            }
        }
    }
    
    /// Generate ICMP Echo Reply
    fn icmpv4_reply(&self, ip_header: &Ipv4Header, _icmp_header: &IcmpHeader, packet_data: &[u8]) -> Option<Vec<u8>> {
        let ip_header_len = ip_header.header_len();
        
        // Create response IP header
        let mut response_data = packet_data.to_vec();
        
        // Swap source and destination addresses
        response_data[12..16].copy_from_slice(&ip_header.dst_addr);
        response_data[16..20].copy_from_slice(&ip_header.src_addr);
        
        // Update TTL
        response_data[8] = 64;
        
        // Clear IP checksum for recalculation
        response_data[10..12].copy_from_slice(&[0, 0]);
        let ip_checksum = checksum(&response_data[..ip_header_len]);
        response_data[10..12].copy_from_slice(&ip_checksum.to_be_bytes());
        
        // Update ICMP header
        response_data[ip_header_len] = ICMP_TYPE_ECHO_REPLY;
        
        // Clear ICMP checksum for recalculation
        response_data[ip_header_len + 2..ip_header_len + 4].copy_from_slice(&[0, 0]);
        let icmp_checksum = checksum(&response_data[ip_header_len..]);
        response_data[ip_header_len + 2..ip_header_len + 4].copy_from_slice(&icmp_checksum.to_be_bytes());
        
        println!("ICMP Echo Reply sent!");
        Some(response_data)
    }
    
    /// Process TCP packet
    fn process_tcp(&mut self, ip_header: &Ipv4Header, payload: &[u8]) -> Option<Vec<u8>> {
        let tcp_header = TcpHeader::from_bytes(payload)?;
        
        println!("Received TCP packet: {}:{} -> {}:{}", 
                 ip_header.src_addr.iter().map(|b| b.to_string()).collect::<Vec<_>>().join("."),
                 tcp_header.src_port,
                 ip_header.dst_addr.iter().map(|b| b.to_string()).collect::<Vec<_>>().join("."),
                 tcp_header.dst_port);
        
        // Find or create connection
        let conn_id = self.find_or_create_connection(&tcp_header);
        
        if let Some(connection) = self.tcp_connections.get_mut(&conn_id) {
            connection.on_packet(payload)
        } else {
            None
        }
    }
    
    /// Process UDP packet (placeholder)
    fn process_udp(&self, _ip_header: &Ipv4Header, _payload: &[u8]) -> Option<Vec<u8>> {
        println!("Received UDP packet (not implemented yet)");
        None
    }
    
    /// Find existing connection or create new one
    fn find_or_create_connection(&mut self, tcp_header: &TcpHeader) -> u16 {
        // Simple connection lookup by destination port
        // In a real implementation, this would use a 4-tuple (src_ip, src_port, dst_ip, dst_port)
        for (&conn_id, connection) in &self.tcp_connections {
            if connection.local_port == tcp_header.dst_port {
                return conn_id;
            }
        }
        
        // Create new connection
        let conn_id = self.next_conn_id;
        self.next_conn_id = self.next_conn_id.wrapping_add(1);
        
        let mut connection = Connection::new_with_addr(self.local_addr, tcp_header.dst_port);
        connection.remote_port = tcp_header.src_port;
        
        self.tcp_connections.insert(conn_id, connection);
        conn_id
    }
    
    /// Check if packet is destined for this interface
    fn is_for_us(&self, dst_addr: &[u8; 4]) -> bool {

        // Check if it's our unicast address
        if dst_addr == &self.local_addr {
            return true;
        }
        
        // Check if it's a broadcast address
        if self.is_broadcast_address(dst_addr) {
            return true;
        }
        
        false
    }
    
    /// Check if address is a broadcast address
    fn is_broadcast_address(&self, addr: &[u8; 4]) -> bool {
        // Limited broadcast (255.255.255.255)
        if addr == &[255, 255, 255, 255] {
            return true;
        }
        
        // Directed broadcast for our network
        let mut broadcast_addr = [0u8; 4];
        for i in 0..4 {
            broadcast_addr[i] = self.local_addr[i] | (!self.netmask[i]);
        }
        
        addr == &broadcast_addr
    }
    
    /// Validate IPv4 header
    fn validate_ipv4_header(&self, header: &Ipv4Header, packet_data: &[u8]) -> bool {
        // Check version
        if header.version != 4 {
            return false;
        }
        
        // Check header length
        let header_len = header.header_len();
        if header_len < 20 || header_len > packet_data.len() {
            return false;
        }
        
        // Check total length
        if header.total_len as usize > packet_data.len() {
            return false;
        }
        
        // Verify checksum
        let mut header_bytes = packet_data[..header_len].to_vec();
        header_bytes[10] = 0; // Clear checksum field
        header_bytes[11] = 0;
        
        let calculated_checksum = checksum(&header_bytes);
        if calculated_checksum != header.checksum {
            println!("IPv4 checksum mismatch: expected {}, got {}", 
                     header.checksum, calculated_checksum);
            return false;
        }
        
        true
    }
    
    /// Select appropriate source address for outgoing packets
    pub fn select_source_address(&self, _dst_addr: &[u8; 4]) -> [u8; 4] {
        // For now, always use our local address
        // In a more sophisticated implementation, this could consider:
        // - Multiple interfaces
        // - Routing table
        // - Source address selection rules (RFC 6724)
        self.local_addr
    }
    
    /// Get network address
    pub fn network_address(&self) -> [u8; 4] {
        let mut network = [0u8; 4];
        for i in 0..4 {
            network[i] = self.local_addr[i] & self.netmask[i];
        }
        network
    }
    
    /// Check if address is in the same network
    pub fn is_same_network(&self, addr: &[u8; 4]) -> bool {
        let our_network = self.network_address();
        let addr_network = {
            let mut network = [0u8; 4];
            for i in 0..4 {
                network[i] = addr[i] & self.netmask[i];
            }
            network
        };
        
        our_network == addr_network
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_network_interface_creation() {
        let iface = NetworkInterface::new([192, 168, 1, 1], [255, 255, 255, 0]);
        assert_eq!(iface.local_addr, [192, 168, 1, 1]);
        assert_eq!(iface.netmask, [255, 255, 255, 0]);
    }
    
    #[test]
    fn test_broadcast_detection() {
        let iface = NetworkInterface::new([192, 168, 1, 1], [255, 255, 255, 0]);
        
        // Limited broadcast
        assert!(iface.is_broadcast_address(&[255, 255, 255, 255]));
        
        // Directed broadcast
        assert!(iface.is_broadcast_address(&[192, 168, 1, 255]));
        
        // Not broadcast
        assert!(!iface.is_broadcast_address(&[192, 168, 1, 2]));
    }
    
    #[test]
    fn test_same_network_detection() {
        let iface = NetworkInterface::new([192, 168, 1, 1], [255, 255, 255, 0]);
        
        assert!(iface.is_same_network(&[192, 168, 1, 100]));
        assert!(!iface.is_same_network(&[192, 168, 2, 1]));
    }
}