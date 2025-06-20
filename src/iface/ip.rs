use crate::transport::tcp::TcpSocket;
use crate::transport::udp::{UdpSocket, UdpError};
use crate::transport::UdpPacket;
use std::collections::HashMap;
use std::collections::VecDeque;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum IpAddr {
    V4([u8; 4]),
    V6([u8; 16]),
}

pub struct IpInterace {
    pub address: IpAddr,
    pub prefix: u8,
    pub tcp_sockets: HashMap<u16, TcpSocket>,
    pub udp_sockets: HashMap<u16, UdpSocket>,
    pub output_queue: VecDeque<Vec<u8>>,
}

impl IpInterace {
    /// Create a new network interface with the specified IP address and netmask
    pub fn new(address: IpAddr, prefix: u8) -> Self {
        IpInterace {
            address,
            prefix,
            tcp_sockets: HashMap::new(),
            udp_sockets: HashMap::new(),
            output_queue: VecDeque::new(),
        }
    }

    pub fn process_packet(&mut self, packet: &Vec<u8>) {
        match self.address {
            IpAddr::V4(addr) => {
                // Handle IPv4 packet processing
                self.process_ipv4_packet(packet);
            }
            IpAddr::V6(addr) => {
                // Handle IPv6 packet processing
                // TODO: Implement IPv6 packet handling logic
            }
        }
    }

    pub fn is_for_us(&self, dst_addr: &IpAddr) -> bool {
        return dst_addr == &self.address;
    }

    pub fn bind_udp_socket(&mut self, port: u16) -> Result<(), UdpError> {
        if self.udp_sockets.contains_key(&port) {
            return Err(UdpError::InvalidPort);
        }
        let socket = UdpSocket::new(port)?;
        self.udp_sockets.insert(port, socket);
        Ok(())
    }

    pub fn recv_udp_packet(&mut self, port: u16) -> Option<UdpPacket> {
        if let Some(socket) = self.udp_sockets.get_mut(&port) {
            return socket.recv();
        }
        None
    }

    /// Send UDP data to a destination
    pub fn send_udp(&mut self, src_port: u16, dst_addr: IpAddr, dst_port: u16, data: &[u8]) -> Result<(), UdpError> {
        if let Some(socket) = self.udp_sockets.get_mut(&src_port) {
            socket.send_to(data, dst_addr, dst_port)?;
            Ok(())
        } else {
            Err(UdpError::SocketNotBound)
        }
    }

    /// Process outgoing UDP packets and add them to output queue
    pub fn process_udp_tx(&mut self) {
        let mut packets_to_send = Vec::new();
        
        for (port, socket) in self.udp_sockets.iter_mut() {
            while let Some(udp_packet) = socket.dequeue_tx_packet() {
                packets_to_send.push(udp_packet);
            }
        }
        
        for packet in packets_to_send {
            self.output_queue.push_back(packet);
        }
    }

    /// Get the next packet from output queue
    pub fn dequeue_output(&mut self) -> Option<Vec<u8>> {
        self.output_queue.pop_front()
    }
}
