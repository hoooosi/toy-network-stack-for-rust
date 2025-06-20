use crate::network::ipv4::{protocol, Ipv4Header, Ipv4Utils};
use crate::transport::tcp::TcpSocket;
use crate::transport::udp::{UdpSocket, UdpUtils};
use crate::transport::UdpPacket;
use std::collections::HashMap;
use std::collections::VecDeque;
use std::fmt::Error;
use std::sync::mpsc::{channel, Receiver, Sender};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum IpAddr {
    V4([u8; 4]),
    V6([u8; 16]),
}

pub enum OutgoingPacketRequest {
    Udp { dst_addr: IpAddr, packet: Vec<u8> },
}

pub struct IpInterace {
    pub address: IpAddr,
    pub prefix: u8,
    pub tcp_sockets: HashMap<u16, TcpSocket>,
    pub udp_sockets: HashMap<u16, UdpSocket>,
    pub packet_receiver: Receiver<OutgoingPacketRequest>,
    pub packet_sender: Sender<OutgoingPacketRequest>,
    pub output_queue: VecDeque<Vec<u8>>,
}

impl IpInterace {
    /// Create a new network interface with the specified IP address and netmask
    pub fn new(address: IpAddr, prefix: u8) -> Self {
        let (tx, rx) = channel();
        IpInterace {
            address,
            prefix,
            tcp_sockets: HashMap::new(),
            udp_sockets: HashMap::new(),
            packet_receiver: rx,
            packet_sender: tx,
            output_queue: VecDeque::new(),
        }
    }

    pub fn process_packet(&mut self, packet: &Vec<u8>) {
        match self.address {
            IpAddr::V4(_) => {
                // Handle IPv4 packet processing
                self.process_ipv4_packet(packet);
            }
            _ => {}
        }
    }

    /// Send IP packet (supports both IPv4 and IPv6)
    /// Validates packet format, calculates checksum, and adds it to output queue
    pub fn send_ip_packet(&mut self, packet: &Vec<u8>) -> Result<(), Error> {
        if packet.is_empty() {
            return Err(Error);
        }

        // Determine IP version from the first 4 bits
        let version = (packet[0] >> 4) & 0x0F;

        match version {
            4 => {
                // IPv4 packet processing
                if packet.len() < 20 {
                    return Err(Error);
                }

                let header = Ipv4Header::from_bytes(packet).ok_or(Error)?;
                header.validate()?;
                self.output_queue.push_back(packet.clone());
                Ok(())
            }
            6 => {
                // IPv6 packet processing
                // TODO: Implement IPv6 packet handling logic
                Err(Error)
            }
            _ => Err(Error),
        }
    }

    pub fn is_for_us(&self, dst_addr: &IpAddr) -> bool {
        return dst_addr == &self.address;
    }

    pub fn bind_udp_socket(&mut self, port: u16) -> Option<&mut UdpSocket> {
        if port == 0 {
            return None;
        }
        if self.udp_sockets.contains_key(&port) {
            return Some(self.udp_sockets.get_mut(&port).unwrap());
        }
        let socket = UdpSocket::new(port, self.packet_sender.clone()).ok()?;
        self.udp_sockets.insert(port, socket);
        Some(self.udp_sockets.get_mut(&port).unwrap())
    }

    pub fn recv_udp_packet(&mut self, port: u16) -> Option<UdpPacket> {
        if let Some(socket) = self.udp_sockets.get_mut(&port) {
            if socket.has_packet() {
                return socket.recv();
            } else {
                self.wait_packet();
            }
        }
        None
    }

    fn wait_packet(&mut self) {
        while let Ok(request) = self.packet_receiver.try_recv() {
            match request {
                OutgoingPacketRequest::Udp { dst_addr, packet } => {
                    println!("recv udp packet");
                    if let Err(_) = self.send_udp_packet(&dst_addr, &packet) {
                        break;
                    }
                }
            }
        }
    }

    fn send_udp_packet(&mut self, dst_addr: &IpAddr, packet: &Vec<u8>) -> Result<(), Error> {
        // Get source IP address
        let src_addr = &self.address;

        // Validate IP address version match
        match (src_addr, dst_addr) {
            (IpAddr::V4(_), IpAddr::V4(_)) | (IpAddr::V6(_), IpAddr::V6(_)) => {}
            _ => return Err(Error),
        }

        // Parse UDP header
        let final_packet = packet.clone();
        UdpUtils::validate_udp_packet(src_addr, dst_addr, &final_packet)?;

        // Create IP packet based on IP version
        let ip_packet = match (src_addr, dst_addr) {
            (IpAddr::V4(src_ipv4), IpAddr::V4(dst_ipv4)) => {
                // Create IPv4 header
                let ipv4_header = Ipv4Header::new_simple(
                    protocol::UDP,
                    *src_ipv4,
                    *dst_ipv4,
                    packet.len() as u16,
                );

                // Create complete IPv4 packet
                Ipv4Utils::create_packet_with_payload(&ipv4_header, packet)
            }
            _ => unreachable!(),
        };

        // Send the constructed IP packet
        self.send_ip_packet(&ip_packet)?;

        Ok(())
    }
}
