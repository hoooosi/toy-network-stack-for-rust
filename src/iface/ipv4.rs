use crate::iface::ip::{IpAddr, IpInterace};
use crate::network::checksum;
use crate::network::icmp::{IcmpHeader, ICMP_TYPE_ECHO_REQUEST};
use crate::network::ipv4::Ipv4Header;
use crate::transport::{UdpHeader, UdpPacket, validate_udp_packet};
use crate::ICMP_TYPE_ECHO_REPLY;

impl IpInterace {
    pub fn process_ipv4_packet(&mut self, packet: &Vec<u8>) {
        let version = Ipv4Header::get_ip_version(packet);
        if version != 4 {
            return;
        }

        let ip_header = Ipv4Header::from_bytes(packet).unwrap();
        if !self.is_for_us(&IpAddr::V4(ip_header.dst_addr)) {
            return;
        }

        // Dispatch based on protocol
        match ip_header.protocol {
            1 => self.process_icmpv4(&packet, &ip_header),
            6 => self.process_tcp(&packet, &ip_header),
            17 => self.process_udp(&packet, &ip_header),
            _ => {
                println!("Unsupported protocol: {}", ip_header.protocol);
            }
        }
    }

    fn process_icmpv4(&mut self, packet: &Vec<u8>, ip_header: &Ipv4Header) {
        let ip_payload = &packet[ip_header.header_len()..];
        let icmp_header = match IcmpHeader::from_bytes(ip_payload) {
            Some(header) => header,
            None => return,
        };
        match icmp_header.msg_type {
            ICMP_TYPE_ECHO_REQUEST => {
                println!("Received ICMP Echo Request, preparing reply...");
                self.icmpv4_reply(ip_header, &icmp_header, &packet);
            }
            _ => {
                println!("Unsupported ICMP type: {}", icmp_header.msg_type);
            }
        }
    }

    /// Generate ICMP Echo Reply
    fn icmpv4_reply(
        &mut self,
        ip_header: &Ipv4Header,
        _icmp_header: &IcmpHeader,
        ip_packet: &[u8],
    ) {
        let ip_header_len = ip_header.header_len();

        // Create response IP header
        let mut response_data = ip_packet.to_vec();

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
        response_data[ip_header_len + 2..ip_header_len + 4]
            .copy_from_slice(&icmp_checksum.to_be_bytes());

        self.output_queue.push_back(response_data);
    }

    fn process_tcp(&mut self, packet: &Vec<u8>, ip_header: &Ipv4Header) {}

    fn process_udp(&mut self, packet: &Vec<u8>, ip_header: &Ipv4Header) {
        let ip_payload = &packet[ip_header.header_len()..];
        
        // Validate UDP packet
        if let Err(e) = validate_udp_packet(ip_payload, &ip_header.src_addr, &ip_header.dst_addr) {
            println!("Invalid UDP packet: {}", e);
            return;
        }
        
        let udp_header = match UdpHeader::from_bytes(ip_payload) {
            Some(header) => header,
            None => {
                println!("Failed to parse UDP header");
                return;
            }
        };
        
        let dst_port = udp_header.dst_port;
        if let Some(socket) = self.udp_sockets.get_mut(&dst_port) {
            let udp_packet = UdpPacket {
                src_addr: IpAddr::V4(ip_header.src_addr),
                packet: ip_payload.to_vec(),
            };
            
            if let Err(e) = socket.enqueue_packet(udp_packet) {
                println!("Failed to enqueue UDP packet: {}", e);
            }
        } else {
            println!("No socket bound to port {}", dst_port);
        }
    }
}
