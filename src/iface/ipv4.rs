use crate::iface::ip::{IpAddr, IpInterace};
use crate::network::icmp::{IcmpHeader, IcmpUtils, ICMP_TYPE_ECHO_REQUEST};
use crate::network::ipv4::Ipv4Header;
use crate::transport::{UdpHeader, UdpPacket, UdpUtils};

impl IpInterace {
    pub fn process_ipv4_packet(&mut self, packet: &Vec<u8>) {
        let ip_header = match Ipv4Header::from_bytes(packet) {
            Some(_ip_header) => _ip_header,
            None => return,
        };

        if let Err(_) = ip_header.validate() {
            return;
        }
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
                let reply_packet =
                    IcmpUtils::create_icmpv4_reply(&ip_header, &icmp_header, &packet);
                self.output_queue.push_back(reply_packet);
            }
            _ => {
                println!("Unsupported ICMP type: {}", icmp_header.msg_type);
            }
        }
    }

    #[allow(unused_variables)]
    fn process_tcp(&mut self, packet: &Vec<u8>, ip_header: &Ipv4Header) {}

    fn process_udp(&mut self, packet: &Vec<u8>, ip_header: &Ipv4Header) {
        let ip_payload = &packet[ip_header.header_len()..];

        // Validate UDP packet
        let src_addr = IpAddr::V4(ip_header.src_addr);
        let dst_addr = IpAddr::V4(ip_header.dst_addr);
        if let Err(e) = UdpUtils::validate_udp_packet(&src_addr, &dst_addr, ip_payload) {
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
