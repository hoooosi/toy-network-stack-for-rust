mod utils;
use byteorder::{BigEndian, ByteOrder};
use std::io::Result;

use toy_network::{
    iface::{IpAddr, IpInterace},
    network::checksum,
    transport::{UdpHeader, create_udp_packet_with_checksum, calculate_udp_checksum},
    Ipv4Header,
};
use tun_tap::{Iface, Mode};
use utils::network::{configure_interface, parse_ip_cidr};

fn main() -> Result<()> {
    let port = 7;
    let tun_name = "tun0";
    let iface = Iface::without_packet_info(tun_name, Mode::Tun)?;
    configure_interface(tun_name, "10.0.0.254/24")?;
    let mut local_ip = IpInterace::new(IpAddr::V4([10, 0, 0, 1]), 24);
    if let Err(e) = local_ip.bind_udp_socket(port) {
        eprintln!("Failed to bind UDP socket: {}", e);
        return Ok(());
    }

    let mut buf = [0u8; 1504]; // MTU + some overhead
    let mut packet_count = 0;

    loop {
        // Receive packet from TUN interface
        let nbytes = iface.recv(&mut buf)?;
        let packet = &buf[..nbytes];
        packet_count += 1;

        // Print IP header information
        println!("\n[Packet #{}] Received {} bytes", packet_count, nbytes);

        local_ip.process_packet(&packet.to_vec());

        loop {
            let udp_packet = local_ip.recv_udp_packet(port);
            if udp_packet.is_none() {
                break;
            }
            let udp_packet = udp_packet.unwrap();
            let packet = &udp_packet.packet;
            let udp_payload = &packet[8..];
            let udp_header = UdpHeader::from_bytes(packet).unwrap();
            let udp_header_len = 8;
            let ip_header_len = 20;
            let total_len = udp_payload.len() + udp_header_len + ip_header_len;
            let mut response = vec![0u8; total_len];

            response[0] = 0x45; // 版本4，头长度20字节
            response[1] = 0x00; // TOS
            BigEndian::write_u16(&mut response[2..4], total_len as u16); // 总长度
            BigEndian::write_u16(&mut response[4..6], 0x1234); // ID
            BigEndian::write_u16(&mut response[6..8], 0x4000); // 标志和片偏移
            response[8] = 64; // TTL
            response[9] = 17; // 协议 (UDP)
                              // 校验和稍后计算
            match local_ip.address {
                IpAddr::V4(addr) => response[12..16].copy_from_slice(&addr), // source address
                IpAddr::V6(_) => panic!("IPv6 not supported"), // Handle IPv6 case if needed
            }
            match udp_packet.src_addr {
                IpAddr::V4(addr) => response[16..20].copy_from_slice(&addr), // destination address
                IpAddr::V6(_) => panic!("IPv6 not supported"),
            }

            // 计算IP校验和
            let ip_checksum = checksum(&response[..ip_header_len]);
            BigEndian::write_u16(&mut response[10..12], ip_checksum);

            // 构建UDP包（带校验和）
            let src_ip = match local_ip.address {
                IpAddr::V4(addr) => addr,
                IpAddr::V6(_) => panic!("IPv6 not supported"),
            };
            let dst_ip = match udp_packet.src_addr {
                IpAddr::V4(addr) => addr,
                IpAddr::V6(_) => panic!("IPv6 not supported"),
            };
            
            let udp_response = create_udp_packet_with_checksum(
                &src_ip,
                &dst_ip,
                port,
                udp_header.src_port,
                udp_payload,
            );
            
            // 复制UDP数据到响应包
            let udp_start = ip_header_len;
            response[udp_start..udp_start + udp_response.len()].copy_from_slice(&udp_response);

            let ip_header = Ipv4Header::from_bytes(&response[..ip_header_len]).unwrap();
            println!("{:?}", ip_header);
            println!("{:?}", udp_header);

            match iface.send(&response) {
                Ok(_) => println!("Echo response sent successfully"),
                Err(e) => eprintln!("Failed to send echo response: {}", e),
            }
        }
    }
}
