mod utils;
use std::{fmt::Error, io::Result};

use toy_network::{
    iface::{IpAddr, IpInterace},
    transport::{UdpHeader, UdpUtils},
};
use tun_tap::{Iface, Mode};
use utils::network::configure_interface;

fn main() -> Result<()> {
    let port = 7;
    let tun_name = "tun0";
    let iface = Iface::without_packet_info(tun_name, Mode::Tun)?;
    configure_interface(tun_name, "10.0.0.254/24")?;
    let mut local_ip = IpInterace::new(IpAddr::V4([10, 0, 0, 1]), 24);
    match local_ip.bind_udp_socket(port) {
        Some(socket) => socket,
        None => {
            println!("Failed to bind UDP socket");
            return Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                "Failed to bind UDP socket",
            ));
        }
    };
    let mut buf = [0u8; 1504]; // MTU + some overhead

    loop {
        // Receive packet from TUN interface
        let nbytes = iface.recv(&mut buf)?;
        let packet = &buf[..nbytes];
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

            let src_ip = match local_ip.address {
                IpAddr::V4(addr) => addr,
                IpAddr::V6(_) => panic!("IPv6 not supported"),
            };
            let dst_ip = match udp_packet.src_addr {
                IpAddr::V4(addr) => addr,
                IpAddr::V6(_) => panic!("IPv6 not supported"),
            };

            let src_addr = IpAddr::V4(src_ip);
            let dst_addr = IpAddr::V4(dst_ip);
            let udp_response = UdpUtils::create_udp_packet_with_checksum(
                &src_addr,
                &dst_addr,
                port,
                udp_header.src_port,
                udp_payload,
            );

            let socket = match local_ip.bind_udp_socket(port) {
                Some(socket) => socket,
                None => {
                    println!("Failed to bind UDP socket");
                    break;
                }
            };
            socket
                .send_to(dst_addr, udp_response)
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
        }

        loop {
            let packet = local_ip.output_queue.pop_front();
            if packet.is_none() {
                break;
            }
            let packet = packet.unwrap();
            iface.send(&packet)?;
        }
    }
}
