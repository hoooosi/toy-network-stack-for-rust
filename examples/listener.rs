//! A TUN interface packet sniffer example
//!
//! This example demonstrates how to create a network packet sniffer using a TUN interface.
//! It captures all incoming IPv4 packets and displays their contents including:
//! - IP headers
//! - Protocol information
//! - Payload data
//!
//! To run this example:
//!
//! ```sh
//! cargo run --example listener
//! ```
//!
//! Note: Root/sudo privileges are required to create and configure the TUN device.
//! The program will create a virtual network interface (tun0) and monitor all IPv4
//! traffic passing through it.

use toy_network::{iface::ip, Ipv4Header};
use tun_tap::{Iface, Mode};

mod utils;
use utils::network::configure_interface;

fn main() -> std::io::Result<()> {
    println!("Starting network packet listener...");

    // Create TUN interface
    let iface = Iface::without_packet_info("tun0", Mode::Tun)?;
    let iface_name = iface.name();
    println!("TUN device created: {}", iface_name);

    // Configure IP address and bring interface up
    configure_interface(iface_name, "10.0.0.254/24")?;

    let mut local_ip = ip::IpInterace::new(ip::IpAddr::V4([10, 0, 0, 1]), 24);

    let mut packet_count = 0;
    let mut buf = [0u8; 1504];

    loop {
        // Receive packet from TUN interface
        let nbytes = iface.recv(&mut buf)?;
        let packet = &buf[..nbytes];
        packet_count += 1;

        // Print IP header information
        println!("\n[Packet #{}] Received {} bytes", packet_count, nbytes);

        local_ip.process_packet(&packet.to_vec());

        loop {
            let output_packet = local_ip.output_queue.pop_front();
            if output_packet.is_none() {
                break;
            }
            iface.send(output_packet.unwrap().as_slice())?;
        }
    }
}
