//! Simple TCP/IP stack example
//!
//! This example demonstrates how to use the toy-tcp library to create
//! a basic TCP/IP stack that can handle ICMP ping requests and TCP connections.
//!
//! Usage:
//!   cargo run --example simple_tcp_stack
//!
//! Then test with:
//!   ping 10.0.0.1
//!   telnet 10.0.0.1 80

use simple_tcp::iface::interface::NetworkInterface;
use std::process::Command;
use tun_tap::{Iface, Mode};

fn main() -> std::io::Result<()> {
    // Create TUN interface
    let iface = Iface::without_packet_info("tun0", Mode::Tun)?;
    let iface_name = iface.name();
    println!("TUN device created: {}", iface_name);

    // Configure IP address: ip addr add 10.0.0.1/24 dev mytun0
    let status = Command::new("ip")
        .arg("addr")
        .arg("add")
        .arg("10.0.0.1/24")
        .arg("dev")
        .arg(iface_name)
        .status()?;

    if !status.success() {
        panic!("Failed to configure IP address for {}", iface_name);
    }

    // Bring interface up: ip link set up dev mytun0
    let status = Command::new("ip")
        .arg("link")
        .arg("set")
        .arg("up")
        .arg("dev")
        .arg(iface_name)
        .status()?;

    if !status.success() {
        panic!("Failed to bring up interface {}", iface_name);
    }

    // Create network interface handler
    const LOCAL_ADDR: [u8; 4] = [10, 0, 0, 100];
    const NETMASK: [u8; 4] = [255, 255, 255, 0];
    let mut net_iface = NetworkInterface::new(
        LOCAL_ADDR,
        NETMASK, 
    );

    println!("TCP/IP stack initialized. Listening for packets...");
    println!(
        "Try: ping {}.{}.{}.{}",
        LOCAL_ADDR[0], LOCAL_ADDR[1], LOCAL_ADDR[2], LOCAL_ADDR[3]
    );
    println!(
        "Try: telnet {}.{}.{}.{} 80",
        LOCAL_ADDR[0], LOCAL_ADDR[1], LOCAL_ADDR[2], LOCAL_ADDR[3]
    );

    // Main packet processing loop
    let mut buf = [0u8; 1504];
    loop {
        // Receive packet from TUN interface
        let nbytes = iface.recv(&mut buf)?;
        let packet_data = &mut buf[..nbytes];

        println!("Received {} bytes", nbytes);

        // Process IPv4 packet
        if let Some(response) = net_iface.process_ipv4_packet(packet_data) {
            // Send response packet
            match iface.send(&response) {
                Ok(_) => println!("Response sent successfully"),
                Err(e) => eprintln!("Failed to send response: {}", e),
            }
        }
    }
}
