//!
//! This example demonstrates the VirtualNetwork implementation with IP pool management.
//! It shows how to:
//! - Create a VirtualNetwork instance
//! - Add multiple network interfaces to the IP pool
//! - Process packets and distribute them to appropriate interfaces
//! - Handle multiple IP addresses on a single TUN device
//!
//! To run this example:
//!
//! ```sh
//! sudo cargo run --example virtual_network_demo
//! ```
//!
//! Note: Root/sudo privileges are required to create and configure the TUN device.
//! The program will create a virtual network interface and demonstrate packet routing
//! across multiple IP addresses.

use toy_network::iface::virtual_network::VirtualNetwork;
use std::io::Result;

mod utils;
use utils::network::configure_interface;

fn main() -> Result<()> {
    println!("Starting Virtual Network Demo...");
    
    // Create VirtualNetwork instance
    let mut vnet = VirtualNetwork::new("vnet0")?;
    let iface_name = vnet.interface_name();
    println!("Created virtual network on interface: {}", iface_name);
    
    // Configure the TUN interface with a base IP
    configure_interface(iface_name, "10.0.0.254/24")?;
    
    // Add multiple network interfaces to the IP pool
    println!("\nAdding network interfaces to IP pool...");
    
    // Add interface
    vnet.add_interface([10, 0, 0, 1], [255, 255, 255, 0])?;
    vnet.add_interface([10, 0, 0, 2], [255, 255, 255, 0])?;
    vnet.add_interface([10, 0, 0, 3], [255, 255, 255, 0])?;
    vnet.add_interface([10, 0, 0, 4], [255, 255, 255, 0])?;
    
    // Display current configuration
    let stats = vnet.get_stats();
    println!("\nVirtual Network Configuration:");
    println!("- Total interfaces: {}", stats.total_interfaces);
    println!("- Active connections: {}", stats.active_connections);
    if let Some(default_ip) = stats.default_interface {
        println!("- Default interface: {}.{}.{}.{}", 
                 default_ip[0], default_ip[1], default_ip[2], default_ip[3]);
    }
    
    println!("\nAvailable IP addresses:");
    for ip in vnet.get_available_ips() {
        println!("  - {}.{}.{}.{}", ip[0], ip[1], ip[2], ip[3]);
    }
    
    println!("\nStarting packet processing loop...");
    println!("Try pinging the configured IP addresses:");
    println!("\nPress Ctrl+C to stop\n");
    
    // Start the main processing loop
    vnet.run()?;
    
    Ok(())
}