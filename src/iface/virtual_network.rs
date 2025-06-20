// //!
// //! Virtual Network implementation that encapsulates TUN interface and manages IP pools.
// //! This module provides the main abstraction for the TCP/IP stack, handling:
// //! - TUN device management
// //! - IP pool management with multiple NetworkInterface instances
// //! - Packet distribution and routing
// //! - Socket API integration
// use crate::iface::interface::NetworkInterface;
// use tun_tap::{Iface, Mode};
// use std::collections::HashMap;
// use std::io::{self, Result};
// use std::sync::{Arc, Mutex};
// use std::sync::mpsc::{self, Receiver, Sender};

// /// Represents a packet with its metadata
// #[derive(Debug, Clone)]
// pub struct Packet {
//     pub data: Vec<u8>,
//     pub timestamp: std::time::Instant,
// }

// /// Virtual Network that manages TUN interface and IP pool
// pub struct VirtualNetwork {
//     /// TUN interface for communication with kernel
//     tun_iface: Iface,
//     /// Pool of network interfaces (IP addresses)
//     ip_pool: HashMap<[u8; 4], NetworkInterface>,
//     /// Default network interface for unmatched packets
//     default_interface: Option<[u8; 4]>,
//     /// Channel for sending outbound packets
//     outbound_sender: Sender<Packet>,
//     /// Channel for receiving outbound packets
//     outbound_receiver: Receiver<Packet>,
//     /// Running state
//     is_running: Arc<Mutex<bool>>,
// }

// impl VirtualNetwork {
//     /// Create a new VirtualNetwork with specified TUN device name
//     pub fn new(tun_name: &str) -> Result<Self> {
//         let tun_iface = Iface::without_packet_info(tun_name, Mode::Tun)?;
//         let (outbound_sender, outbound_receiver) = mpsc::channel();
        
//         Ok(VirtualNetwork {
//             tun_iface,
//             ip_pool: HashMap::new(),
//             default_interface: None,
//             outbound_sender,
//             outbound_receiver,
//             is_running: Arc::new(Mutex::new(false)),
//         })
//     }
    
//     /// Add a network interface to the IP pool
//     pub fn add_interface(&mut self, ip_addr: [u8; 4], netmask: [u8; 4]) -> Result<()> {
//         let interface = NetworkInterface::new(ip_addr, netmask);
//         self.ip_pool.insert(ip_addr, interface);
        
//         // Set as default if it's the first interface
//         if self.default_interface.is_none() {
//             self.default_interface = Some(ip_addr);
//         }
        
//         println!("Added network interface: {}.{}.{}.{}/{}.{}.{}.{}", 
//                  ip_addr[0], ip_addr[1], ip_addr[2], ip_addr[3],
//                  netmask[0], netmask[1], netmask[2], netmask[3]);
//         Ok(())
//     }
    
//     /// Remove a network interface from the IP pool
//     pub fn remove_interface(&mut self, ip_addr: &[u8; 4]) -> Option<NetworkInterface> {
//         let removed = self.ip_pool.remove(ip_addr);
        
//         // Update default interface if removed
//         if self.default_interface == Some(*ip_addr) {
//             self.default_interface = self.ip_pool.keys().next().copied();
//         }
        
//         if removed.is_some() {
//             println!("Removed network interface: {}.{}.{}.{}", 
//                      ip_addr[0], ip_addr[1], ip_addr[2], ip_addr[3]);
//         }
        
//         removed
//     }
    
//     /// Get a reference to a specific network interface
//     pub fn get_interface(&self, ip_addr: &[u8; 4]) -> Option<&NetworkInterface> {
//         self.ip_pool.get(ip_addr)
//     }
    
//     /// Get a mutable reference to a specific network interface
//     pub fn get_interface_mut(&mut self, ip_addr: &[u8; 4]) -> Option<&mut NetworkInterface> {
//         self.ip_pool.get_mut(ip_addr)
//     }
    
//     /// Get all available IP addresses in the pool
//     pub fn get_available_ips(&self) -> Vec<[u8; 4]> {
//         self.ip_pool.keys().copied().collect()
//     }
    
//     /// Find the appropriate interface for a destination IP
//     fn find_interface_for_packet(&self, dst_ip: &[u8; 4]) -> Option<&[u8; 4]> {
//         // First, check if any interface claims this packet
//         for (ip, interface) in &self.ip_pool {
//             if interface.local_addr == *dst_ip {
//                 return Some(ip);
//             }
            
//             // Check if it's a broadcast for this interface
//             // Note: is_broadcast_address is private, so we'll implement a simple check here
//             // Limited broadcast
//             if *dst_ip == [255, 255, 255, 255] {
//                 return Some(ip);
//             }
            
//             // Directed broadcast for this interface's network
//             let mut broadcast_addr = [0u8; 4];
//             for i in 0..4 {
//                 broadcast_addr[i] = interface.local_addr[i] | (!interface.netmask[i]);
//             }
//             if *dst_ip == broadcast_addr {
//                 return Some(ip);
//             }
//         }
        
//         // If no specific interface found, use default
//         self.default_interface.as_ref()
//     }
    
//     /// Process an incoming packet and distribute it to appropriate interface
//     pub fn process_inbound_packet(&mut self, packet_data: &mut [u8]) -> Option<Vec<u8>> {
//         if packet_data.len() < 20 {
//             return None; // Too short for IPv4 header
//         }
        
//         // Extract destination IP from IPv4 header (bytes 16-19)
//         let dst_ip = [
//             packet_data[16],
//             packet_data[17], 
//             packet_data[18],
//             packet_data[19]
//         ];
        
//         println!("Processing inbound packet for {}.{}.{}.{}", 
//                  dst_ip[0], dst_ip[1], dst_ip[2], dst_ip[3]);
        
//         // Find appropriate interface (separate from mutable access)
//         let interface_ip = self.find_interface_for_packet(&dst_ip).copied();
        
//         if let Some(ip) = interface_ip {
//             if let Some(interface) = self.ip_pool.get_mut(&ip) {
//                 return interface.process_ipv4_packet(packet_data);
//             }
//         }
        
//         println!("No interface found for packet to {}.{}.{}.{}", 
//                  dst_ip[0], dst_ip[1], dst_ip[2], dst_ip[3]);
//         None
//     }
    
//     /// Send an outbound packet through the TUN interface
//     pub fn send_outbound_packet(&mut self, packet_data: Vec<u8>) -> Result<()> {
//         let packet = Packet {
//             data: packet_data,
//             timestamp: std::time::Instant::now(),
//         };
        
//         self.outbound_sender.send(packet)
//             .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Failed to queue packet: {}", e)))?;
        
//         Ok(())
//     }
    
//     /// Start the packet processing loop
//     pub fn start(&mut self) -> Result<()> {
//         let mut is_running = self.is_running.lock().unwrap();
//         if *is_running {
//             return Err(io::Error::new(io::ErrorKind::AlreadyExists, "VirtualNetwork is already running"));
//         }
//         *is_running = true;
//         drop(is_running);
        
//         println!("Starting VirtualNetwork packet processing...");
        
//         // Note: We'll handle outbound packets in the main run loop instead
//         // since tun_tap::Iface doesn't implement Clone
//         println!("Outbound packet handling will be done in main loop");
        
//         Ok(())
//     }
    
//     /// Stop the packet processing
//     pub fn stop(&mut self) {
//         let mut is_running = self.is_running.lock().unwrap();
//         *is_running = false;
//         println!("Stopped VirtualNetwork packet processing");
//     }
    
//     /// Run the main packet processing loop (blocking)
//     pub fn run(&mut self) -> Result<()> {
//         self.start()?;
        
//         let mut buf = [0u8; 1504]; // MTU + some overhead
//         let mut packet_count = 0;
        
//         loop {
//             // Check if we should stop
//             if !*self.is_running.lock().unwrap() {
//                 break;
//             }
            
//             // Check for outbound packets to send
//             if let Ok(packet) = self.outbound_receiver.try_recv() {
//                 if let Err(e) = self.tun_iface.send(&packet.data) {
//                     eprintln!("Failed to send outbound packet: {}", e);
//                 } else {
//                     println!("Sent outbound packet ({} bytes)", packet.data.len());
//                 }
//             }
            
//             // Receive packet from TUN interface (non-blocking)
//             match self.tun_iface.recv(&mut buf) {
//                 Ok(nbytes) => {
//                     packet_count += 1;
//                     println!("\n[Packet #{}] Received {} bytes from TUN", packet_count, nbytes);
                    
//                     let mut packet_data = buf[..nbytes].to_vec();
                    
//                     // Process the packet and get potential response
//                     if let Some(response) = self.process_inbound_packet(&mut packet_data) {
//                         // Send response directly through TUN
//                         if let Err(e) = self.tun_iface.send(&response) {
//                             eprintln!("Failed to send response: {}", e);
//                         } else {
//                             println!("Sent response packet ({} bytes)", response.len());
//                         }
//                     }
//                 }
//                 Err(e) => {
//                     eprintln!("Error receiving from TUN: {}", e);
//                     break;
//                 }
//             }
//         }
        
//         Ok(())
//     }
    
//     /// Get TUN interface name
//     pub fn interface_name(&self) -> &str {
//         self.tun_iface.name()
//     }
    
//     /// Get statistics about the IP pool
//     pub fn get_stats(&self) -> VirtualNetworkStats {
//         VirtualNetworkStats {
//             total_interfaces: self.ip_pool.len(),
//             active_connections: self.ip_pool.values()
//                 .map(|iface| iface.tcp_connections.len())
//                 .sum(),
//             default_interface: self.default_interface,
//         }
//     }
// }

// /// Statistics about the virtual network
// #[derive(Debug, Clone)]
// pub struct VirtualNetworkStats {
//     pub total_interfaces: usize,
//     pub active_connections: usize,
//     pub default_interface: Option<[u8; 4]>,
// }

// impl Drop for VirtualNetwork {
//     fn drop(&mut self) {
//         self.stop();
//     }
// }

// #[cfg(test)]
// mod tests {
//     use super::*;
    
//     #[test]
//     fn test_virtual_network_creation() {
//         // Note: This test might fail in environments without TUN support
//         // In a real test environment, you'd mock the TUN interface
//         if let Ok(mut vnet) = VirtualNetwork::new("test_tun") {
//             assert_eq!(vnet.get_available_ips().len(), 0);
            
//             vnet.add_interface([192, 168, 1, 1], [255, 255, 255, 0]).unwrap();
//             assert_eq!(vnet.get_available_ips().len(), 1);
            
//             let stats = vnet.get_stats();
//             assert_eq!(stats.total_interfaces, 1);
//             assert_eq!(stats.default_interface, Some([192, 168, 1, 1]));
//         }
//     }
    
//     #[test]
//     fn test_interface_management() {
//         if let Ok(mut vnet) = VirtualNetwork::new("test_tun2") {
//             let ip1 = [192, 168, 1, 1];
//             let ip2 = [192, 168, 1, 2];
//             let netmask = [255, 255, 255, 0];
            
//             vnet.add_interface(ip1, netmask).unwrap();
//             vnet.add_interface(ip2, netmask).unwrap();
            
//             assert!(vnet.get_interface(&ip1).is_some());
//             assert!(vnet.get_interface(&ip2).is_some());
            
//             vnet.remove_interface(&ip1);
//             assert!(vnet.get_interface(&ip1).is_none());
//             assert!(vnet.get_interface(&ip2).is_some());
//         }
//     }
// }