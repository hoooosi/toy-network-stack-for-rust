//! Network interface abstraction layer
//! 
//! This module provides abstractions for network interfaces and packet processing:
//! - Interface management
//! - Packet routing and processing
//! - Protocol dispatch
//! - Virtual network with IP pool management

pub mod interface;
pub mod virtual_network;

// Re-export commonly used items
pub use interface::NetworkInterface;
pub use virtual_network::{VirtualNetwork, VirtualNetworkStats, Packet};