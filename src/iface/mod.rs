//! Network interface abstraction layer
//!
//! This module provides abstractions for network interfaces and packet processing:
//! - Interface management
//! - Packet routing and processing
//! - Protocol dispatch
//! - Virtual network with IP pool management

pub mod interface;
pub mod ip;
pub mod ipv4;
pub mod virtual_network;

// Re-export commonly used items
pub use ip::*;
