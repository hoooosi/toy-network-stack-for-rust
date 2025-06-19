//! Network interface abstraction layer
//! 
//! This module provides abstractions for network interfaces and packet processing:
//! - Interface management
//! - Packet routing and processing
//! - Protocol dispatch

pub mod interface;

// Re-export commonly used items
pub use interface::NetworkInterface;