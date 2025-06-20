//! Network interface abstraction and packet processing
//!
//! This module provides the main interface for packet processing, including:
//! - IPv4 packet reception and validation
//! - Protocol dispatch (ICMP, TCP, UDP)
//! - ICMP echo request/reply handling
//! - Source address selection and broadcast address handling

use crate::iface::ip::{IpAddr, IpInterace};
use crate::transport::tcp::TcpSocket;
use crate::transport::udp::UdpSocket;
use std::collections::HashMap;
use std::collections::VecDeque;
use std::sync::{Arc, Mutex};

/// Network interface for packet processing
pub struct NetworkInterface {
    pub ip_pool: HashMap<IpAddr, IpInterace>,
    pub rx_queue: Arc<Mutex<VecDeque<Vec<u8>>>>,
    pub tx_queue: Arc<Mutex<VecDeque<Vec<u8>>>>,
}

impl NetworkInterface {
    /// Create a new network interface
    pub fn new() -> Self {
        NetworkInterface {
            ip_pool: HashMap::new(),
            rx_queue: Arc::new(Mutex::new(VecDeque::new())),
            tx_queue: Arc::new(Mutex::new(VecDeque::new())),
        }
    }
}
