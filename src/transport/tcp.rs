//! TCP (Transmission Control Protocol) implementation
//! 
//! This module provides TCP packet parsing, connection state management,
//! and basic TCP protocol handling capabilities.

/// TCP connection states as defined in RFC 793
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum TcpState {
    Listen,
    SynRcvd,
    Established,
    FinWait1,
    FinWait2,
    CloseWait,
    Closing,
    LastAck,
    TimeWait,
    Closed,
}

/// TCP packet header structure
/// 
/// Represents the standard 20-byte TCP header as defined in RFC 793
#[derive(Debug, Clone, Copy)]
pub struct TcpHeader {
    pub src_port: u16,
    pub dst_port: u16,
    pub seq_number: u32,
    pub ack_number: u32,
    pub data_offset_and_flags: u16,  // Data offset (4 bits) + Reserved (3 bits) + Flags (9 bits)
    pub window_size: u16,
    pub checksum: u16,
    pub urgent_ptr: u16,
}

impl TcpHeader {
    /// Parse TCP header from byte slice
    /// 
    /// Returns None if the data is too short to contain a valid TCP header
    pub fn from_bytes(data: &[u8]) -> Option<Self> {
        if data.len() < 20 {
            return None;
        }
        
        Some(TcpHeader {
            src_port: u16::from_be_bytes([data[0], data[1]]),
            dst_port: u16::from_be_bytes([data[2], data[3]]),
            seq_number: u32::from_be_bytes([data[4], data[5], data[6], data[7]]),
            ack_number: u32::from_be_bytes([data[8], data[9], data[10], data[11]]),
            data_offset_and_flags: u16::from_be_bytes([data[12], data[13]]),
            window_size: u16::from_be_bytes([data[14], data[15]]),
            checksum: u16::from_be_bytes([data[16], data[17]]),
            urgent_ptr: u16::from_be_bytes([data[18], data[19]]),
        })
    }
    
    /// Convert TCP header to bytes
    pub fn to_bytes(&self) -> [u8; 20] {
        let mut bytes = [0u8; 20];
        bytes[0..2].copy_from_slice(&self.src_port.to_be_bytes());
        bytes[2..4].copy_from_slice(&self.dst_port.to_be_bytes());
        bytes[4..8].copy_from_slice(&self.seq_number.to_be_bytes());
        bytes[8..12].copy_from_slice(&self.ack_number.to_be_bytes());
        bytes[12..14].copy_from_slice(&self.data_offset_and_flags.to_be_bytes());
        bytes[14..16].copy_from_slice(&self.window_size.to_be_bytes());
        bytes[16..18].copy_from_slice(&self.checksum.to_be_bytes());
        bytes[18..20].copy_from_slice(&self.urgent_ptr.to_be_bytes());
        bytes
    }

    /// Check if SYN flag is set
    pub fn is_syn(&self) -> bool {
        (self.data_offset_and_flags & 0x0002) != 0
    }
    
    /// Check if ACK flag is set
    pub fn is_ack(&self) -> bool {
        (self.data_offset_and_flags & 0x0010) != 0
    }
    
    /// Check if FIN flag is set
    pub fn is_fin(&self) -> bool {
        (self.data_offset_and_flags & 0x0001) != 0
    }
    
    /// Check if RST flag is set
    pub fn is_rst(&self) -> bool {
        (self.data_offset_and_flags & 0x0004) != 0
    }
    
    /// Check if PSH flag is set
    pub fn is_psh(&self) -> bool {
        (self.data_offset_and_flags & 0x0008) != 0
    }
    
    /// Check if URG flag is set
    pub fn is_urg(&self) -> bool {
        (self.data_offset_and_flags & 0x0020) != 0
    }
    
    /// Get the data offset (header length) in bytes
    pub fn data_offset(&self) -> usize {
        ((self.data_offset_and_flags >> 12) as usize) * 4
    }
    
    /// Set TCP flags
    pub fn set_flags(&mut self, syn: bool, ack: bool, fin: bool, rst: bool, psh: bool, urg: bool) {
        let mut flags = (self.data_offset_and_flags >> 12) << 12; // Preserve data offset
        if syn { flags |= 0x0002; }
        if ack { flags |= 0x0010; }
        if fin { flags |= 0x0001; }
        if rst { flags |= 0x0004; }
        if psh { flags |= 0x0008; }
        if urg { flags |= 0x0020; }
        self.data_offset_and_flags = flags;
    }
}

/// TCP connection structure
/// 
/// Manages the state and parameters of a TCP connection
#[derive(Debug)]
pub struct TcpSocket {
    pub state: TcpState,
    pub local_addr: [u8; 4],
    pub remote_addr: [u8; 4],
    pub local_port: u16,
    pub remote_port: u16,
    pub local_seq: u32,
    pub remote_seq: u32,
    pub local_ack: u32,
    pub remote_ack: u32,
}

impl TcpSocket {
    /// Create a new TCP connection in LISTEN state
    pub fn new() -> Self {
        TcpSocket {
            state: TcpState::Listen,
            local_addr: [0; 4],
            remote_addr: [0; 4],
            local_port: 0,
            remote_port: 0,
            local_seq: 0,
            remote_seq: 0,
            local_ack: 0,
            remote_ack: 0,
        }
    }
    
    /// Create a new TCP connection with specified local address and port
    pub fn new_with_addr(local_addr: [u8; 4], local_port: u16) -> Self {
        TcpSocket {
            state: TcpState::Listen,
            local_addr,
            remote_addr: [0; 4],
            local_port,
            remote_port: 0,
            local_seq: 0,
            remote_seq: 0,
            local_ack: 0,
            remote_ack: 0,
        }
    }

    /// Process incoming TCP packet and return response if needed
    /// 
    /// This method implements basic TCP state machine logic
    pub fn on_packet(&mut self, data: &[u8]) -> Option<Vec<u8>> {
        if let Some(tcp_header) = TcpHeader::from_bytes(data) {
            match self.state {
                TcpState::Listen => {
                    if tcp_header.is_syn() && !tcp_header.is_ack() {
                        println!("State: LISTEN -> SYN_RCVD (received valid SYN packet)");
                        self.state = TcpState::SynRcvd;
                        self.remote_port = tcp_header.src_port;
                        self.remote_seq = tcp_header.seq_number;
                        self.local_ack = tcp_header.seq_number.wrapping_add(1);
                        
                        // TODO: Build a proper SYN+ACK response
                        return Some(b"placeholder SYN-ACK".to_vec());
                    }
                }
                TcpState::SynRcvd => {
                    if tcp_header.is_ack() && !tcp_header.is_syn() {
                        if tcp_header.ack_number == self.local_seq.wrapping_add(1) {
                            println!("State: SYN_RCVD -> ESTABLISHED (received valid ACK)");
                            self.state = TcpState::Established;
                            self.remote_ack = tcp_header.ack_number;
                        }
                    }
                }
                TcpState::Established => {
                    if tcp_header.is_fin() {
                        println!("State: ESTABLISHED -> CLOSE_WAIT (received FIN)");
                        self.state = TcpState::CloseWait;
                        self.local_ack = tcp_header.seq_number.wrapping_add(1);
                        
                        // TODO: Send ACK for FIN
                        return Some(b"placeholder FIN-ACK".to_vec());
                    }
                    // Handle data packets here
                }
                _ => {
                    // Handle other states
                }
            }
        }
        None
    }
    
    /// Check if connection is in an active state
    pub fn is_active(&self) -> bool {
        matches!(self.state, TcpState::Established | TcpState::CloseWait)
    }
    
    /// Check if connection is closed
    pub fn is_closed(&self) -> bool {
        matches!(self.state, TcpState::Closed)
    }
}

impl Default for TcpSocket {
    fn default() -> Self {
        Self::new()
    }
}
