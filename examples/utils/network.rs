use std::io;
use std::process::Command;

pub fn configure_interface(iface_name: &str, ip_cidr: &str) -> io::Result<()> {
    // Configure IP address: ip addr add <ip_cidr> dev <iface_name>
    let status = Command::new("ip")
        .arg("addr")
        .arg("add")
        .arg(ip_cidr)
        .arg("dev")
        .arg(iface_name)
        .status()?;

    if !status.success() {
        panic!(
            "Failed to configure IP address {} for {}",
            ip_cidr, iface_name
        );
    }

    // Bring interface up: ip link set up dev <iface_name>
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

    println!(
        "Interface {} configured with IP {} and brought up",
        iface_name, ip_cidr
    );
    Ok(())
}

#[allow(dead_code)]
pub fn parse_ip_cidr(ip_cidr: &str) -> ([u8; 4], [u8; 4]) {
    let parts: Vec<&str> = ip_cidr.split('/').collect();
    if parts.len() != 2 {
        panic!("Invalid IP CIDR format");
    }

    let ip_parts: Vec<&str> = parts[0].split('.').collect();
    if ip_parts.len() != 4 {
        panic!("Invalid IP address format");
    }

    let ip_bytes = [
        ip_parts[0].parse::<u8>().unwrap(),
        ip_parts[1].parse::<u8>().unwrap(),
        ip_parts[2].parse::<u8>().unwrap(),
        ip_parts[3].parse::<u8>().unwrap(),
    ];

    let prefix_len = parts[1].parse::<u8>().unwrap();
    if prefix_len > 32 {
        panic!("Invalid network prefix length");
    }

    let mut netmask = [0u8; 4];
    for i in 0..4 {
        let start = i * 8;
        let end = std::cmp::min(start + 8, prefix_len as usize);
        let bits = if end > start {
            let shift = 8 - (end - start);
            255u8 >> shift << shift
        } else {
            0
        };
        netmask[i] = bits;
    }

    (ip_bytes, netmask)
}
