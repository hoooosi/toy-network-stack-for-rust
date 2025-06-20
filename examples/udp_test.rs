//! UDP功能测试示例
//! 演示UDP校验和计算、发送功能和错误处理

use std::io::Result;
use toy_network::{
    iface::{IpAddr, IpInterace},
    transport::{
        calculate_udp_checksum, create_udp_packet_with_checksum, validate_udp_packet, UdpError,
        UdpSocket,
    },
};

fn main() -> Result<()> {
    println!("=== UDP功能测试 ===");

    // 测试1: UDP Socket创建和错误处理
    println!("\n1. 测试UDP Socket创建:");

    // 测试无效端口
    match UdpSocket::new(0) {
        Ok(_) => println!("❌ 应该拒绝端口0"),
        Err(UdpError::InvalidPort) => println!("✅ 正确拒绝了无效端口0"),
        Err(e) => println!("❌ 意外错误: {}", e),
    }

    // 测试有效端口
    match UdpSocket::new(8080) {
        Ok(_) => println!("✅ 成功创建端口8080的socket"),
        Err(e) => println!("❌ 创建socket失败: {}", e),
    }

    // 测试2: UDP校验和计算
    println!("\n2. 测试UDP校验和计算:");

    let src_ip = [192, 168, 1, 1];
    let dst_ip = [192, 168, 1, 2];
    let test_data = b"Hello, UDP!";

    let udp_packet = create_udp_packet_with_checksum(&src_ip, &dst_ip, 8080, 9090, test_data);

    println!("✅ 创建了带校验和的UDP包，长度: {} 字节", udp_packet.len());

    // 验证校验和
    match validate_udp_packet(&udp_packet, &src_ip, &dst_ip) {
        Ok(_) => println!("✅ UDP包校验和验证通过"),
        Err(e) => println!("❌ UDP包校验和验证失败: {}", e),
    }

    // 测试3: IP接口集成
    println!("\n3. 测试IP接口集成:");

    let mut ip_interface = IpInterace::new(IpAddr::V4([192, 168, 1, 100]), 24);

    // 绑定UDP socket
    match ip_interface.bind_udp_socket(7777) {
        Ok(_) => println!("✅ 成功在IP接口上绑定UDP端口7777"),
        Err(e) => println!("❌ 绑定UDP端口失败: {}", e),
    }

    // 尝试重复绑定同一端口
    match ip_interface.bind_udp_socket(7777) {
        Ok(_) => println!("❌ 应该拒绝重复绑定"),
        Err(UdpError::InvalidPort) => println!("✅ 正确拒绝了重复绑定"),
        Err(e) => println!("❌ 意外错误: {}", e),
    }

    // 测试发送功能
    let dst_addr = IpAddr::V4([192, 168, 1, 200]);
    let send_data = b"Test message";

    match ip_interface.send_udp(7777, dst_addr, 8888, send_data) {
        Ok(_) => println!("✅ 成功发送UDP数据"),
        Err(e) => println!("❌ 发送UDP数据失败: {}", e),
    }

    // 处理发送队列
    ip_interface.process_udp_tx();

    if let Some(outgoing_packet) = ip_interface.dequeue_output() {
        println!(
            "✅ 从输出队列获取到待发送包，长度: {} 字节",
            outgoing_packet.len()
        );
    } else {
        println!("❌ 输出队列为空");
    }

    // 测试4: 缓冲区溢出保护
    println!("\n4. 测试缓冲区溢出保护:");

    let mut small_socket = UdpSocket::with_queue_sizes(9999, 2, 2).unwrap();

    // 填满发送队列
    for i in 0..3 {
        let result = small_socket.send_to(
            format!("Message {}", i).as_bytes(),
            IpAddr::V4([127, 0, 0, 1]),
            8080,
        );

        match result {
            Ok(_) => println!("✅ 消息 {} 成功加入队列", i),
            Err(UdpError::BufferOverflow) => {
                println!("✅ 消息 {} 被正确拒绝（缓冲区溢出）", i);
                break;
            }
            Err(e) => println!("❌ 意外错误: {}", e),
        }
    }

    println!("\n=== 所有测试完成 ===");
    Ok(())
}
