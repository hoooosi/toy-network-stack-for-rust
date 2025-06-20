# UDP功能实现文档

本文档描述了在toy-tcp-for-rust项目中新实现的UDP功能。

## 已实现的功能

### 1. UDP校验和计算

#### 功能描述
- 实现了符合RFC 768标准的UDP校验和计算
- 支持UDP伪头部校验和，包括源IP、目标IP、协议号和UDP长度
- 提供校验和验证功能

#### 相关函数
```rust
// 计算UDP校验和（包含伪头部）
pub fn calculate_udp_checksum(
    src_ip: &[u8; 4],
    dst_ip: &[u8; 4], 
    udp_packet: &[u8],
) -> u16

// 创建带正确校验和的UDP包
pub fn create_udp_packet_with_checksum(
    src_ip: &[u8; 4],
    dst_ip: &[u8; 4],
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> Vec<u8>
```

#### 使用示例
```rust
use toy_network::transport::{calculate_udp_checksum, create_udp_packet_with_checksum};

let src_ip = [192, 168, 1, 1];
let dst_ip = [192, 168, 1, 2];
let data = b"Hello, UDP!";

// 创建带校验和的UDP包
let udp_packet = create_udp_packet_with_checksum(
    &src_ip, &dst_ip, 8080, 9090, data
);
```

### 2. UDP发送功能

#### 功能描述
- 实现了完整的UDP包发送接口
- 自动构建UDP包并加入发送队列
- 集成到网络接口的输出队列管理

#### UdpSocket新方法
```rust
// 发送数据到指定目标
pub fn send_to(&mut self, data: &[u8], dst_addr: IpAddr, dst_port: u16) -> Result<(), UdpError>

// 检查是否有待发送的包
pub fn has_pending_tx(&self) -> bool

// 获取队列长度
pub fn tx_queue_len(&self) -> usize
pub fn rx_queue_len(&self) -> usize
```

#### IP接口集成
```rust
// 通过IP接口发送UDP数据
pub fn send_udp(&mut self, src_port: u16, dst_addr: IpAddr, dst_port: u16, data: &[u8]) -> Result<(), UdpError>

// 处理UDP发送队列
pub fn process_udp_tx(&mut self)

// 获取待发送的包
pub fn dequeue_output(&mut self) -> Option<Vec<u8>>
```

#### 使用示例
```rust
use toy_network::iface::{IpAddr, IpInterace};

let mut ip_interface = IpInterace::new(IpAddr::V4([192, 168, 1, 100]), 24);
ip_interface.bind_udp_socket(7777)?;

// 发送UDP数据
let dst_addr = IpAddr::V4([192, 168, 1, 200]);
ip_interface.send_udp(7777, dst_addr, 8888, b"Hello!")?;

// 处理发送队列
ip_interface.process_udp_tx();
if let Some(packet) = ip_interface.dequeue_output() {
    // 发送packet到网络
}
```

### 3. 错误处理和验证

#### UdpError错误类型
```rust
#[derive(Debug, Clone, PartialEq)]
pub enum UdpError {
    InvalidLength,    // 无效的包长度
    InvalidChecksum,  // 校验和错误
    InvalidPort,      // 无效端口（如端口0或重复绑定）
    BufferOverflow,   // 缓冲区溢出
    SocketNotBound,   // Socket未绑定
}
```

#### 验证功能
```rust
// 验证UDP包的完整性
pub fn validate_udp_packet(
    packet: &[u8], 
    src_ip: &[u8; 4], 
    dst_ip: &[u8; 4]
) -> Result<(), UdpError>
```

#### 缓冲区保护
- 接收队列和发送队列都有大小限制
- 默认队列大小为1024个包
- 可以通过`UdpSocket::with_queue_sizes()`自定义队列大小
- 队列满时返回`UdpError::BufferOverflow`

#### 使用示例
```rust
// 创建带自定义队列大小的socket
let mut socket = UdpSocket::with_queue_sizes(8080, 512, 256)?;

// 验证UDP包
match validate_udp_packet(&packet_data, &src_ip, &dst_ip) {
    Ok(_) => println!("包验证通过"),
    Err(UdpError::InvalidChecksum) => println!("校验和错误"),
    Err(e) => println!("其他错误: {}", e),
}
```

## 改进的功能

### 1. UdpSocket构造函数
- 原来的`new()`方法现在返回`Result<Self, UdpError>`
- 添加了端口验证（拒绝端口0）
- 添加了`with_queue_sizes()`方法用于自定义缓冲区大小

### 2. 包接收处理
- 添加了UDP包验证
- 改进了错误处理和日志记录
- 防止缓冲区溢出

### 3. IP接口集成
- UDP socket绑定现在返回错误而不是panic
- 添加了发送队列处理
- 集成了输出队列管理

## 测试

运行UDP功能测试：
```bash
cargo run --example udp_test
```

运行UDP echo服务器（需要root权限）：
```bash
sudo cargo run --example udp_echo
```

## 兼容性说明

### 破坏性变更
1. `UdpSocket::new()` 现在返回 `Result<Self, UdpError>`
2. `IpInterace::bind_udp_socket()` 现在返回 `Result<(), UdpError>`
3. `UdpSocket::enqueue_packet()` 现在返回 `Result<(), UdpError>`

### 迁移指南
```rust
// 旧代码
let socket = UdpSocket::new(8080);
ip_interface.bind_udp_socket(8080);

// 新代码
let socket = UdpSocket::new(8080)?;
ip_interface.bind_udp_socket(8080)?;
```

## 性能特性

- 零拷贝的UDP头部解析
- 高效的校验和计算
- 队列大小限制防止内存耗尽
- 批量处理发送队列

## 未来改进方向

1. **异步支持**: 添加async/await支持
2. **多播支持**: 实现UDP多播功能
3. **Socket选项**: 添加更多socket配置选项
4. **零拷贝优化**: 进一步减少内存拷贝
5. **IPv6支持**: 扩展到IPv6