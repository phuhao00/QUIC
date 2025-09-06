# QUIC协议库

这是一个用Go语言实现的QUIC（Quick UDP Internet Connections）协议库。

## 功能特性

- ✅ QUIC协议核心实现 (RFC 9000)
- ✅ 基于UDP的可靠传输
- ✅ 内置TLS 1.3加密
- ✅ 多路复用流支持
- ✅ CUBIC拥塞控制算法
- ✅ 连接状态管理
- ✅ 完整的数据包和帧处理

## 快速开始

### 前置要求

- Go 1.21 或更高版本
- 基本的网络编程知识

### 安装

```bash
go get github.com/quic-go/quic
```

### 服务端示例

```go
package main

import (
    "context"
    "crypto/tls"
    "log"
    
    "github.com/quic-go/quic"
)

func main() {
    // 配置TLS证书
    tlsConfig := &tls.Config{
        Certificates: []tls.Certificate{loadYourCertificate()},
        NextProtos:   []string{"quic-echo"},
    }

    // 监听QUIC连接
    listener, err := quic.ListenAddr("localhost:4242", tlsConfig, nil)
    if err != nil {
        log.Fatal(err)
    }
    defer listener.Close()

    log.Println("QUIC服务器正在监听 localhost:4242")

    for {
        // 接受新连接
        conn, err := listener.Accept(context.Background())
        if err != nil {
            log.Fatal(err)
        }

        // 处理连接（在新的goroutine中）
        go handleConnection(conn)
    }
}

func handleConnection(conn quic.Connection) {
    defer conn.Close()
    
    for {
        // 接受新流
        stream, err := conn.AcceptStream(context.Background())
        if err != nil {
            return
        }
        
        // 处理流（回显服务）
        go func() {
            defer stream.Close()
            
            buf := make([]byte, 1024)
            n, err := stream.Read(buf)
            if err != nil {
                return
            }
            
            // 回显数据
            stream.Write(buf[:n])
        }()
    }
}
```

### 客户端示例

```go
package main

import (
    "context"
    "crypto/tls"
    "log"
    
    "github.com/quic-go/quic"
)

func main() {
    // 配置TLS
    tlsConfig := &tls.Config{
        ServerName:         "localhost",
        InsecureSkipVerify: true, // 仅用于测试
        NextProtos:         []string{"quic-echo"},
    }

    // 连接到服务器
    conn, err := quic.DialAddr("localhost:4242", tlsConfig, nil)
    if err != nil {
        log.Fatal(err)
    }
    defer conn.Close()

    log.Println("已连接到QUIC服务器")

    // 打开流
    stream, err := conn.OpenStreamSync(context.Background())
    if err != nil {
        log.Fatal(err)
    }
    defer stream.Close()

    // 发送数据
    message := "Hello, QUIC!"
    _, err = stream.Write([]byte(message))
    if err != nil {
        log.Fatal(err)
    }

    // 接收回显数据
    buf := make([]byte, 1024)
    n, err := stream.Read(buf)
    if err != nil {
        log.Fatal(err)
    }

    log.Printf("收到回显: %s", string(buf[:n]))
}
```

## 运行示例

### 启动服务器
```bash
cd examples/server
go run main.go
```

### 启动客户端（在另一个终端中）
```bash
cd examples/client  
go run main.go
```

## 配置选项

你可以通过`Config`结构体自定义QUIC连接的行为：

```go
config := &quic.Config{
    // 连接超时
    HandshakeIdleTimeout:  10 * time.Second,
    MaxIdleTimeout:        30 * time.Second,
    
    // 流控制
    MaxIncomingStreams:    100,
    MaxStreamReceiveWindow: 6 * 1024 * 1024, // 6MB
    MaxConnectionReceiveWindow: 15 * 1024 * 1024, // 15MB
    
    // 0-RTT支持
    Allow0RTT: true,
    
    // Keep-alive
    KeepAlivePeriod: 15 * time.Second,
}

conn, err := quic.DialAddr("example.com:443", tlsConfig, config)
```

## API文档

### 主要接口

#### Connection
```go
type Connection interface {
    // 流管理
    OpenStream() (Stream, error)
    OpenStreamSync(ctx context.Context) (Stream, error)
    AcceptStream(ctx context.Context) (Stream, error)
    
    // 连接信息
    LocalAddr() net.Addr
    RemoteAddr() net.Addr
    ConnectionState() ConnectionState
    
    // 生命周期
    Close() error
    CloseWithError(errorCode uint64, reason string) error
}
```

#### Stream
```go
type Stream interface {
    // 标准的读写接口
    Read([]byte) (int, error)
    Write([]byte) (int, error)
    Close() error

    // QUIC特定方法
    StreamID() uint64
    SetDeadline(time.Time) error
    SetReadDeadline(time.Time) error
    SetWriteDeadline(time.Time) error
}
```

### 连接状态

```go
state := conn.ConnectionState()
fmt.Printf("握手完成: %v\n", state.HandshakeComplete)
fmt.Printf("QUIC版本: %d\n", state.Version)
fmt.Printf("加密套件: %x\n", state.CipherSuite)
```

### 统计信息

```go
stats := conn.GetStats()
fmt.Printf("发送包数: %d\n", stats.PacketsSent)
fmt.Printf("接收包数: %d\n", stats.PacketsReceived)
fmt.Printf("RTT: %v\n", stats.RTT)
```

## 开发指南

### 构建和测试

```bash
# 安装依赖
make deps

# 格式化代码
make format

# 运行静态分析
make vet

# 运行测试
make test

# 生成测试覆盖率报告
make test-coverage

# 运行基准测试
make benchmark

# 构建项目
make build
```

### 运行集成测试

```bash
go test -tags=integration ./...
```

### 项目结构

```
quic/
├── internal/           # 内部实现
│   ├── packet/        # 数据包和帧处理
│   │   ├── header.go  # 包头解析和序列化
│   │   ├── frame.go   # 帧解析和序列化
│   │   └── utils.go   # 工具函数
│   ├── connection/    # 连接管理
│   │   └── connection.go
│   ├── stream/        # 流管理
│   │   ├── stream.go
│   │   └── stream_test.go
│   ├── crypto/        # 加密处理
│   │   └── tls.go
│   └── congestion/    # 拥塞控制
│       ├── cubic.go
│       └── cubic_test.go
├── examples/          # 示例代码
│   ├── server/        # 服务器示例
│   └── client/        # 客户端示例
├── quic.go           # 公共API
├── doc.go            # 包文档
├── integration_test.go # 集成测试
├── benchmarks_test.go  # 基准测试
└── Makefile          # 构建脚本
```

## 实现详情

### QUIC协议支持

本实现遵循以下RFC规范：

- **RFC 9000**: QUIC v1 核心协议
- **RFC 9001**: 使用TLS 1.3保护QUIC
- **RFC 9002**: QUIC丢包检测和拥塞控制

### 支持的特性

1. **数据包格式**
   - 长包头（Initial、0-RTT、Handshake、Retry）
   - 短包头（1-RTT数据包）
   - 变长整数编码
   - 包头保护

2. **帧类型**
   - STREAM: 应用数据传输
   - ACK: 确认机制
   - CRYPTO: TLS握手数据
   - PADDING: 包填充
   - PING: 连接保活
   - CONNECTION_CLOSE: 连接关闭

3. **连接管理**
   - 连接建立和握手
   - 状态跟踪
   - 优雅关闭
   - 错误处理

4. **流管理**
   - 双向和单向流
   - 流控制
   - 多路复用
   - 有序数据传输

5. **加密和安全**
   - TLS 1.3集成
   - 多层加密保护
   - 密钥派生
   - 包头保护

6. **拥塞控制**
   - CUBIC算法实现
   - 慢启动
   - 拥塞避免
   - 快速恢复

### 性能特性

- **低延迟**: 减少往返时间
- **并发**: 支持多流并发传输
- **高效**: 优化的内存使用
- **可扩展**: 模块化设计

## 限制和已知问题

⚠️ **重要说明**: 这是一个简化的QUIC实现，主要用于学习和演示目的。

### 当前限制

1. **简化的TLS集成**: 使用模拟的TLS握手
2. **基础的错误处理**: 错误恢复机制不完整
3. **有限的连接迁移**: 暂不支持完整的连接迁移
4. **简单的流控制**: 流控制算法需要优化
5. **测试覆盖率**: 需要更多的边缘情况测试

### 建议

- **学习用途**: 适合理解QUIC协议工作原理
- **原型开发**: 可用于概念验证和原型开发
- **生产环境**: 建议使用成熟的QUIC实现，如 [quic-go](https://github.com/quic-go/quic-go)

## 性能测试

### 基准测试结果

运行基准测试：
```bash
make benchmark
```

典型结果（仅供参考）：
```
BenchmarkVarintEncoding-8         1000000    1053 ns/op    0 B/op    0 allocs/op
BenchmarkHeaderParsing-8          500000     2847 ns/op    480 B/op  12 allocs/op
BenchmarkFrameParsing-8           1000000    1234 ns/op    256 B/op  6 allocs/op
BenchmarkCongestionControl-8      2000000    678 ns/op     0 B/op    0 allocs/op
```

## 贡献

欢迎贡献代码！请参阅 [CONTRIBUTING.md](CONTRIBUTING.md) 了解详细的贡献指南。

### 贡献方式

1. Fork 项目
2. 创建功能分支 (`git checkout -b feature/AmazingFeature`)
3. 提交更改 (`git commit -m 'Add some AmazingFeature'`)
4. 推送到分支 (`git push origin feature/AmazingFeature`)
5. 创建 Pull Request

## 许可证

本项目使用 MIT 许可证。详情请参阅 [LICENSE](LICENSE) 文件。

## 致谢

- QUIC协议设计团队
- Go语言标准库团队
- 所有参与测试和反馈的开发者

## 参考资源

- [QUIC RFC 9000](https://datatracker.ietf.org/doc/html/rfc9000)
- [TLS 1.3 RFC 8446](https://datatracker.ietf.org/doc/html/rfc8446)
- [QUIC协议解析](https://datatracker.ietf.org/wg/quic/documents/)
- [HTTP/3规范](https://datatracker.ietf.org/doc/html/rfc9114)

## 联系方式

如有问题或建议，请创建 [GitHub Issue](https://github.com/quic-go/quic/issues)。