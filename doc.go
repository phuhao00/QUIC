/*
Package quic 提供了QUIC (Quick UDP Internet Connections) 协议的Go语言实现。

QUIC是由Google开发的传输层网络协议，旨在替代TCP+TLS的组合，提供更好的性能和安全性。
本实现基于RFC 9000 (QUIC v1)规范。

# 主要特性

• 基于UDP的可靠传输
• 内置TLS 1.3加密
• 多路复用流支持，无队头阻塞
• 0-RTT连接建立
• 连接迁移支持
• 现代拥塞控制算法(CUBIC)

# 快速开始

## 服务端示例

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
			Certificates: loadCertificates(),
		}

		// 监听QUIC连接
		listener, err := quic.ListenAddr("localhost:4242", tlsConfig, nil)
		if err != nil {
			log.Fatal(err)
		}
		defer listener.Close()

		for {
			// 接受新连接
			conn, err := listener.Accept(context.Background())
			if err != nil {
				log.Fatal(err)
			}

			go handleConnection(conn)
		}
	}

## 客户端示例

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
			ServerName: "example.com",
		}

		// 连接到服务器
		conn, err := quic.DialAddr("example.com:4242", tlsConfig, nil)
		if err != nil {
			log.Fatal(err)
		}
		defer conn.Close()

		// 打开流
		stream, err := conn.OpenStreamSync(context.Background())
		if err != nil {
			log.Fatal(err)
		}
		defer stream.Close()

		// 发送和接收数据
		stream.Write([]byte("Hello, QUIC!"))
		// ...
	}

# 配置选项

可以通过Config结构体自定义QUIC连接的行为：

	config := &quic.Config{
		MaxIdleTimeout:        30 * time.Second,
		MaxIncomingStreams:    100,
		MaxStreamReceiveWindow: 6 * 1024 * 1024, // 6MB
		Allow0RTT:             true,
		KeepAlivePeriod:       15 * time.Second,
	}

# 流管理

QUIC支持在单个连接上创建多个独立的流：

	// 打开新的双向流
	stream, err := conn.OpenStreamSync(ctx)
	if err != nil {
		return err
	}

	// 接受来自对端的流
	stream, err := conn.AcceptStream(ctx)
	if err != nil {
		return err
	}

	// 流支持标准的io.ReadWriteCloser接口
	n, err := stream.Write(data)
	n, err = stream.Read(buffer)
	err = stream.Close()

# 错误处理

QUIC定义了两种类型的错误：
• 连接级错误：影响整个连接
• 流级错误：只影响单个流

	// 优雅关闭连接
	err := conn.Close()

	// 带错误码关闭连接
	err := conn.CloseWithError(0x100, "应用程序错误")

# 性能调优

• 调整接收窗口大小以适应应用需求
• 启用0-RTT以减少连接建立延迟
• 配置合适的keep-alive间隔
• 监控连接统计信息进行诊断

	stats := conn.GetStats()
	log.Printf("RTT: %v, 丢包率: %.2f%%",
		stats.RTT,
		float64(stats.PacketsLost)/float64(stats.PacketsSent)*100)

# 安全考虑

• 始终验证服务器证书（生产环境）
• 谨慎启用0-RTT，注意重放攻击风险
• 定期更新TLS证书
• 考虑实现证书透明度检查

# 协议版本

本实现支持以下QUIC版本：
• QUIC v1 (RFC 9000) - 默认版本

# 限制和已知问题

• 当前实现为简化版本，主要用于演示和学习
• 某些高级特性可能未完全实现
• 性能优化空间仍然较大
• 建议在生产环境中使用成熟的QUIC实现

# 相关RFC文档

• RFC 9000: QUIC: A UDP-Based Multiplexed and Secure Transport
• RFC 9001: Using TLS to Secure QUIC
• RFC 9002: QUIC Loss Detection and Congestion Control
• RFC 9218: Extensible Prioritization Scheme for HTTP
*/
package quic
