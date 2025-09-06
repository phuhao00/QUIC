//go:build integration
// +build integration

package quic

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"testing"
	"time"
)

// TestClientServerIntegration 集成测试：客户端-服务器通信
func TestClientServerIntegration(t *testing.T) {
	// 生成自签名证书
	cert, err := generateTestCert()
	if err != nil {
		t.Fatalf("生成测试证书失败: %v", err)
	}

	// 服务器TLS配置
	serverTLSConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		NextProtos:   []string{"test-protocol"},
	}

	// 启动服务器
	listener, err := ListenAddr("localhost:0", serverTLSConfig, DefaultConfig())
	if err != nil {
		t.Fatalf("启动服务器失败: %v", err)
	}
	defer listener.Close()

	serverAddr := listener.Addr().String()
	t.Logf("服务器监听地址: %s", serverAddr)

	// 启动服务器处理goroutine
	go func() {
		for {
			conn, err := listener.Accept(context.Background())
			if err != nil {
				return // 监听器关闭
			}

			go func() {
				defer conn.Close()
				stream, err := conn.AcceptStream(context.Background())
				if err != nil {
					return
				}
				defer stream.Close()

				// 简单的回显服务
				buf := make([]byte, 1024)
				n, err := stream.Read(buf)
				if err != nil {
					return
				}

				_, err = stream.Write(buf[:n])
				if err != nil {
					return
				}
			}()
		}
	}()

	// 等待服务器启动
	time.Sleep(100 * time.Millisecond)

	// 客户端TLS配置
	clientTLSConfig := &tls.Config{
		InsecureSkipVerify: true,
		NextProtos:         []string{"test-protocol"},
	}

	// 创建客户端连接
	conn, err := DialAddr(serverAddr, clientTLSConfig, DefaultConfig())
	if err != nil {
		t.Fatalf("客户端连接失败: %v", err)
	}
	defer conn.Close()

	t.Logf("客户端已连接到服务器")

	// 打开流
	stream, err := conn.OpenStreamSync(context.Background())
	if err != nil {
		t.Fatalf("打开流失败: %v", err)
	}
	defer stream.Close()

	// 发送测试数据
	testData := []byte("Hello, QUIC World!")
	_, err = stream.Write(testData)
	if err != nil {
		t.Fatalf("发送数据失败: %v", err)
	}

	// 读取回显数据
	buf := make([]byte, 1024)
	n, err := stream.Read(buf)
	if err != nil {
		t.Fatalf("读取数据失败: %v", err)
	}

	receivedData := buf[:n]
	if string(receivedData) != string(testData) {
		t.Errorf("数据不匹配，期望 %s，收到 %s", string(testData), string(receivedData))
	}

	t.Logf("集成测试通过：成功收到回显数据")
}

// TestMultipleStreams 测试多流并发
func TestMultipleStreams(t *testing.T) {
	cert, err := generateTestCert()
	if err != nil {
		t.Fatalf("生成测试证书失败: %v", err)
	}

	serverTLSConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		NextProtos:   []string{"test-multi-stream"},
	}

	listener, err := ListenAddr("localhost:0", serverTLSConfig, DefaultConfig())
	if err != nil {
		t.Fatalf("启动服务器失败: %v", err)
	}
	defer listener.Close()

	serverAddr := listener.Addr().String()

	// 服务器处理多个流
	go func() {
		conn, err := listener.Accept(context.Background())
		if err != nil {
			return
		}
		defer conn.Close()

		streamCount := 0
		for {
			stream, err := conn.AcceptStream(context.Background())
			if err != nil {
				break
			}

			streamCount++
			go func(streamID int) {
				defer stream.Close()

				buf := make([]byte, 1024)
				n, err := stream.Read(buf)
				if err != nil {
					return
				}

				response := append([]byte("Stream "), []byte(string(buf[:n]))...)
				stream.Write(response)
			}(streamCount)
		}
	}()

	time.Sleep(100 * time.Millisecond)

	clientTLSConfig := &tls.Config{
		InsecureSkipVerify: true,
		NextProtos:         []string{"test-multi-stream"},
	}

	conn, err := DialAddr(serverAddr, clientTLSConfig, DefaultConfig())
	if err != nil {
		t.Fatalf("客户端连接失败: %v", err)
	}
	defer conn.Close()

	// 创建多个流并发送数据
	numStreams := 3
	done := make(chan bool, numStreams)

	for i := 0; i < numStreams; i++ {
		go func(streamNum int) {
			stream, err := conn.OpenStreamSync(context.Background())
			if err != nil {
				t.Errorf("打开流 %d 失败: %v", streamNum, err)
				done <- false
				return
			}
			defer stream.Close()

			testData := []byte(string(rune('A'+streamNum)) + " data")
			_, err = stream.Write(testData)
			if err != nil {
				t.Errorf("流 %d 发送数据失败: %v", streamNum, err)
				done <- false
				return
			}

			buf := make([]byte, 1024)
			n, err := stream.Read(buf)
			if err != nil {
				t.Errorf("流 %d 读取数据失败: %v", streamNum, err)
				done <- false
				return
			}

			t.Logf("流 %d 收到响应: %s", streamNum, string(buf[:n]))
			done <- true
		}(i)
	}

	// 等待所有流完成
	for i := 0; i < numStreams; i++ {
		success := <-done
		if !success {
			t.Error("某个流处理失败")
		}
	}

	t.Logf("多流测试通过")
}

// TestConnectionStatistics 测试连接统计
func TestConnectionStatistics(t *testing.T) {
	cert, err := generateTestCert()
	if err != nil {
		t.Fatalf("生成测试证书失败: %v", err)
	}

	serverTLSConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		NextProtos:   []string{"test-stats"},
	}

	listener, err := ListenAddr("localhost:0", serverTLSConfig, DefaultConfig())
	if err != nil {
		t.Fatalf("启动服务器失败: %v", err)
	}
	defer listener.Close()

	serverAddr := listener.Addr().String()

	// 简单的服务器
	go func() {
		conn, err := listener.Accept(context.Background())
		if err != nil {
			return
		}
		defer conn.Close()

		stream, err := conn.AcceptStream(context.Background())
		if err != nil {
			return
		}
		defer stream.Close()

		// 读取并丢弃数据（不回显）
		buf := make([]byte, 1024)
		stream.Read(buf)
	}()

	time.Sleep(100 * time.Millisecond)

	clientTLSConfig := &tls.Config{
		InsecureSkipVerify: true,
		NextProtos:         []string{"test-stats"},
	}

	conn, err := DialAddr(serverAddr, clientTLSConfig, DefaultConfig())
	if err != nil {
		t.Fatalf("客户端连接失败: %v", err)
	}
	defer conn.Close()

	// 检查连接状态
	state := conn.ConnectionState()
	if !state.HandshakeComplete {
		t.Error("握手应该已完成")
	}

	if state.Version != Version1 {
		t.Errorf("期望版本 %d，得到 %d", Version1, state.Version)
	}

	// 获取统计信息
	stats := conn.GetStats()
	t.Logf("连接统计: 发送包数=%d, 接收包数=%d, RTT=%v",
		stats.PacketsSent, stats.PacketsReceived, stats.RTT)

	// 发送一些数据以产生统计
	stream, err := conn.OpenStreamSync(context.Background())
	if err != nil {
		t.Fatalf("打开流失败: %v", err)
	}
	defer stream.Close()

	testData := make([]byte, 100)
	_, err = stream.Write(testData)
	if err != nil {
		t.Fatalf("发送数据失败: %v", err)
	}

	time.Sleep(50 * time.Millisecond)

	// 再次检查统计
	newStats := conn.GetStats()
	if newStats.BytesSent <= stats.BytesSent {
		t.Error("发送字节数应该有所增加")
	}

	t.Logf("更新后的统计: 发送字节数=%d", newStats.BytesSent)
}

// generateTestCert 生成测试用的自签名证书
func generateTestCert() (tls.Certificate, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return tls.Certificate{}, err
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"QUIC Test"},
		},
		NotBefore:   time.Now(),
		NotAfter:    time.Now().Add(time.Hour),
		KeyUsage:    x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses: []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback},
		DNSNames:    []string{"localhost"},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, err
	}

	return tls.Certificate{
		Certificate: [][]byte{certDER},
		PrivateKey:  key,
	}, nil
}
