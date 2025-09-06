package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"time"

	"github.com/quic-go/quic"
)

func main() {
	// 生成自签名证书
	cert, err := generateSelfSignedCert()
	if err != nil {
		log.Fatalf("生成证书失败: %v", err)
	}

	// 创建TLS配置
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		NextProtos:   []string{"quic-echo-example"},
	}

	// 创建QUIC配置
	config := quic.DefaultConfig()
	config.Allow0RTT = true

	// 监听QUIC连接
	listener, err := quic.ListenAddr("localhost:4242", tlsConfig, config)
	if err != nil {
		log.Fatalf("监听失败: %v", err)
	}
	defer listener.Close()

	fmt.Printf("QUIC服务器正在监听 %s\n", listener.Addr())

	for {
		// 接受新连接
		conn, err := listener.Accept(context.Background())
		if err != nil {
			log.Printf("接受连接失败: %v", err)
			continue
		}

		fmt.Printf("新连接来自: %s\n", conn.RemoteAddr())

		// 处理连接
		go handleConnection(conn)
	}
}

// handleConnection 处理单个连接
func handleConnection(conn quic.Connection) {
	defer conn.Close()

	for {
		// 接受新流
		stream, err := conn.AcceptStream(context.Background())
		if err != nil {
			log.Printf("接受流失败: %v", err)
			return
		}

		fmt.Printf("新流 ID: %d\n", stream.StreamID())

		// 处理流
		go handleStream(stream)
	}
}

// handleStream 处理单个流（回显服务）
func handleStream(stream quic.Stream) {
	defer stream.Close()

	// 读取数据并回显
	buf := make([]byte, 1024)
	for {
		n, err := stream.Read(buf)
		if err != nil {
			if err != io.EOF {
				log.Printf("读取流数据失败: %v", err)
			}
			return
		}

		data := buf[:n]
		fmt.Printf("接收到数据: %s\n", string(data))

		// 回显数据
		_, err = stream.Write(data)
		if err != nil {
			log.Printf("写入流数据失败: %v", err)
			return
		}

		// 如果收到 "bye"，关闭流
		if string(data) == "bye" {
			fmt.Println("收到bye，关闭流")
			return
		}
	}
}

// generateSelfSignedCert 生成自签名证书
func generateSelfSignedCert() (tls.Certificate, error) {
	// 生成私钥
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return tls.Certificate{}, err
	}

	// 创建证书模板
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization:  []string{"QUIC Go Example"},
			Country:       []string{"CN"},
			Province:      []string{""},
			Locality:      []string{"Beijing"},
			StreetAddress: []string{""},
			PostalCode:    []string{""},
		},
		NotBefore:   time.Now(),
		NotAfter:    time.Now().Add(365 * 24 * time.Hour), // 1年有效期
		KeyUsage:    x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses: []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback},
		DNSNames:    []string{"localhost"},
	}

	// 生成证书
	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, err
	}

	return tls.Certificate{
		Certificate: [][]byte{certDER},
		PrivateKey:  key,
	}, nil
}
