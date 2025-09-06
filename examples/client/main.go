package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"os"
	"strings"
	"time"

	"github.com/quic-go/quic"
)

func main() {
	// 创建TLS配置（客户端）
	tlsConfig := &tls.Config{
		InsecureSkipVerify: true, // 仅用于演示，生产环境应该验证证书
		NextProtos:         []string{"quic-echo-example"},
	}

	// 创建QUIC配置
	config := quic.DefaultConfig()
	config.Allow0RTT = true

	// 连接到服务器
	fmt.Println("正在连接到 QUIC 服务器...")
	conn, err := quic.DialAddr("localhost:4242", tlsConfig, config)
	if err != nil {
		log.Fatalf("连接失败: %v", err)
	}
	defer conn.Close()

	fmt.Printf("已连接到服务器: %s\n", conn.RemoteAddr())
	fmt.Printf("本地地址: %s\n", conn.LocalAddr())

	// 显示连接状态
	state := conn.ConnectionState()
	fmt.Printf("连接状态: 握手完成=%v, 版本=%d\n", state.HandshakeComplete, state.Version)

	// 打开流
	stream, err := conn.OpenStreamSync(context.Background())
	if err != nil {
		log.Fatalf("打开流失败: %v", err)
	}
	defer stream.Close()

	fmt.Printf("已打开流 ID: %d\n", stream.StreamID())

	// 启动接收goroutine
	go receiveMessages(stream)

	// 发送消息
	sendMessages(stream)
}

// sendMessages 发送消息
func sendMessages(stream quic.Stream) {
	scanner := bufio.NewScanner(os.Stdin)

	fmt.Println("\n=== QUIC 回显客户端 ===")
	fmt.Println("输入消息按回车发送，输入 'bye' 退出")
	fmt.Print("> ")

	for scanner.Scan() {
		text := strings.TrimSpace(scanner.Text())
		if text == "" {
			fmt.Print("> ")
			continue
		}

		// 发送消息
		_, err := stream.Write([]byte(text))
		if err != nil {
			log.Printf("发送消息失败: %v", err)
			return
		}

		fmt.Printf("已发送: %s\n", text)

		// 如果是bye，退出
		if text == "bye" {
			time.Sleep(100 * time.Millisecond) // 等待服务器处理
			return
		}

		fmt.Print("> ")
	}

	if err := scanner.Err(); err != nil {
		log.Printf("读取输入失败: %v", err)
	}
}

// receiveMessages 接收消息
func receiveMessages(stream quic.Stream) {
	buf := make([]byte, 1024)

	for {
		n, err := stream.Read(buf)
		if err != nil {
			if err != io.EOF {
				log.Printf("接收消息失败: %v", err)
			}
			return
		}

		message := string(buf[:n])
		fmt.Printf("\n收到回显: %s\n", message)
		fmt.Print("> ")
	}
}
