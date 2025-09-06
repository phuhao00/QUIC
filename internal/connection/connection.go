package connection

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/quic-go/quic/internal/packet"
	"github.com/quic-go/quic/internal/stream"
)

// ConnectionState 表示连接状态
type ConnectionState int

const (
	StateInitial ConnectionState = iota
	StateHandshaking
	StateConnected
	StateClosing
	StateClosed
)

func (s ConnectionState) String() string {
	switch s {
	case StateInitial:
		return "Initial"
	case StateHandshaking:
		return "Handshaking"
	case StateConnected:
		return "Connected"
	case StateClosing:
		return "Closing"
	case StateClosed:
		return "Closed"
	default:
		return "Unknown"
	}
}

// Connection 表示一个QUIC连接
type Connection struct {
	// 基本信息
	localAddr    net.Addr
	remoteAddr   net.Addr
	localConnID  packet.ConnectionID
	remoteConnID packet.ConnectionID
	version      uint32

	// 连接状态
	state      ConnectionState
	stateMutex sync.RWMutex

	// 数据包处理
	packetConn net.PacketConn
	sendQueue  chan []byte
	recvQueue  chan []byte

	// 流管理
	streams      map[uint64]*stream.Stream
	streamsMutex sync.RWMutex
	nextStreamID uint64

	// 数据包序号
	sendPacketNumber atomic.Uint64
	recvPacketNumber atomic.Uint64

	// 定时器和重传
	rttStats            *RTTStats
	retransmissionTimer *time.Timer

	// 控制通道
	closeChan chan struct{}
	errorChan chan error

	// 配置
	config *Config

	// 上下文
	ctx    context.Context
	cancel context.CancelFunc
}

// Config 表示连接配置
type Config struct {
	// 连接超时
	HandshakeTimeout time.Duration
	IdleTimeout      time.Duration

	// 流控制
	MaxStreams    uint64
	MaxStreamData uint64
	MaxData       uint64

	// 重传配置
	MaxRetransmissions int
	InitialRTT         time.Duration

	// 其他配置
	KeepAlive       bool
	KeepAlivePeriod time.Duration
}

// DefaultConfig 返回默认配置
func DefaultConfig() *Config {
	return &Config{
		HandshakeTimeout:   10 * time.Second,
		IdleTimeout:        30 * time.Second,
		MaxStreams:         100,
		MaxStreamData:      1024 * 1024,      // 1MB
		MaxData:            16 * 1024 * 1024, // 16MB
		MaxRetransmissions: 3,
		InitialRTT:         100 * time.Millisecond,
		KeepAlive:          true,
		KeepAlivePeriod:    30 * time.Second,
	}
}

// RTTStats 表示RTT统计信息
type RTTStats struct {
	mutex        sync.RWMutex
	latestRTT    time.Duration
	smoothedRTT  time.Duration
	rttVariation time.Duration
	minRTT       time.Duration
}

// NewConnection 创建新的连接
func NewConnection(localAddr, remoteAddr net.Addr, conn net.PacketConn, config *Config) *Connection {
	if config == nil {
		config = DefaultConfig()
	}

	ctx, cancel := context.WithCancel(context.Background())

	// 生成本地连接ID
	localConnID := make([]byte, 8)
	rand.Read(localConnID)

	c := &Connection{
		localAddr:   localAddr,
		remoteAddr:  remoteAddr,
		localConnID: localConnID,
		version:     1, // QUIC v1
		state:       StateInitial,
		packetConn:  conn,
		sendQueue:   make(chan []byte, 100),
		recvQueue:   make(chan []byte, 100),
		streams:     make(map[uint64]*stream.Stream),
		rttStats:    &RTTStats{minRTT: time.Hour}, // 初始化为很大的值
		closeChan:   make(chan struct{}),
		errorChan:   make(chan error, 1),
		config:      config,
		ctx:         ctx,
		cancel:      cancel,
	}

	// 初始化RTT
	c.rttStats.smoothedRTT = config.InitialRTT
	c.rttStats.rttVariation = config.InitialRTT / 2

	// 启动后台处理goroutines
	go c.sendLoop()
	go c.receiveLoop()

	return c
}

// GetState 获取连接状态
func (c *Connection) GetState() ConnectionState {
	c.stateMutex.RLock()
	defer c.stateMutex.RUnlock()
	return c.state
}

// setState 设置连接状态
func (c *Connection) setState(state ConnectionState) {
	c.stateMutex.Lock()
	defer c.stateMutex.Unlock()
	c.state = state
}

// LocalAddr 返回本地地址
func (c *Connection) LocalAddr() net.Addr {
	return c.localAddr
}

// RemoteAddr 返回远程地址
func (c *Connection) RemoteAddr() net.Addr {
	return c.remoteAddr
}

// ConnectionID 返回本地连接ID
func (c *Connection) ConnectionID() packet.ConnectionID {
	return c.localConnID
}

// OpenStream 打开新的流
func (c *Connection) OpenStream() (*stream.Stream, error) {
	if c.GetState() != StateConnected {
		return nil, fmt.Errorf("连接未建立")
	}

	c.streamsMutex.Lock()
	defer c.streamsMutex.Unlock()

	if uint64(len(c.streams)) >= c.config.MaxStreams {
		return nil, fmt.Errorf("超过最大流数量限制")
	}

	streamID := c.nextStreamID
	c.nextStreamID += 4 // 客户端发起的双向流使用4的倍数

	s := stream.NewStream(streamID, c.config.MaxStreamData)
	c.streams[streamID] = s

	return s, nil
}

// AcceptStream 接受新的流
func (c *Connection) AcceptStream(ctx context.Context) (*stream.Stream, error) {
	// 实际实现中，这里会等待对端打开的流
	// 目前返回错误
	return nil, fmt.Errorf("暂未实现")
}

// SendPacket 发送数据包
func (c *Connection) SendPacket(frames []packet.Frame) error {
	if c.GetState() == StateClosed {
		return fmt.Errorf("连接已关闭")
	}

	// 创建数据包头部
	header := &packet.Header{
		Type:         packet.PacketType1RTT,
		DestConnID:   c.remoteConnID,
		PacketNumber: packet.PacketNumber(c.sendPacketNumber.Add(1)),
		IsLongHeader: false,
	}

	// 序列化数据包
	buf := make([]byte, 1500) // MTU大小
	offset := 0

	// 序列化头部
	headerLen, err := header.SerializeHeader(buf[offset:])
	if err != nil {
		return fmt.Errorf("序列化头部失败: %v", err)
	}
	offset += headerLen

	// 序列化帧
	for _, frame := range frames {
		frameLen, err := frame.Serialize(buf[offset:])
		if err != nil {
			return fmt.Errorf("序列化帧失败: %v", err)
		}
		offset += frameLen
	}

	// 发送数据包
	select {
	case c.sendQueue <- buf[:offset]:
		return nil
	case <-c.ctx.Done():
		return fmt.Errorf("连接已关闭")
	}
}

// sendLoop 发送循环
func (c *Connection) sendLoop() {
	defer func() {
		if r := recover(); r != nil {
			c.errorChan <- fmt.Errorf("发送循环异常: %v", r)
		}
	}()

	for {
		select {
		case data := <-c.sendQueue:
			_, err := c.packetConn.WriteTo(data, c.remoteAddr)
			if err != nil {
				c.errorChan <- fmt.Errorf("发送数据包失败: %v", err)
				return
			}

		case <-c.ctx.Done():
			return
		}
	}
}

// receiveLoop 接收循环
func (c *Connection) receiveLoop() {
	defer func() {
		if r := recover(); r != nil {
			c.errorChan <- fmt.Errorf("接收循环异常: %v", r)
		}
	}()

	buf := make([]byte, 1500)

	for {
		select {
		case <-c.ctx.Done():
			return
		default:
			// 设置读取超时
			if deadline, ok := c.ctx.Deadline(); ok {
				c.packetConn.SetReadDeadline(deadline)
			}

			n, addr, err := c.packetConn.ReadFrom(buf)
			if err != nil {
				if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
					continue
				}
				c.errorChan <- fmt.Errorf("读取数据包失败: %v", err)
				return
			}

			// 验证发送方地址
			if addr.String() != c.remoteAddr.String() {
				continue // 忽略来自其他地址的数据包
			}

			// 处理接收到的数据包
			go c.handlePacket(buf[:n])
		}
	}
}

// handlePacket 处理接收到的数据包
func (c *Connection) handlePacket(data []byte) {
	defer func() {
		if r := recover(); r != nil {
			c.errorChan <- fmt.Errorf("处理数据包异常: %v", r)
		}
	}()

	// 解析数据包头部
	header, headerLen, err := packet.ParseHeader(data)
	if err != nil {
		return // 忽略无效的数据包
	}

	// 验证连接ID
	if header.DestConnID.String() != c.localConnID.String() {
		return // 不是发给我们的数据包
	}

	// 更新远程连接ID
	if len(c.remoteConnID) == 0 {
		c.remoteConnID = header.SrcConnID
	}

	// 解析帧
	frameData := data[headerLen:]
	offset := 0

	for offset < len(frameData) {
		frame, frameLen, err := packet.ParseFrame(frameData[offset:])
		if err != nil {
			break
		}

		c.handleFrame(frame)
		offset += frameLen
	}
}

// handleFrame 处理单个帧
func (c *Connection) handleFrame(frame packet.Frame) {
	switch f := frame.(type) {
	case *packet.StreamFrame:
		c.handleStreamFrame(f)
	case *packet.AckFrame:
		c.handleAckFrame(f)
	case *packet.ConnectionCloseFrame:
		c.handleConnectionCloseFrame(f)
	case *packet.PingFrame:
		c.handlePingFrame(f)
		// 其他帧类型的处理...
	}
}

// handleStreamFrame 处理STREAM帧
func (c *Connection) handleStreamFrame(frame *packet.StreamFrame) {
	c.streamsMutex.RLock()
	s, exists := c.streams[frame.StreamID]
	c.streamsMutex.RUnlock()

	if !exists {
		// 创建新流
		c.streamsMutex.Lock()
		s = stream.NewStream(frame.StreamID, c.config.MaxStreamData)
		c.streams[frame.StreamID] = s
		c.streamsMutex.Unlock()
	}

	// 将数据写入流
	s.ReceiveData(frame.Data, frame.Offset, frame.Fin)
}

// handleAckFrame 处理ACK帧
func (c *Connection) handleAckFrame(frame *packet.AckFrame) {
	// 更新RTT统计
	// 这里需要实际的发送时间戳，简化实现
	c.updateRTT(time.Millisecond * 50) // 假设RTT
}

// handleConnectionCloseFrame 处理CONNECTION_CLOSE帧
func (c *Connection) handleConnectionCloseFrame(frame *packet.ConnectionCloseFrame) {
	c.setState(StateClosed)
	c.cancel()
}

// handlePingFrame 处理PING帧
func (c *Connection) handlePingFrame(frame *packet.PingFrame) {
	// 发送ACK帧作为响应
	ackFrame := &packet.AckFrame{
		LargestAcked: uint64(c.recvPacketNumber.Load()),
		AckDelay:     0,
		AckRanges:    []packet.AckRange{},
	}
	c.SendPacket([]packet.Frame{ackFrame})
}

// updateRTT 更新RTT统计
func (c *Connection) updateRTT(latestRTT time.Duration) {
	c.rttStats.mutex.Lock()
	defer c.rttStats.mutex.Unlock()

	c.rttStats.latestRTT = latestRTT

	if c.rttStats.minRTT > latestRTT {
		c.rttStats.minRTT = latestRTT
	}

	// 更新smoothed RTT和RTT variation
	if c.rttStats.smoothedRTT == 0 {
		c.rttStats.smoothedRTT = latestRTT
		c.rttStats.rttVariation = latestRTT / 2
	} else {
		rttDiff := c.rttStats.smoothedRTT - latestRTT
		if rttDiff < 0 {
			rttDiff = -rttDiff
		}
		c.rttStats.rttVariation = (3*c.rttStats.rttVariation + rttDiff) / 4
		c.rttStats.smoothedRTT = (7*c.rttStats.smoothedRTT + latestRTT) / 8
	}
}

// Close 关闭连接
func (c *Connection) Close() error {
	if c.GetState() == StateClosed {
		return nil
	}

	c.setState(StateClosing)

	// 发送CONNECTION_CLOSE帧
	closeFrame := &packet.ConnectionCloseFrame{
		ErrorCode:    0,
		ReasonPhrase: []byte("Connection closed by application"),
		IsAppError:   true,
	}

	err := c.SendPacket([]packet.Frame{closeFrame})
	if err == nil {
		// 等待一小段时间让数据包发送出去
		time.Sleep(100 * time.Millisecond)
	}

	c.setState(StateClosed)
	c.cancel()

	// 关闭所有流
	c.streamsMutex.Lock()
	for _, s := range c.streams {
		s.Close()
	}
	c.streams = make(map[uint64]*stream.Stream)
	c.streamsMutex.Unlock()

	return nil
}

// Wait 等待连接关闭或出错
func (c *Connection) Wait() error {
	select {
	case err := <-c.errorChan:
		return err
	case <-c.ctx.Done():
		return c.ctx.Err()
	}
}

// String 返回连接的字符串表示
func (c *Connection) String() string {
	return fmt.Sprintf("QUIC Connection [%s -> %s] State: %s ConnID: %s",
		c.localAddr, c.remoteAddr, c.GetState(), hex.EncodeToString(c.localConnID))
}
