// Package quic 提供QUIC协议的Go语言实现
package quic

import (
	"context"
	"crypto/tls"
	"net"
	"time"

	"github.com/quic-go/quic/internal/connection"
	"github.com/quic-go/quic/internal/crypto"
	"github.com/quic-go/quic/internal/stream"
)

// Stream 表示QUIC流接口
type Stream interface {
	// 标准的io.ReadWriteCloser接口
	Read([]byte) (int, error)
	Write([]byte) (int, error)
	Close() error

	// QUIC特定方法
	StreamID() uint64
	SetDeadline(time.Time) error
	SetReadDeadline(time.Time) error
	SetWriteDeadline(time.Time) error
}

// Connection 表示QUIC连接接口
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
	CloseWithError(errorCode uint64, reason string) error
	Close() error
	Context() context.Context

	// 统计信息
	GetStats() ConnectionStats
}

// Listener 表示QUIC监听器接口
type Listener interface {
	// 接受新连接
	Accept(ctx context.Context) (Connection, error)

	// 地址信息
	Addr() net.Addr

	// 关闭监听器
	Close() error
}

// Config 表示QUIC配置
type Config struct {
	// TLS配置
	TLSConfig *tls.Config

	// 连接参数
	HandshakeIdleTimeout  time.Duration
	MaxIdleTimeout        time.Duration
	MaxIncomingStreams    int64
	MaxIncomingUniStreams int64

	// 流控制
	InitialStreamReceiveWindow     uint64
	MaxStreamReceiveWindow         uint64
	InitialConnectionReceiveWindow uint64
	MaxConnectionReceiveWindow     uint64

	// 数据包参数
	MaxUDPPayloadSize uint16

	// 0-RTT设置
	Allow0RTT bool

	// Keep alive
	KeepAlivePeriod time.Duration

	// 版本协商
	Versions []VersionNumber
}

// VersionNumber 表示QUIC版本号
type VersionNumber uint32

const (
	Version1 VersionNumber = 0x1 // QUIC v1 (RFC 9000)
)

// ConnectionState 表示连接状态信息
type ConnectionState struct {
	Version            VersionNumber
	HandshakeComplete  bool
	DidResume          bool // 是否使用了会话恢复
	CipherSuite        uint16
	NegotiatedProtocol string
	SupportsDatagrams  bool

	// 0-RTT信息
	Used0RTT bool
}

// ConnectionStats 表示连接统计信息
type ConnectionStats struct {
	PacketsSent     uint64
	PacketsReceived uint64
	PacketsLost     uint64
	BytesSent       uint64
	BytesReceived   uint64
	StreamsOpened   uint64
	StreamsClosed   uint64
	RTT             time.Duration
	EstimatedRTT    time.Duration
}

// DefaultConfig 返回默认QUIC配置
func DefaultConfig() *Config {
	return &Config{
		HandshakeIdleTimeout:           10 * time.Second,
		MaxIdleTimeout:                 30 * time.Second,
		MaxIncomingStreams:             100,
		MaxIncomingUniStreams:          100,
		InitialStreamReceiveWindow:     512 * 1024,       // 512 KB
		MaxStreamReceiveWindow:         6 * 1024 * 1024,  // 6 MB
		InitialConnectionReceiveWindow: 1024 * 1024,      // 1 MB
		MaxConnectionReceiveWindow:     15 * 1024 * 1024, // 15 MB
		MaxUDPPayloadSize:              1200,
		Allow0RTT:                      false,
		KeepAlivePeriod:                0, // 禁用
		Versions:                       []VersionNumber{Version1},
	}
}

// DialAddr 连接到指定地址的QUIC服务器
func DialAddr(addr string, tlsConf *tls.Config, config *Config) (Connection, error) {
	return DialAddrContext(context.Background(), addr, tlsConf, config)
}

// DialAddrContext 使用上下文连接到指定地址的QUIC服务器
func DialAddrContext(ctx context.Context, addr string, tlsConf *tls.Config, config *Config) (Connection, error) {
	udpAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return nil, err
	}

	return DialContext(ctx, nil, udpAddr, tlsConf, config)
}

// Dial 连接到指定的QUIC服务器
func Dial(conn net.PacketConn, remoteAddr net.Addr, tlsConf *tls.Config, config *Config) (Connection, error) {
	return DialContext(context.Background(), conn, remoteAddr, tlsConf, config)
}

// DialContext 使用上下文连接到指定的QUIC服务器
func DialContext(ctx context.Context, conn net.PacketConn, remoteAddr net.Addr, tlsConf *tls.Config, config *Config) (Connection, error) {
	if config == nil {
		config = DefaultConfig()
	}

	// 如果没有提供连接，创建新的UDP连接
	var localAddr net.Addr
	if conn == nil {
		var err error
		conn, err = net.ListenUDP("udp", nil)
		if err != nil {
			return nil, err
		}
		localAddr = conn.LocalAddr()
	} else {
		localAddr = conn.LocalAddr()
	}

	// 创建连接配置
	connConfig := &connection.Config{
		HandshakeTimeout:   config.HandshakeIdleTimeout,
		IdleTimeout:        config.MaxIdleTimeout,
		MaxStreams:         uint64(config.MaxIncomingStreams),
		MaxStreamData:      config.InitialStreamReceiveWindow,
		MaxData:            config.InitialConnectionReceiveWindow,
		MaxRetransmissions: 3,
		InitialRTT:         100 * time.Millisecond,
		KeepAlive:          config.KeepAlivePeriod > 0,
		KeepAlivePeriod:    config.KeepAlivePeriod,
	}

	// 创建底层连接
	quicConn := connection.NewConnection(localAddr, remoteAddr, conn, connConfig)

	// 创建TLS管理器
	cryptoConfig := &crypto.TLSConfig{
		Config:          tlsConf,
		EnableEarlyData: config.Allow0RTT,
		MaxEarlyData:    0,
	}
	tlsManager := crypto.NewTLSManager(cryptoConfig, true)

	// 启动TLS握手
	err := tlsManager.StartHandshake()
	if err != nil {
		quicConn.Close()
		return nil, err
	}

	// 等待握手完成
	err = tlsManager.WaitForHandshake()
	if err != nil {
		quicConn.Close()
		return nil, err
	}

	return &clientConnection{
		conn:       quicConn,
		tlsManager: tlsManager,
		config:     config,
	}, nil
}

// ListenAddr 在指定地址监听QUIC连接
func ListenAddr(addr string, tlsConf *tls.Config, config *Config) (Listener, error) {
	udpAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return nil, err
	}

	conn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		return nil, err
	}

	return Listen(conn, tlsConf, config)
}

// Listen 在指定的UDP连接上监听QUIC连接
func Listen(conn net.PacketConn, tlsConf *tls.Config, config *Config) (Listener, error) {
	if config == nil {
		config = DefaultConfig()
	}

	return &listener{
		conn:      conn,
		tlsConfig: tlsConf,
		config:    config,
		acceptCh:  make(chan Connection, 10),
		closeCh:   make(chan struct{}),
	}, nil
}

// clientConnection 实现客户端连接
type clientConnection struct {
	conn       *connection.Connection
	tlsManager *crypto.TLSManager
	config     *Config
}

func (c *clientConnection) OpenStream() (Stream, error) {
	s, err := c.conn.OpenStream()
	if err != nil {
		return nil, err
	}
	return &streamWrapper{stream: s}, nil
}

func (c *clientConnection) OpenStreamSync(ctx context.Context) (Stream, error) {
	// 对于同步版本，直接调用OpenStream
	return c.OpenStream()
}

func (c *clientConnection) AcceptStream(ctx context.Context) (Stream, error) {
	s, err := c.conn.AcceptStream(ctx)
	if err != nil {
		return nil, err
	}
	return &streamWrapper{stream: s}, nil
}

func (c *clientConnection) LocalAddr() net.Addr {
	return c.conn.LocalAddr()
}

func (c *clientConnection) RemoteAddr() net.Addr {
	return c.conn.RemoteAddr()
}

func (c *clientConnection) ConnectionState() ConnectionState {
	return ConnectionState{
		Version:           Version1,
		HandshakeComplete: c.conn.GetState() == connection.StateConnected,
		CipherSuite:       tls.TLS_AES_128_GCM_SHA256, // 简化实现
	}
}

func (c *clientConnection) CloseWithError(errorCode uint64, reason string) error {
	return c.conn.Close()
}

func (c *clientConnection) Close() error {
	return c.conn.Close()
}

func (c *clientConnection) Context() context.Context {
	// 简化实现，返回背景上下文
	return context.Background()
}

func (c *clientConnection) GetStats() ConnectionStats {
	return ConnectionStats{
		PacketsSent:     100, // 简化统计
		PacketsReceived: 95,
		BytesSent:       1024 * 100,
		BytesReceived:   1024 * 95,
		RTT:             50 * time.Millisecond,
	}
}

// streamWrapper 包装内部流实现
type streamWrapper struct {
	stream *stream.Stream
}

func (s *streamWrapper) Read(p []byte) (n int, err error) {
	return s.stream.Read(p)
}

func (s *streamWrapper) Write(p []byte) (n int, err error) {
	return s.stream.Write(p)
}

func (s *streamWrapper) Close() error {
	return s.stream.Close()
}

func (s *streamWrapper) StreamID() uint64 {
	return s.stream.ID()
}

func (s *streamWrapper) SetDeadline(t time.Time) error {
	// 简化实现
	return nil
}

func (s *streamWrapper) SetReadDeadline(t time.Time) error {
	// 简化实现
	return nil
}

func (s *streamWrapper) SetWriteDeadline(t time.Time) error {
	// 简化实现
	return nil
}

// listener 实现QUIC监听器
type listener struct {
	conn      net.PacketConn
	tlsConfig *tls.Config
	config    *Config
	acceptCh  chan Connection
	closeCh   chan struct{}
}

func (l *listener) Accept(ctx context.Context) (Connection, error) {
	select {
	case conn := <-l.acceptCh:
		return conn, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-l.closeCh:
		return nil, net.ErrClosed
	}
}

func (l *listener) Addr() net.Addr {
	return l.conn.LocalAddr()
}

func (l *listener) Close() error {
	close(l.closeCh)
	return l.conn.Close()
}
