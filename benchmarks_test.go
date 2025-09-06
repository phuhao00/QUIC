package quic

import (
	"testing"
	"time"

	"github.com/quic-go/quic/internal/congestion"
	"github.com/quic-go/quic/internal/packet"
)

// BenchmarkVarintEncoding 基准测试：变长整数编码
func BenchmarkVarintEncoding(b *testing.B) {
	values := []uint64{37, 151, 16384, 1073741823}
	buf := make([]byte, 8)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for _, value := range values {
			packet.PutVarint(buf, value)
		}
	}
}

// BenchmarkVarintDecoding 基准测试：变长整数解码
func BenchmarkVarintDecoding(b *testing.B) {
	testData := [][]byte{
		{0x25},                   // 1 byte
		{0x40, 0x97},             // 2 bytes
		{0x80, 0x00, 0x40, 0x00}, // 4 bytes
		{0xC0, 0x00, 0x00, 0x00, 0x3F, 0xFF, 0xFF, 0xFF}, // 8 bytes
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for _, data := range testData {
			packet.ParseVarint(data)
		}
	}
}

// BenchmarkHeaderParsing 基准测试：包头解析
func BenchmarkHeaderParsing(b *testing.B) {
	// 构造一个典型的长包头
	headerData := []byte{
		0xC0,                   // 长包头，Initial包类型
		0x00, 0x00, 0x00, 0x01, // 版本号 1
		0x08,                                           // 目标连接ID长度
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, // 目标连接ID
		0x08,                                           // 源连接ID长度
		0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, // 源连接ID
		0x00,       // Token长度（0）
		0x40, 0x64, // 长度字段（100字节）
		0x01, // 包序号（1字节）
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		packet.ParseHeader(headerData)
	}
}

// BenchmarkHeaderSerialization 基准测试：包头序列化
func BenchmarkHeaderSerialization(b *testing.B) {
	header := &packet.Header{
		Type:         packet.PacketTypeInitial,
		Version:      1,
		DestConnID:   []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08},
		SrcConnID:    []byte{0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18},
		PacketNumber: 1,
		Length:       100,
		IsLongHeader: true,
		Token:        []byte{},
	}

	buf := make([]byte, 256)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		header.SerializeHeader(buf)
	}
}

// BenchmarkFrameParsing 基准测试：帧解析
func BenchmarkFrameParsing(b *testing.B) {
	// STREAM帧数据
	streamFrameData := []byte{
		0x0A,                                                       // STREAM帧类型（带OFF和LEN位）
		0x04,                                                       // 流ID = 4
		0x00,                                                       // 偏移量 = 0
		0x0C,                                                       // 长度 = 12
		'H', 'e', 'l', 'l', 'o', ',', ' ', 'Q', 'U', 'I', 'C', '!', // 数据
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		packet.ParseFrame(streamFrameData)
	}
}

// BenchmarkFrameSerialization 基准测试：帧序列化
func BenchmarkFrameSerialization(b *testing.B) {
	frame := &packet.StreamFrame{
		StreamID: 4,
		Offset:   0,
		Data:     []byte("Hello, QUIC!"),
		Fin:      false,
	}

	buf := make([]byte, 256)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		frame.Serialize(buf)
	}
}

// BenchmarkCongestionControlOnAck 基准测试：拥塞控制ACK处理
func BenchmarkCongestionControlOnAck(b *testing.B) {
	cc := congestion.NewCubicCongestionControl(1200)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		cc.OnAck(uint64(i), 1200, 1200, time.Now())
	}
}

// BenchmarkCongestionControlOnLoss 基准测试：拥塞控制丢包处理
func BenchmarkCongestionControlOnLoss(b *testing.B) {
	cc := congestion.NewCubicCongestionControl(1200)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		cc.OnPacketLost(uint64(i), 1200, 1200)
		// 重置状态避免一直处于恢复模式
		if i%10 == 0 {
			cc = congestion.NewCubicCongestionControl(1200)
		}
	}
}

// BenchmarkMultipleFramesParsing 基准测试：多帧解析
func BenchmarkMultipleFramesParsing(b *testing.B) {
	// 包含多个帧的数据包
	packetData := []byte{
		// PING帧
		0x01,
		// PADDING帧（5个字节）
		0x00, 0x00, 0x00, 0x00, 0x00,
		// STREAM帧
		0x0A,                    // STREAM帧类型
		0x04,                    // 流ID = 4
		0x00,                    // 偏移量 = 0
		0x05,                    // 长度 = 5
		'H', 'e', 'l', 'l', 'o', // 数据
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		offset := 0
		for offset < len(packetData) {
			frame, frameLen, err := packet.ParseFrame(packetData[offset:])
			if err != nil {
				break
			}
			_ = frame // 使用frame变量避免编译器优化
			offset += frameLen
		}
	}
}

// BenchmarkConnectionIDString 基准测试：连接ID字符串转换
func BenchmarkConnectionIDString(b *testing.B) {
	connID := packet.ConnectionID([]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08})

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = connID.String()
	}
}

// BenchmarkAckFrameSerialization 基准测试：ACK帧序列化
func BenchmarkAckFrameSerialization(b *testing.B) {
	frame := &packet.AckFrame{
		LargestAcked: 100,
		AckDelay:     50,
		AckRanges: []packet.AckRange{
			{Gap: 0, Length: 50},
			{Gap: 10, Length: 30},
		},
	}

	buf := make([]byte, 256)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		frame.Serialize(buf)
	}
}

// BenchmarkPacketNumberLength 基准测试：包序号长度计算
func BenchmarkPacketNumberLength(b *testing.B) {
	packetNumbers := []packet.PacketNumber{1, 255, 65535, 16777215}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for _, pn := range packetNumbers {
			packet.GetPacketNumberLength(pn)
		}
	}
}
