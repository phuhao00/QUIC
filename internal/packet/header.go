package packet

import (
	"encoding/binary"
	"fmt"
	"io"
)

// PacketType 定义QUIC数据包类型
type PacketType uint8

const (
	PacketTypeInitial    PacketType = 0x00
	PacketType0RTT       PacketType = 0x01
	PacketTypeHandshake  PacketType = 0x02
	PacketTypeRetry      PacketType = 0x03
	PacketTypeVersionNeg PacketType = 0xFF
	PacketType1RTT       PacketType = 0x40 // 短包头标识位
)

// ConnectionID 表示QUIC连接ID
type ConnectionID []byte

func (c ConnectionID) String() string {
	return fmt.Sprintf("%x", []byte(c))
}

// PacketNumber 表示数据包序号
type PacketNumber uint64

// Header 表示QUIC数据包头部
type Header struct {
	Type         PacketType
	Version      uint32
	DestConnID   ConnectionID
	SrcConnID    ConnectionID
	PacketNumber PacketNumber
	Token        []byte
	Length       uint64
	IsLongHeader bool
}

// ParseHeader 解析QUIC数据包头部
func ParseHeader(data []byte) (*Header, int, error) {
	if len(data) == 0 {
		return nil, 0, fmt.Errorf("空数据包")
	}

	header := &Header{}
	offset := 0

	// 读取第一个字节
	firstByte := data[offset]
	offset++

	// 检查是否为长包头
	header.IsLongHeader = (firstByte & 0x80) != 0

	if header.IsLongHeader {
		return parseLongHeader(data, header, firstByte)
	} else {
		return parseShortHeader(data, header, firstByte)
	}
}

// parseLongHeader 解析长包头
func parseLongHeader(data []byte, header *Header, firstByte byte) (*Header, int, error) {
	offset := 1

	// 包类型 (bits 4-5)
	header.Type = PacketType((firstByte & 0x30) >> 4)

	if len(data) < 5 {
		return nil, 0, fmt.Errorf("长包头数据不足")
	}

	// 版本号 (4 bytes)
	header.Version = binary.BigEndian.Uint32(data[offset : offset+4])
	offset += 4

	// 目标连接ID长度
	if offset >= len(data) {
		return nil, 0, fmt.Errorf("数据包截断")
	}
	destConnIDLen := int(data[offset])
	offset++

	// 目标连接ID
	if offset+destConnIDLen > len(data) {
		return nil, 0, fmt.Errorf("目标连接ID超出边界")
	}
	header.DestConnID = make([]byte, destConnIDLen)
	copy(header.DestConnID, data[offset:offset+destConnIDLen])
	offset += destConnIDLen

	// 源连接ID长度
	if offset >= len(data) {
		return nil, 0, fmt.Errorf("数据包截断")
	}
	srcConnIDLen := int(data[offset])
	offset++

	// 源连接ID
	if offset+srcConnIDLen > len(data) {
		return nil, 0, fmt.Errorf("源连接ID超出边界")
	}
	header.SrcConnID = make([]byte, srcConnIDLen)
	copy(header.SrcConnID, data[offset:offset+srcConnIDLen])
	offset += srcConnIDLen

	// 根据包类型处理特定字段
	switch header.Type {
	case PacketTypeInitial:
		// Token长度和Token
		tokenLen, n, err := parseVarint(data[offset:])
		if err != nil {
			return nil, 0, fmt.Errorf("解析token长度失败: %v", err)
		}
		offset += n

		if offset+int(tokenLen) > len(data) {
			return nil, 0, fmt.Errorf("token超出边界")
		}
		header.Token = make([]byte, tokenLen)
		copy(header.Token, data[offset:offset+int(tokenLen)])
		offset += int(tokenLen)
	case PacketTypeRetry:
		// Retry包没有长度字段
		return header, offset, nil
	}

	// 长度字段 (变长整数)
	length, n, err := parseVarint(data[offset:])
	if err != nil {
		return nil, 0, fmt.Errorf("解析长度失败: %v", err)
	}
	header.Length = length
	offset += n

	// 包序号长度由第一个字节的低2位决定
	pnLen := int((firstByte & 0x03) + 1)
	if offset+pnLen > len(data) {
		return nil, 0, fmt.Errorf("包序号超出边界")
	}

	// 解析包序号（截断的）
	var pn uint64
	for i := 0; i < pnLen; i++ {
		pn = (pn << 8) | uint64(data[offset+i])
	}
	header.PacketNumber = PacketNumber(pn)
	offset += pnLen

	return header, offset, nil
}

// parseShortHeader 解析短包头
func parseShortHeader(data []byte, header *Header, firstByte byte) (*Header, int, error) {
	header.Type = PacketType1RTT
	offset := 1

	// 目标连接ID（固定长度，通常在握手时协商）
	// 这里假设连接ID长度为8字节
	destConnIDLen := 8
	if offset+destConnIDLen > len(data) {
		return nil, 0, fmt.Errorf("目标连接ID超出边界")
	}
	header.DestConnID = make([]byte, destConnIDLen)
	copy(header.DestConnID, data[offset:offset+destConnIDLen])
	offset += destConnIDLen

	// 包序号长度由第一个字节的低2位决定
	pnLen := int((firstByte & 0x03) + 1)
	if offset+pnLen > len(data) {
		return nil, 0, fmt.Errorf("包序号超出边界")
	}

	// 解析包序号（截断的）
	var pn uint64
	for i := 0; i < pnLen; i++ {
		pn = (pn << 8) | uint64(data[offset+i])
	}
	header.PacketNumber = PacketNumber(pn)
	offset += pnLen

	return header, offset, nil
}

// SerializeHeader 序列化QUIC数据包头部
func (h *Header) SerializeHeader(buf []byte) (int, error) {
	if h.IsLongHeader {
		return h.serializeLongHeader(buf)
	} else {
		return h.serializeShortHeader(buf)
	}
}

// serializeLongHeader 序列化长包头
func (h *Header) serializeLongHeader(buf []byte) (int, error) {
	offset := 0

	// 第一个字节: 1LTTPPNN
	// L=1 (长包头), TT=类型, PP=保留, NN=包序号长度-1
	pnLen := getPacketNumberLength(h.PacketNumber)
	firstByte := byte(0x80) | byte(h.Type<<4) | byte(pnLen-1)
	buf[offset] = firstByte
	offset++

	// 版本号
	binary.BigEndian.PutUint32(buf[offset:], h.Version)
	offset += 4

	// 目标连接ID
	buf[offset] = byte(len(h.DestConnID))
	offset++
	copy(buf[offset:], h.DestConnID)
	offset += len(h.DestConnID)

	// 源连接ID
	buf[offset] = byte(len(h.SrcConnID))
	offset++
	copy(buf[offset:], h.SrcConnID)
	offset += len(h.SrcConnID)

	// Token（仅Initial包）
	if h.Type == PacketTypeInitial {
		n, err := putVarint(buf[offset:], uint64(len(h.Token)))
		if err != nil {
			return 0, err
		}
		offset += n
		copy(buf[offset:], h.Token)
		offset += len(h.Token)
	}

	// 长度字段（Retry包除外）
	if h.Type != PacketTypeRetry {
		n, err := putVarint(buf[offset:], h.Length)
		if err != nil {
			return 0, err
		}
		offset += n
	}

	// 包序号
	for i := pnLen - 1; i >= 0; i-- {
		buf[offset] = byte(h.PacketNumber >> (i * 8))
		offset++
	}

	return offset, nil
}

// serializeShortHeader 序列化短包头
func (h *Header) serializeShortHeader(buf []byte) (int, error) {
	offset := 0

	// 第一个字节: 01KPPPNN
	// K=密钥阶段位, PPP=保留, NN=包序号长度-1
	pnLen := getPacketNumberLength(h.PacketNumber)
	firstByte := byte(0x40) | byte(pnLen-1)
	buf[offset] = firstByte
	offset++

	// 目标连接ID
	copy(buf[offset:], h.DestConnID)
	offset += len(h.DestConnID)

	// 包序号
	for i := pnLen - 1; i >= 0; i-- {
		buf[offset] = byte(h.PacketNumber >> (i * 8))
		offset++
	}

	return offset, nil
}

// getPacketNumberLength 获取包序号需要的字节数
func getPacketNumberLength(pn PacketNumber) int {
	if pn <= 0xFF {
		return 1
	} else if pn <= 0xFFFF {
		return 2
	} else if pn <= 0xFFFFFF {
		return 3
	}
	return 4
}

// parseVarint 解析QUIC变长整数
func parseVarint(data []byte) (uint64, int, error) {
	if len(data) == 0 {
		return 0, 0, io.ErrUnexpectedEOF
	}

	firstByte := data[0]
	length := 1 << ((firstByte & 0xC0) >> 6)

	if len(data) < length {
		return 0, 0, io.ErrUnexpectedEOF
	}

	var value uint64
	for i := 0; i < length; i++ {
		if i == 0 {
			value = uint64(data[i] & 0x3F) // 清除前两位
		} else {
			value = (value << 8) | uint64(data[i])
		}
	}

	return value, length, nil
}

// putVarint 编码QUIC变长整数
func putVarint(buf []byte, value uint64) (int, error) {
	if value <= 0x3F {
		if len(buf) < 1 {
			return 0, io.ErrShortBuffer
		}
		buf[0] = byte(value)
		return 1, nil
	} else if value <= 0x3FFF {
		if len(buf) < 2 {
			return 0, io.ErrShortBuffer
		}
		buf[0] = byte((value >> 8) | 0x40)
		buf[1] = byte(value)
		return 2, nil
	} else if value <= 0x3FFFFFFF {
		if len(buf) < 4 {
			return 0, io.ErrShortBuffer
		}
		buf[0] = byte((value >> 24) | 0x80)
		buf[1] = byte(value >> 16)
		buf[2] = byte(value >> 8)
		buf[3] = byte(value)
		return 4, nil
	} else if value <= 0x3FFFFFFFFFFFFFFF {
		if len(buf) < 8 {
			return 0, io.ErrShortBuffer
		}
		buf[0] = byte((value >> 56) | 0xC0)
		buf[1] = byte(value >> 48)
		buf[2] = byte(value >> 40)
		buf[3] = byte(value >> 32)
		buf[4] = byte(value >> 24)
		buf[5] = byte(value >> 16)
		buf[6] = byte(value >> 8)
		buf[7] = byte(value)
		return 8, nil
	}

	return 0, fmt.Errorf("值太大，无法编码为变长整数")
}
