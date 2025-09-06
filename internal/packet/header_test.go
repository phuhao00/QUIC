package packet

import (
	"bytes"
	"testing"
)

func TestParseVarint(t *testing.T) {
	tests := []struct {
		name     string
		input    []byte
		expected uint64
		length   int
		hasError bool
	}{
		{
			name:     "single byte",
			input:    []byte{0x25},
			expected: 37,
			length:   1,
			hasError: false,
		},
		{
			name:     "two bytes",
			input:    []byte{0x40, 0x25},
			expected: 37,
			length:   2,
			hasError: false,
		},
		{
			name:     "four bytes",
			input:    []byte{0x80, 0x00, 0x00, 0x25},
			expected: 37,
			length:   4,
			hasError: false,
		},
		{
			name:     "eight bytes",
			input:    []byte{0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x25},
			expected: 37,
			length:   8,
			hasError: false,
		},
		{
			name:     "empty input",
			input:    []byte{},
			expected: 0,
			length:   0,
			hasError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			value, length, err := parseVarint(tt.input)

			if tt.hasError {
				if err == nil {
					t.Error("期望出现错误，但没有错误")
				}
				return
			}

			if err != nil {
				t.Errorf("意外的错误: %v", err)
				return
			}

			if value != tt.expected {
				t.Errorf("期望值 %d，但得到 %d", tt.expected, value)
			}

			if length != tt.length {
				t.Errorf("期望长度 %d，但得到 %d", tt.length, length)
			}
		})
	}
}

func TestPutVarint(t *testing.T) {
	tests := []struct {
		name     string
		value    uint64
		expected []byte
		hasError bool
	}{
		{
			name:     "single byte",
			value:    37,
			expected: []byte{0x25},
			hasError: false,
		},
		{
			name:     "two bytes",
			value:    151,
			expected: []byte{0x40, 0x97},
			hasError: false,
		},
		{
			name:     "four bytes",
			value:    16384,
			expected: []byte{0x80, 0x00, 0x40, 0x00},
			hasError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			buf := make([]byte, 8)
			length, err := putVarint(buf, tt.value)

			if tt.hasError {
				if err == nil {
					t.Error("期望出现错误，但没有错误")
				}
				return
			}

			if err != nil {
				t.Errorf("意外的错误: %v", err)
				return
			}

			result := buf[:length]
			if !bytes.Equal(result, tt.expected) {
				t.Errorf("期望 %x，但得到 %x", tt.expected, result)
			}
		})
	}
}

func TestHeaderParsing(t *testing.T) {
	// 测试长包头解析
	t.Run("long header initial packet", func(t *testing.T) {
		// 构造一个Initial包的头部数据
		data := []byte{
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

		header, headerLen, err := ParseHeader(data)
		if err != nil {
			t.Fatalf("解析头部失败: %v", err)
		}

		if header.Type != PacketTypeInitial {
			t.Errorf("期望包类型 %v，但得到 %v", PacketTypeInitial, header.Type)
		}

		if header.Version != 1 {
			t.Errorf("期望版本号 1，但得到 %d", header.Version)
		}

		expectedDestID := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}
		if !bytes.Equal(header.DestConnID, expectedDestID) {
			t.Errorf("目标连接ID不匹配，期望 %x，得到 %x", expectedDestID, header.DestConnID)
		}

		if headerLen != len(data) {
			t.Errorf("头部长度不正确，期望 %d，得到 %d", len(data), headerLen)
		}
	})

	// 测试短包头解析
	t.Run("short header", func(t *testing.T) {
		data := []byte{
			0x40,                                           // 短包头
			0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, // 目标连接ID
			0x01, // 包序号（1字节）
		}

		header, headerLen, err := ParseHeader(data)
		if err != nil {
			t.Fatalf("解析短包头失败: %v", err)
		}

		if header.Type != PacketType1RTT {
			t.Errorf("期望包类型 %v，但得到 %v", PacketType1RTT, header.Type)
		}

		if header.IsLongHeader {
			t.Error("应该是短包头")
		}

		if headerLen != len(data) {
			t.Errorf("头部长度不正确，期望 %d，得到 %d", len(data), headerLen)
		}
	})
}

func TestHeaderSerialization(t *testing.T) {
	t.Run("serialize long header", func(t *testing.T) {
		header := &Header{
			Type:         PacketTypeInitial,
			Version:      1,
			DestConnID:   []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08},
			SrcConnID:    []byte{0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18},
			PacketNumber: 1,
			Length:       100,
			IsLongHeader: true,
			Token:        []byte{},
		}

		buf := make([]byte, 256)
		length, err := header.SerializeHeader(buf)
		if err != nil {
			t.Fatalf("序列化头部失败: %v", err)
		}

		// 解析序列化的数据
		parsedHeader, parsedLen, err := ParseHeader(buf[:length])
		if err != nil {
			t.Fatalf("解析序列化的头部失败: %v", err)
		}

		if parsedLen != length {
			t.Errorf("长度不匹配，期望 %d，得到 %d", length, parsedLen)
		}

		if parsedHeader.Type != header.Type {
			t.Errorf("包类型不匹配")
		}

		if parsedHeader.Version != header.Version {
			t.Errorf("版本号不匹配")
		}

		if !bytes.Equal(parsedHeader.DestConnID, header.DestConnID) {
			t.Errorf("目标连接ID不匹配")
		}
	})
}

func TestConnectionID(t *testing.T) {
	connID := ConnectionID([]byte{0x01, 0x02, 0x03, 0x04})
	expected := "01020304"

	if connID.String() != expected {
		t.Errorf("连接ID字符串表示不正确，期望 %s，得到 %s", expected, connID.String())
	}
}
