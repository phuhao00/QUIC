package stream

import (
	"io"
	"testing"
	"time"
)

func TestNewStream(t *testing.T) {
	streamID := uint64(4) // 客户端发起的双向流
	maxData := uint64(1024)

	s := NewStream(streamID, maxData)

	if s.ID() != streamID {
		t.Errorf("期望流ID %d，但得到 %d", streamID, s.ID())
	}

	if s.Type() != StreamTypeBidirectional {
		t.Errorf("期望双向流，但得到 %v", s.Type())
	}

	if s.State() != StateOpen {
		t.Errorf("期望流状态为Open，但得到 %v", s.State())
	}
}

func TestStreamType(t *testing.T) {
	tests := []struct {
		streamID     uint64
		expectedType StreamType
	}{
		{0, StreamTypeBidirectional},  // 客户端双向流
		{1, StreamTypeBidirectional},  // 服务端双向流 (01)
		{2, StreamTypeUnidirectional}, // 客户端单向流 (10)
		{3, StreamTypeUnidirectional}, // 客户端单向流
		{4, StreamTypeBidirectional},  // 客户端双向流
	}

	for _, tt := range tests {
		t.Run("stream type", func(t *testing.T) {
			streamType := getStreamType(tt.streamID)
			if streamType != tt.expectedType {
				t.Errorf("流ID %d 期望类型 %v，但得到 %v",
					tt.streamID, tt.expectedType, streamType)
			}
		})
	}
}

func TestStreamReadWrite(t *testing.T) {
	s := NewStream(4, 1024)

	// 测试写入
	testData := []byte("Hello, QUIC!")
	n, err := s.Write(testData)
	if err != nil {
		t.Fatalf("写入失败: %v", err)
	}

	if n != len(testData) {
		t.Errorf("期望写入 %d 字节，但写入了 %d 字节", len(testData), n)
	}

	// 模拟从网络接收数据
	err = s.ReceiveData(testData, 0, false)
	if err != nil {
		t.Fatalf("接收数据失败: %v", err)
	}

	// 测试读取
	readBuf := make([]byte, 100)
	n, err = s.Read(readBuf)
	if err != nil {
		t.Fatalf("读取失败: %v", err)
	}

	if n != len(testData) {
		t.Errorf("期望读取 %d 字节，但读取了 %d 字节", len(testData), n)
	}

	readData := readBuf[:n]
	for i, b := range testData {
		if readData[i] != b {
			t.Errorf("读取的数据不匹配，位置 %d 期望 %x，得到 %x", i, b, readData[i])
		}
	}
}

func TestStreamClose(t *testing.T) {
	s := NewStream(4, 1024)

	// 关闭流
	err := s.Close()
	if err != nil {
		t.Fatalf("关闭流失败: %v", err)
	}

	// 检查状态
	if s.State() != StateHalfClosedLocal {
		t.Errorf("期望流状态为 HalfClosedLocal，但得到 %v", s.State())
	}

	// 尝试写入应该失败
	_, err = s.Write([]byte("test"))
	if err == nil {
		t.Error("期望写入失败，但成功了")
	}
}

func TestStreamFinHandling(t *testing.T) {
	s := NewStream(4, 1024)

	testData := []byte("Hello")

	// 接收带有FIN标志的数据
	err := s.ReceiveData(testData, 0, true)
	if err != nil {
		t.Fatalf("接收数据失败: %v", err)
	}

	// 读取数据
	readBuf := make([]byte, 100)
	n, err := s.Read(readBuf)
	if err != nil {
		t.Fatalf("读取失败: %v", err)
	}

	if n != len(testData) {
		t.Errorf("期望读取 %d 字节，但读取了 %d 字节", len(testData), n)
	}

	// 再次读取应该返回EOF
	_, err = s.Read(readBuf)
	if err != io.EOF {
		t.Errorf("期望返回EOF，但得到 %v", err)
	}

	// 流状态应该是HalfClosedRemote
	if s.State() != StateHalfClosedRemote {
		t.Errorf("期望流状态为 HalfClosedRemote，但得到 %v", s.State())
	}
}

func TestStreamReset(t *testing.T) {
	s := NewStream(4, 1024)

	// 重置流
	s.Reset(42, "测试重置")

	// 检查状态
	if s.State() != StateReset {
		t.Errorf("期望流状态为 Reset，但得到 %v", s.State())
	}

	// 尝试读写应该返回错误
	_, err := s.Read(make([]byte, 10))
	if err == nil {
		t.Error("期望读取失败，但成功了")
	}

	_, err = s.Write([]byte("test"))
	if err == nil {
		t.Error("期望写入失败，但成功了")
	}
}

func TestStreamOrderedData(t *testing.T) {
	s := NewStream(4, 1024)

	// 按乱序接收数据
	err := s.ReceiveData([]byte("World"), 6, false)
	if err != nil {
		t.Fatalf("接收数据失败: %v", err)
	}

	err = s.ReceiveData([]byte("Hello "), 0, false)
	if err != nil {
		t.Fatalf("接收数据失败: %v", err)
	}

	err = s.ReceiveData([]byte("!"), 11, true)
	if err != nil {
		t.Fatalf("接收数据失败: %v", err)
	}

	// 读取应该得到有序的数据
	readBuf := make([]byte, 100)
	n, err := s.Read(readBuf)
	if err != nil {
		t.Fatalf("读取失败: %v", err)
	}

	expected := "Hello World!"
	result := string(readBuf[:n])

	if result != expected {
		t.Errorf("期望读取 %s，但得到 %s", expected, result)
	}
}

func TestStreamStats(t *testing.T) {
	s := NewStream(4, 1024)

	// 写入一些数据
	testData := []byte("Hello, QUIC!")
	s.Write(testData)

	// 接收一些数据
	s.ReceiveData([]byte("Response"), 0, false)

	// 获取统计信息
	stats := s.GetStats()

	if stats.ID != 4 {
		t.Errorf("期望流ID 4，但得到 %d", stats.ID)
	}

	if stats.Type != StreamTypeBidirectional {
		t.Errorf("期望双向流，但得到 %v", stats.Type)
	}

	if stats.State != StateOpen {
		t.Errorf("期望状态为Open，但得到 %v", stats.State)
	}

	if stats.SentData != uint64(len(testData)) {
		t.Errorf("期望发送数据 %d 字节，但得到 %d", len(testData), stats.SentData)
	}

	if stats.MaxData != 1024 {
		t.Errorf("期望最大数据 1024，但得到 %d", stats.MaxData)
	}

	// 检查创建时间
	if time.Since(stats.CreatedAt) > time.Second {
		t.Error("创建时间不合理")
	}
}
