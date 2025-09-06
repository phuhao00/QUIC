package stream

import (
	"fmt"
	"io"
	"sort"
	"sync"
	"time"
)

// StreamType 表示流的类型
type StreamType int

const (
	StreamTypeBidirectional StreamType = iota
	StreamTypeUnidirectional
)

func (t StreamType) String() string {
	switch t {
	case StreamTypeBidirectional:
		return "Bidirectional"
	case StreamTypeUnidirectional:
		return "Unidirectional"
	default:
		return "Unknown"
	}
}

// StreamState 表示流的状态
type StreamState int

const (
	StateOpen StreamState = iota
	StateHalfClosedLocal
	StateHalfClosedRemote
	StateClosed
	StateReset
)

func (s StreamState) String() string {
	switch s {
	case StateOpen:
		return "Open"
	case StateHalfClosedLocal:
		return "HalfClosedLocal"
	case StateHalfClosedRemote:
		return "HalfClosedRemote"
	case StateClosed:
		return "Closed"
	case StateReset:
		return "Reset"
	default:
		return "Unknown"
	}
}

// StreamData 表示流数据片段
type StreamData struct {
	Offset uint64
	Data   []byte
	Fin    bool
}

// Stream 表示一个QUIC流
type Stream struct {
	id         uint64
	streamType StreamType
	state      StreamState
	stateMutex sync.RWMutex

	// 发送侧
	sendBuffer   []byte
	sendOffset   uint64
	sendMutex    sync.Mutex
	sendFinished bool

	// 接收侧
	recvBuffer      map[uint64]StreamData // 偏移量 -> 数据
	recvBufferMutex sync.RWMutex
	recvOffset      uint64 // 下一个期望的偏移量
	recvFinished    bool
	recvFinalOffset uint64

	// 流控制
	maxData  uint64 // 我们可以接收的最大数据量
	sentData uint64 // 我们已发送的数据量
	recvData uint64 // 我们已接收的数据量

	// 阻塞和通知
	readCond  *sync.Cond
	writeCond *sync.Cond
	closeCond *sync.Cond

	// 读写接口
	readBuffer      []byte
	readBufferMutex sync.Mutex

	// 错误状态
	resetError error

	// 创建时间
	createdAt time.Time
}

// NewStream 创建新的流
func NewStream(id uint64, maxData uint64) *Stream {
	s := &Stream{
		id:         id,
		streamType: getStreamType(id),
		state:      StateOpen,
		recvBuffer: make(map[uint64]StreamData),
		maxData:    maxData,
		createdAt:  time.Now(),
	}

	s.readCond = sync.NewCond(&s.readBufferMutex)
	s.writeCond = sync.NewCond(&s.sendMutex)
	s.closeCond = sync.NewCond(&s.stateMutex)

	return s
}

// getStreamType 根据流ID确定流类型
func getStreamType(id uint64) StreamType {
	// 流ID的第二位（bit 1）决定流类型
	// 0: 双向流, 1: 单向流
	if (id & 0x02) == 0 {
		return StreamTypeBidirectional
	}
	return StreamTypeUnidirectional
}

// ID 返回流ID
func (s *Stream) ID() uint64 {
	return s.id
}

// Type 返回流类型
func (s *Stream) Type() StreamType {
	return s.streamType
}

// State 返回流状态
func (s *Stream) State() StreamState {
	s.stateMutex.RLock()
	defer s.stateMutex.RUnlock()
	return s.state
}

// setState 设置流状态
func (s *Stream) setState(state StreamState) {
	s.stateMutex.Lock()
	defer s.stateMutex.Unlock()
	s.state = state
	s.closeCond.Broadcast()
}

// Read 从流中读取数据
func (s *Stream) Read(p []byte) (n int, err error) {
	s.readBufferMutex.Lock()
	defer s.readBufferMutex.Unlock()

	for {
		// 检查流状态
		state := s.State()
		if state == StateClosed || state == StateReset {
			if s.resetError != nil {
				return 0, s.resetError
			}
			return 0, io.EOF
		}

		// 尝试从接收缓冲区读取数据
		data := s.getOrderedData()
		if len(data) > 0 {
			n = copy(p, data)
			s.consumeData(n)
			return n, nil
		}

		// 如果远程已关闭且没有更多数据，返回EOF
		if state == StateHalfClosedRemote && s.recvFinished {
			return 0, io.EOF
		}

		// 等待更多数据
		s.readCond.Wait()
	}
}

// Write 向流中写入数据
func (s *Stream) Write(p []byte) (n int, err error) {
	s.sendMutex.Lock()
	defer s.sendMutex.Unlock()

	state := s.State()
	if state == StateClosed || state == StateReset {
		if s.resetError != nil {
			return 0, s.resetError
		}
		return 0, io.ErrClosedPipe
	}

	if state == StateHalfClosedLocal {
		return 0, io.ErrClosedPipe
	}

	// 单向流检查
	if s.streamType == StreamTypeUnidirectional {
		// 检查这是否是发送方向的单向流
		if !s.canSend() {
			return 0, fmt.Errorf("无法在接收单向流上写入")
		}
	}

	// 将数据添加到发送缓冲区
	s.sendBuffer = append(s.sendBuffer, p...)
	s.sentData += uint64(len(p))

	return len(p), nil
}

// Close 关闭流的发送方向
func (s *Stream) Close() error {
	s.sendMutex.Lock()
	defer s.sendMutex.Unlock()

	state := s.State()
	if state == StateClosed || state == StateReset {
		return nil
	}

	s.sendFinished = true

	// 更新流状态
	switch state {
	case StateOpen:
		s.setState(StateHalfClosedLocal)
	case StateHalfClosedRemote:
		s.setState(StateClosed)
	}

	return nil
}

// Reset 重置流
func (s *Stream) Reset(errorCode uint64, reason string) {
	s.setState(StateReset)
	s.resetError = fmt.Errorf("流已重置 (错误码: %d): %s", errorCode, reason)

	// 唤醒所有等待的goroutine
	s.readCond.Broadcast()
	s.writeCond.Broadcast()
	s.closeCond.Broadcast()
}

// ReceiveData 接收来自网络的数据
func (s *Stream) ReceiveData(data []byte, offset uint64, fin bool) error {
	s.recvBufferMutex.Lock()
	defer s.recvBufferMutex.Unlock()

	state := s.State()
	if state == StateClosed || state == StateReset {
		return fmt.Errorf("流已关闭或重置")
	}

	// 检查偏移量是否合理
	if offset+uint64(len(data)) > s.maxData {
		return fmt.Errorf("接收数据超出流量控制限制")
	}

	// 存储数据片段
	s.recvBuffer[offset] = StreamData{
		Offset: offset,
		Data:   data,
		Fin:    fin,
	}

	if fin {
		s.recvFinished = true
		s.recvFinalOffset = offset + uint64(len(data))

		// 更新流状态
		switch state {
		case StateOpen:
			s.setState(StateHalfClosedRemote)
		case StateHalfClosedLocal:
			s.setState(StateClosed)
		}
	}

	// 唤醒等待读取的goroutine
	s.readCond.Broadcast()

	return nil
}

// GetSendData 获取待发送的数据
func (s *Stream) GetSendData(maxSize int) ([]byte, uint64, bool, error) {
	s.sendMutex.Lock()
	defer s.sendMutex.Unlock()

	if len(s.sendBuffer) == 0 && !s.sendFinished {
		return nil, 0, false, nil
	}

	// 确定要发送的数据量
	dataSize := len(s.sendBuffer)
	if dataSize > maxSize {
		dataSize = maxSize
	}

	data := make([]byte, dataSize)
	copy(data, s.sendBuffer[:dataSize])

	offset := s.sendOffset
	s.sendOffset += uint64(dataSize)
	s.sendBuffer = s.sendBuffer[dataSize:]

	fin := s.sendFinished && len(s.sendBuffer) == 0

	return data, offset, fin, nil
}

// getOrderedData 获取按顺序的接收数据
func (s *Stream) getOrderedData() []byte {
	var data []byte

	s.recvBufferMutex.RLock()
	defer s.recvBufferMutex.RUnlock()

	// 获取所有偏移量并排序
	var offsets []uint64
	for offset := range s.recvBuffer {
		offsets = append(offsets, offset)
	}
	sort.Slice(offsets, func(i, j int) bool {
		return offsets[i] < offsets[j]
	})

	// 从当前接收偏移量开始按顺序组装数据
	currentOffset := s.recvOffset
	for _, offset := range offsets {
		if offset == currentOffset {
			streamData := s.recvBuffer[offset]
			data = append(data, streamData.Data...)
			currentOffset += uint64(len(streamData.Data))
		} else if offset > currentOffset {
			// 有缺失的数据，停止
			break
		}
	}

	return data
}

// consumeData 消费已读取的数据
func (s *Stream) consumeData(n int) {
	s.recvBufferMutex.Lock()
	defer s.recvBufferMutex.Unlock()

	consumed := uint64(n)
	s.recvOffset += consumed
	s.recvData += consumed

	// 清理已消费的数据片段
	var toDelete []uint64
	for offset, streamData := range s.recvBuffer {
		if offset+uint64(len(streamData.Data)) <= s.recvOffset {
			toDelete = append(toDelete, offset)
		}
	}

	for _, offset := range toDelete {
		delete(s.recvBuffer, offset)
	}
}

// canSend 检查流是否可以发送数据
func (s *Stream) canSend() bool {
	// 流ID的最低位和第二低位决定方向
	// 客户端发起: 偶数ID可发送
	// 服务端发起: 奇数ID可发送
	// 这里简化处理，假设都可以发送
	return true
}

// IsInitiatedByClient 检查流是否由客户端发起
func (s *Stream) IsInitiatedByClient() bool {
	// 流ID的最低位决定发起方
	// 0: 客户端发起, 1: 服务端发起
	return (s.id & 0x01) == 0
}

// WaitForCompletion 等待流完成
func (s *Stream) WaitForCompletion() {
	s.stateMutex.RLock()
	defer s.stateMutex.RUnlock()

	for s.state != StateClosed && s.state != StateReset {
		s.closeCond.Wait()
	}
}

// Stats 返回流的统计信息
type StreamStats struct {
	ID               uint64
	Type             StreamType
	State            StreamState
	SentData         uint64
	RecvData         uint64
	MaxData          uint64
	CreatedAt        time.Time
	BufferedSendData int
	BufferedRecvData int
}

// GetStats 获取流统计信息
func (s *Stream) GetStats() StreamStats {
	s.sendMutex.Lock()
	bufferedSendData := len(s.sendBuffer)
	s.sendMutex.Unlock()

	s.recvBufferMutex.RLock()
	bufferedRecvData := 0
	for _, data := range s.recvBuffer {
		bufferedRecvData += len(data.Data)
	}
	s.recvBufferMutex.RUnlock()

	return StreamStats{
		ID:               s.id,
		Type:             s.streamType,
		State:            s.State(),
		SentData:         s.sentData,
		RecvData:         s.recvData,
		MaxData:          s.maxData,
		CreatedAt:        s.createdAt,
		BufferedSendData: bufferedSendData,
		BufferedRecvData: bufferedRecvData,
	}
}

// String 返回流的字符串表示
func (s *Stream) String() string {
	return fmt.Sprintf("Stream[ID=%d, Type=%s, State=%s]",
		s.id, s.streamType, s.State())
}
