package packet

import (
	"fmt"
)

// FrameType 定义QUIC帧类型
type FrameType uint64

const (
	FrameTypePadding            FrameType = 0x00
	FrameTypePing               FrameType = 0x01
	FrameTypeAck                FrameType = 0x02
	FrameTypeAckECN             FrameType = 0x03
	FrameTypeResetStream        FrameType = 0x04
	FrameTypeStopSending        FrameType = 0x05
	FrameTypeCrypto             FrameType = 0x06
	FrameTypeNewToken           FrameType = 0x07
	FrameTypeStream             FrameType = 0x08 // 0x08-0x0f
	FrameTypeMaxData            FrameType = 0x10
	FrameTypeMaxStreamData      FrameType = 0x11
	FrameTypeMaxStreams         FrameType = 0x12
	FrameTypeDataBlocked        FrameType = 0x14
	FrameTypeStreamDataBlocked  FrameType = 0x15
	FrameTypeStreamsBlocked     FrameType = 0x16
	FrameTypeNewConnectionID    FrameType = 0x18
	FrameTypeRetireConnectionID FrameType = 0x19
	FrameTypePathChallenge      FrameType = 0x1a
	FrameTypePathResponse       FrameType = 0x1b
	FrameTypeConnectionClose    FrameType = 0x1c
	FrameTypeConnectionCloseApp FrameType = 0x1d
	FrameTypeHandshakeDone      FrameType = 0x1e
)

// Frame 表示QUIC帧的接口
type Frame interface {
	Type() FrameType
	Serialize(buf []byte) (int, error)
	Length() int
}

// AckRange 表示ACK帧中的确认范围
type AckRange struct {
	Gap    uint64
	Length uint64
}

// AckFrame 表示ACK帧
type AckFrame struct {
	LargestAcked uint64
	AckDelay     uint64
	AckRanges    []AckRange
	ECTCount     [3]uint64 // ECN计数器（仅ACK_ECN帧）
}

func (f *AckFrame) Type() FrameType {
	if len(f.ECTCount) > 0 && (f.ECTCount[0] > 0 || f.ECTCount[1] > 0 || f.ECTCount[2] > 0) {
		return FrameTypeAckECN
	}
	return FrameTypeAck
}

func (f *AckFrame) Length() int {
	length := 1 // 帧类型
	length += varintLen(f.LargestAcked)
	length += varintLen(f.AckDelay)
	length += varintLen(uint64(len(f.AckRanges)))

	for _, r := range f.AckRanges {
		length += varintLen(r.Gap)
		length += varintLen(r.Length)
	}

	if f.Type() == FrameTypeAckECN {
		for i := 0; i < 3; i++ {
			length += varintLen(f.ECTCount[i])
		}
	}

	return length
}

func (f *AckFrame) Serialize(buf []byte) (int, error) {
	offset := 0

	// 帧类型
	n, err := putVarint(buf[offset:], uint64(f.Type()))
	if err != nil {
		return 0, err
	}
	offset += n

	// 最大确认包序号
	n, err = putVarint(buf[offset:], f.LargestAcked)
	if err != nil {
		return 0, err
	}
	offset += n

	// ACK延迟
	n, err = putVarint(buf[offset:], f.AckDelay)
	if err != nil {
		return 0, err
	}
	offset += n

	// ACK范围计数
	n, err = putVarint(buf[offset:], uint64(len(f.AckRanges)))
	if err != nil {
		return 0, err
	}
	offset += n

	// ACK范围
	for _, r := range f.AckRanges {
		n, err = putVarint(buf[offset:], r.Gap)
		if err != nil {
			return 0, err
		}
		offset += n

		n, err = putVarint(buf[offset:], r.Length)
		if err != nil {
			return 0, err
		}
		offset += n
	}

	// ECN计数器（仅ACK_ECN帧）
	if f.Type() == FrameTypeAckECN {
		for i := 0; i < 3; i++ {
			n, err = putVarint(buf[offset:], f.ECTCount[i])
			if err != nil {
				return 0, err
			}
			offset += n
		}
	}

	return offset, nil
}

// StreamFrame 表示STREAM帧
type StreamFrame struct {
	StreamID uint64
	Offset   uint64
	Data     []byte
	Fin      bool
}

func (f *StreamFrame) Type() FrameType {
	frameType := uint64(FrameTypeStream)

	// 设置标志位
	if f.Fin {
		frameType |= 0x01
	}
	if len(f.Data) > 0 {
		frameType |= 0x02 // LEN位
	}
	if f.Offset > 0 {
		frameType |= 0x04 // OFF位
	}

	return FrameType(frameType)
}

func (f *StreamFrame) Length() int {
	length := 1 // 帧类型
	length += varintLen(f.StreamID)

	if f.Offset > 0 {
		length += varintLen(f.Offset)
	}

	if len(f.Data) > 0 {
		length += varintLen(uint64(len(f.Data)))
	}

	length += len(f.Data)
	return length
}

func (f *StreamFrame) Serialize(buf []byte) (int, error) {
	offset := 0

	// 帧类型
	n, err := putVarint(buf[offset:], uint64(f.Type()))
	if err != nil {
		return 0, err
	}
	offset += n

	// 流ID
	n, err = putVarint(buf[offset:], f.StreamID)
	if err != nil {
		return 0, err
	}
	offset += n

	// 偏移量（如果OFF位设置）
	if f.Offset > 0 {
		n, err = putVarint(buf[offset:], f.Offset)
		if err != nil {
			return 0, err
		}
		offset += n
	}

	// 长度（如果LEN位设置）
	if len(f.Data) > 0 {
		n, err = putVarint(buf[offset:], uint64(len(f.Data)))
		if err != nil {
			return 0, err
		}
		offset += n
	}

	// 数据
	copy(buf[offset:], f.Data)
	offset += len(f.Data)

	return offset, nil
}

// CryptoFrame 表示CRYPTO帧
type CryptoFrame struct {
	Offset uint64
	Data   []byte
}

func (f *CryptoFrame) Type() FrameType {
	return FrameTypeCrypto
}

func (f *CryptoFrame) Length() int {
	length := 1 // 帧类型
	length += varintLen(f.Offset)
	length += varintLen(uint64(len(f.Data)))
	length += len(f.Data)
	return length
}

func (f *CryptoFrame) Serialize(buf []byte) (int, error) {
	offset := 0

	// 帧类型
	n, err := putVarint(buf[offset:], uint64(f.Type()))
	if err != nil {
		return 0, err
	}
	offset += n

	// 偏移量
	n, err = putVarint(buf[offset:], f.Offset)
	if err != nil {
		return 0, err
	}
	offset += n

	// 长度
	n, err = putVarint(buf[offset:], uint64(len(f.Data)))
	if err != nil {
		return 0, err
	}
	offset += n

	// 数据
	copy(buf[offset:], f.Data)
	offset += len(f.Data)

	return offset, nil
}

// ConnectionCloseFrame 表示CONNECTION_CLOSE帧
type ConnectionCloseFrame struct {
	ErrorCode    uint64
	FrameType    uint64
	ReasonPhrase []byte
	IsAppError   bool
}

func (f *ConnectionCloseFrame) Type() FrameType {
	if f.IsAppError {
		return FrameTypeConnectionCloseApp
	}
	return FrameTypeConnectionClose
}

func (f *ConnectionCloseFrame) Length() int {
	length := 1 // 帧类型
	length += varintLen(f.ErrorCode)

	if !f.IsAppError {
		length += varintLen(f.FrameType)
	}

	length += varintLen(uint64(len(f.ReasonPhrase)))
	length += len(f.ReasonPhrase)
	return length
}

func (f *ConnectionCloseFrame) Serialize(buf []byte) (int, error) {
	offset := 0

	// 帧类型
	n, err := putVarint(buf[offset:], uint64(f.Type()))
	if err != nil {
		return 0, err
	}
	offset += n

	// 错误码
	n, err = putVarint(buf[offset:], f.ErrorCode)
	if err != nil {
		return 0, err
	}
	offset += n

	// 触发帧类型（仅传输错误）
	if !f.IsAppError {
		n, err = putVarint(buf[offset:], f.FrameType)
		if err != nil {
			return 0, err
		}
		offset += n
	}

	// 原因短语长度
	n, err = putVarint(buf[offset:], uint64(len(f.ReasonPhrase)))
	if err != nil {
		return 0, err
	}
	offset += n

	// 原因短语
	copy(buf[offset:], f.ReasonPhrase)
	offset += len(f.ReasonPhrase)

	return offset, nil
}

// PingFrame 表示PING帧
type PingFrame struct{}

func (f *PingFrame) Type() FrameType {
	return FrameTypePing
}

func (f *PingFrame) Length() int {
	return 1 // 只有帧类型
}

func (f *PingFrame) Serialize(buf []byte) (int, error) {
	n, err := putVarint(buf, uint64(f.Type()))
	return n, err
}

// PaddingFrame 表示PADDING帧
type PaddingFrame struct {
	PaddingLength int
}

func (f *PaddingFrame) Type() FrameType {
	return FrameTypePadding
}

func (f *PaddingFrame) Length() int {
	return f.PaddingLength
}

func (f *PaddingFrame) Serialize(buf []byte) (int, error) {
	for i := 0; i < f.PaddingLength && i < len(buf); i++ {
		buf[i] = 0x00
	}
	return f.PaddingLength, nil
}

// ParseFrame 解析QUIC帧
func ParseFrame(data []byte) (Frame, int, error) {
	if len(data) == 0 {
		return nil, 0, fmt.Errorf("空帧数据")
	}

	frameType, n, err := parseVarint(data)
	if err != nil {
		return nil, 0, fmt.Errorf("解析帧类型失败: %v", err)
	}

	switch FrameType(frameType) {
	case FrameTypePadding:
		return parsePaddingFrame(data, n)
	case FrameTypePing:
		return &PingFrame{}, n, nil
	case FrameTypeAck, FrameTypeAckECN:
		return parseAckFrame(data, n, FrameType(frameType))
	case FrameTypeCrypto:
		return parseCryptoFrame(data, n)
	case FrameTypeConnectionClose, FrameTypeConnectionCloseApp:
		return parseConnectionCloseFrame(data, n, FrameType(frameType))
	default:
		if (frameType & 0xF8) == 0x08 {
			// STREAM帧 (0x08-0x0f)
			return parseStreamFrame(data, n, FrameType(frameType))
		}
		return nil, 0, fmt.Errorf("不支持的帧类型: %d", frameType)
	}
}

// parsePaddingFrame 解析PADDING帧
func parsePaddingFrame(data []byte, offset int) (Frame, int, error) {
	// 计算连续的0x00字节数量
	length := 1 // 至少包含帧类型字节
	for i := offset; i < len(data) && data[i] == 0x00; i++ {
		length++
	}
	return &PaddingFrame{PaddingLength: length}, length, nil
}

// parseAckFrame 解析ACK帧
func parseAckFrame(data []byte, offset int, frameType FrameType) (Frame, int, error) {
	originalOffset := offset

	// 最大确认包序号
	largestAcked, n, err := parseVarint(data[offset:])
	if err != nil {
		return nil, 0, err
	}
	offset += n

	// ACK延迟
	ackDelay, n, err := parseVarint(data[offset:])
	if err != nil {
		return nil, 0, err
	}
	offset += n

	// ACK范围计数
	rangeCount, n, err := parseVarint(data[offset:])
	if err != nil {
		return nil, 0, err
	}
	offset += n

	// 解析ACK范围
	ackRanges := make([]AckRange, rangeCount)
	for i := uint64(0); i < rangeCount; i++ {
		gap, n, err := parseVarint(data[offset:])
		if err != nil {
			return nil, 0, err
		}
		offset += n

		length, n, err := parseVarint(data[offset:])
		if err != nil {
			return nil, 0, err
		}
		offset += n

		ackRanges[i] = AckRange{Gap: gap, Length: length}
	}

	frame := &AckFrame{
		LargestAcked: largestAcked,
		AckDelay:     ackDelay,
		AckRanges:    ackRanges,
	}

	// ECN计数器（仅ACK_ECN帧）
	if frameType == FrameTypeAckECN {
		for i := 0; i < 3; i++ {
			count, n, err := parseVarint(data[offset:])
			if err != nil {
				return nil, 0, err
			}
			offset += n
			frame.ECTCount[i] = count
		}
	}

	return frame, offset - originalOffset, nil
}

// parseStreamFrame 解析STREAM帧
func parseStreamFrame(data []byte, offset int, frameType FrameType) (Frame, int, error) {
	originalOffset := offset

	// 流ID
	streamID, n, err := parseVarint(data[offset:])
	if err != nil {
		return nil, 0, err
	}
	offset += n

	frame := &StreamFrame{
		StreamID: streamID,
		Fin:      (uint64(frameType) & 0x01) != 0,
	}

	// 偏移量（如果OFF位设置）
	if (uint64(frameType) & 0x04) != 0 {
		streamOffset, n, err := parseVarint(data[offset:])
		if err != nil {
			return nil, 0, err
		}
		offset += n
		frame.Offset = streamOffset
	}

	// 长度（如果LEN位设置）
	var dataLen uint64
	if (uint64(frameType) & 0x02) != 0 {
		dataLen, n, err = parseVarint(data[offset:])
		if err != nil {
			return nil, 0, err
		}
		offset += n
	} else {
		// 如果没有长度字段，数据延伸到包的末尾
		dataLen = uint64(len(data) - offset)
	}

	// 数据
	if offset+int(dataLen) > len(data) {
		return nil, 0, fmt.Errorf("STREAM帧数据超出边界")
	}
	frame.Data = make([]byte, dataLen)
	copy(frame.Data, data[offset:offset+int(dataLen)])
	offset += int(dataLen)

	return frame, offset - originalOffset, nil
}

// parseCryptoFrame 解析CRYPTO帧
func parseCryptoFrame(data []byte, offset int) (Frame, int, error) {
	originalOffset := offset

	// 偏移量
	cryptoOffset, n, err := parseVarint(data[offset:])
	if err != nil {
		return nil, 0, err
	}
	offset += n

	// 长度
	length, n, err := parseVarint(data[offset:])
	if err != nil {
		return nil, 0, err
	}
	offset += n

	// 数据
	if offset+int(length) > len(data) {
		return nil, 0, fmt.Errorf("CRYPTO帧数据超出边界")
	}

	frame := &CryptoFrame{
		Offset: cryptoOffset,
		Data:   make([]byte, length),
	}
	copy(frame.Data, data[offset:offset+int(length)])
	offset += int(length)

	return frame, offset - originalOffset, nil
}

// parseConnectionCloseFrame 解析CONNECTION_CLOSE帧
func parseConnectionCloseFrame(data []byte, offset int, frameType FrameType) (Frame, int, error) {
	originalOffset := offset

	// 错误码
	errorCode, n, err := parseVarint(data[offset:])
	if err != nil {
		return nil, 0, err
	}
	offset += n

	frame := &ConnectionCloseFrame{
		ErrorCode:  errorCode,
		IsAppError: frameType == FrameTypeConnectionCloseApp,
	}

	// 触发帧类型（仅传输错误）
	if !frame.IsAppError {
		triggerFrameType, n, err := parseVarint(data[offset:])
		if err != nil {
			return nil, 0, err
		}
		offset += n
		frame.FrameType = triggerFrameType
	}

	// 原因短语长度
	reasonLen, n, err := parseVarint(data[offset:])
	if err != nil {
		return nil, 0, err
	}
	offset += n

	// 原因短语
	if offset+int(reasonLen) > len(data) {
		return nil, 0, fmt.Errorf("原因短语超出边界")
	}
	frame.ReasonPhrase = make([]byte, reasonLen)
	copy(frame.ReasonPhrase, data[offset:offset+int(reasonLen)])
	offset += int(reasonLen)

	return frame, offset - originalOffset, nil
}

// varintLen 计算变长整数所需的字节数
func varintLen(value uint64) int {
	if value <= 0x3F {
		return 1
	} else if value <= 0x3FFF {
		return 2
	} else if value <= 0x3FFFFFFF {
		return 4
	}
	return 8
}
