package packet

// ParseVarint 解析QUIC变长整数（导出版本）
func ParseVarint(data []byte) (uint64, int, error) {
	return parseVarint(data)
}

// PutVarint 编码QUIC变长整数（导出版本）
func PutVarint(buf []byte, value uint64) (int, error) {
	return putVarint(buf, value)
}

// GetPacketNumberLength 获取包序号需要的字节数（导出版本）
func GetPacketNumberLength(pn PacketNumber) int {
	return getPacketNumberLength(pn)
}

// VarintLen 计算变长整数所需的字节数（导出版本）
func VarintLen(value uint64) int {
	return varintLen(value)
}
