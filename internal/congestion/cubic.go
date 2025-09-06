package congestion

import (
	"math"
	"sync"
	"time"
)

// CongestionControl 表示拥塞控制接口
type CongestionControl interface {
	// OnPacketSent 数据包发送时调用
	OnPacketSent(sentTime time.Time, bytesInFlight uint64, packetNumber uint64, bytes uint64, isRetransmittable bool)

	// OnAck 收到ACK时调用
	OnAck(ackedPacketNumber uint64, ackedBytes uint64, priorInFlight uint64, eventTime time.Time) bool

	// OnPacketLost 数据包丢失时调用
	OnPacketLost(packetNumber uint64, lostBytes uint64, priorInFlight uint64)

	// CanSend 是否可以发送数据
	CanSend(bytesInFlight uint64) bool

	// GetCongestionWindow 获取拥塞窗口大小
	GetCongestionWindow() uint64

	// InSlowStart 是否处于慢启动阶段
	InSlowStart() bool

	// InRecovery 是否处于恢复阶段
	InRecovery() bool
}

// CubicState 表示CUBIC算法状态
type CubicState int

const (
	SlowStart CubicState = iota
	CongestionAvoidance
	FastRecovery
)

func (s CubicState) String() string {
	switch s {
	case SlowStart:
		return "SlowStart"
	case CongestionAvoidance:
		return "CongestionAvoidance"
	case FastRecovery:
		return "FastRecovery"
	default:
		return "Unknown"
	}
}

// CubicCongestionControl 实现CUBIC拥塞控制算法
type CubicCongestionControl struct {
	mutex sync.RWMutex

	// 基本参数
	maxDatagramSize uint64 // 最大数据包大小
	initialCwnd     uint64 // 初始拥塞窗口
	minCwnd         uint64 // 最小拥塞窗口
	maxCwnd         uint64 // 最大拥塞窗口

	// 当前状态
	state              CubicState
	congestionWindow   uint64 // 拥塞窗口
	slowStartThreshold uint64 // 慢启动阈值
	bytesInFlight      uint64 // 正在传输的字节数

	// CUBIC特定参数
	cubicC       float64   // CUBIC常数C
	betaCubic    float64   // CUBIC的β参数
	wMax         uint64    // 上次拥塞时的窗口大小
	epochStart   time.Time // 当前周期开始时间
	originPoint  uint64    // 原点（W_max * β）
	timeToOrigin float64   // 到达原点的时间
	lastMaxCwnd  uint64    // 上次最大拥塞窗口

	// 快速恢复
	endOfRecovery     uint64    // 恢复结束的包序号
	recoveryStartTime time.Time // 恢复开始时间

	// 统计信息
	packetsAcked   uint64
	packetsLost    uint64
	roundTripCount uint64
	minRtt         time.Duration
	smoothedRtt    time.Duration

	// RTT测量
	largestAcked               uint64
	largestSentAtLastCutback   uint64
	lastCutbackExitedSlowstart bool
}

// NewCubicCongestionControl 创建新的CUBIC拥塞控制
func NewCubicCongestionControl(maxDatagramSize uint64) *CubicCongestionControl {
	if maxDatagramSize == 0 {
		maxDatagramSize = 1200 // 默认MTU
	}

	initialCwnd := 10 * maxDatagramSize // RFC推荐初始窗口

	return &CubicCongestionControl{
		maxDatagramSize:    maxDatagramSize,
		initialCwnd:        initialCwnd,
		minCwnd:            2 * maxDatagramSize,
		maxCwnd:            1000 * maxDatagramSize, // 1MB
		state:              SlowStart,
		congestionWindow:   initialCwnd,
		slowStartThreshold: math.MaxUint64,
		cubicC:             0.4,       // CUBIC常数
		betaCubic:          0.7,       // β = 0.7
		minRtt:             time.Hour, // 初始化为很大的值
	}
}

// OnPacketSent 数据包发送时调用
func (c *CubicCongestionControl) OnPacketSent(sentTime time.Time, bytesInFlight uint64, packetNumber uint64, bytes uint64, isRetransmittable bool) {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	if isRetransmittable {
		c.bytesInFlight = bytesInFlight
	}
}

// OnAck 收到ACK时调用
func (c *CubicCongestionControl) OnAck(ackedPacketNumber uint64, ackedBytes uint64, priorInFlight uint64, eventTime time.Time) bool {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	c.packetsAcked++
	c.bytesInFlight = priorInFlight - ackedBytes

	if ackedPacketNumber > c.largestAcked {
		c.largestAcked = ackedPacketNumber
	}

	priorInRecovery := (c.state == FastRecovery)

	// 如果处于快速恢复且ACK的包序号大于恢复结束序号，退出恢复
	if priorInRecovery && ackedPacketNumber > c.endOfRecovery {
		c.state = CongestionAvoidance
		c.endOfRecovery = 0
	}

	// 如果不在恢复阶段，增加拥塞窗口
	inRecovery := (c.state == FastRecovery)
	if !inRecovery {
		c.maybeIncreaseCwndLocked(ackedBytes, priorInFlight, eventTime)
	}

	return priorInRecovery && !inRecovery
}

// OnPacketLost 数据包丢失时调用
func (c *CubicCongestionControl) OnPacketLost(packetNumber uint64, lostBytes uint64, priorInFlight uint64) {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	c.packetsLost++
	c.bytesInFlight = priorInFlight - lostBytes

	// 如果已经在恢复阶段，不需要重新进入
	if c.InRecovery() {
		return
	}

	// 进入快速恢复
	c.enterRecoveryLocked(packetNumber)

	// 减少拥塞窗口
	c.reduceCongestionWindow()
}

// CanSend 是否可以发送数据
func (c *CubicCongestionControl) CanSend(bytesInFlight uint64) bool {
	c.mutex.RLock()
	defer c.mutex.RUnlock()

	return bytesInFlight < c.congestionWindow
}

// GetCongestionWindow 获取拥塞窗口大小
func (c *CubicCongestionControl) GetCongestionWindow() uint64 {
	c.mutex.RLock()
	defer c.mutex.RUnlock()

	return c.congestionWindow
}

// InSlowStart 是否处于慢启动阶段
func (c *CubicCongestionControl) InSlowStart() bool {
	c.mutex.RLock()
	defer c.mutex.RUnlock()

	return c.state == SlowStart
}

// InRecovery 是否处于恢复阶段
func (c *CubicCongestionControl) InRecovery() bool {
	c.mutex.RLock()
	defer c.mutex.RUnlock()

	return c.state == FastRecovery
}

// maybeIncreaseCwndLocked 可能增加拥塞窗口（已持有锁）
func (c *CubicCongestionControl) maybeIncreaseCwndLocked(ackedBytes uint64, priorInFlight uint64, eventTime time.Time) {
	if !c.isCwndLimitedLocked(priorInFlight) {
		return
	}

	if c.state == SlowStart {
		// 慢启动：每个ACK增加一个MSS
		c.congestionWindow += ackedBytes

		// 检查是否应该退出慢启动
		if c.congestionWindow >= c.slowStartThreshold {
			c.state = CongestionAvoidance
			c.epochStart = time.Time{} // 重置epoch
		}
	} else {
		// 拥塞避免：使用CUBIC算法
		c.cubicCongestionAvoidance(eventTime)
	}

	// 确保拥塞窗口不超过最大值
	if c.congestionWindow > c.maxCwnd {
		c.congestionWindow = c.maxCwnd
	}
}

// cubicCongestionAvoidance CUBIC拥塞避免算法
func (c *CubicCongestionControl) cubicCongestionAvoidance(eventTime time.Time) {
	if c.epochStart.IsZero() {
		c.epochStart = eventTime
		c.computeNewWMax()

		if c.lastMaxCwnd <= c.congestionWindow {
			c.timeToOrigin = 0
			c.originPoint = c.congestionWindow
		} else {
			c.timeToOrigin = math.Cbrt(float64(c.lastMaxCwnd-c.congestionWindow) / c.cubicC)
			c.originPoint = c.lastMaxCwnd
		}
	}

	// 计算当前时间距离epoch开始的时间（秒）
	t := eventTime.Sub(c.epochStart).Seconds()

	// CUBIC函数: W(t) = C(t - K)³ + W_max
	// 其中K是到达W_max所需的时间
	target := c.cubicC*math.Pow(t-c.timeToOrigin, 3) + float64(c.originPoint)

	if target > float64(c.congestionWindow) {
		// 计算需要增加的窗口大小
		cwndIncrement := uint64(target) - c.congestionWindow

		// 平滑增长，每个RTT最多增加一个MSS
		if cwndIncrement > c.maxDatagramSize {
			cwndIncrement = c.maxDatagramSize
		}

		c.congestionWindow += cwndIncrement
	}
}

// enterRecoveryLocked 进入快速恢复（已持有锁）
func (c *CubicCongestionControl) enterRecoveryLocked(packetNumber uint64) {
	c.state = FastRecovery
	c.endOfRecovery = c.largestAcked
	c.recoveryStartTime = time.Now()
}

// reduceCongestionWindow 减少拥塞窗口
func (c *CubicCongestionControl) reduceCongestionWindow() {
	c.lastMaxCwnd = c.congestionWindow

	// 记录减少前的拥塞窗口为W_max
	c.wMax = c.congestionWindow

	// 按照CUBIC的β因子减少窗口
	c.congestionWindow = uint64(float64(c.congestionWindow) * c.betaCubic)

	// 确保不小于最小窗口
	if c.congestionWindow < c.minCwnd {
		c.congestionWindow = c.minCwnd
	}

	// 设置慢启动阈值
	c.slowStartThreshold = c.congestionWindow
}

// computeNewWMax 计算新的W_max
func (c *CubicCongestionControl) computeNewWMax() {
	// 如果当前拥塞窗口小于上次的W_max，使用快速收敛
	if c.congestionWindow < c.lastMaxCwnd {
		c.lastMaxCwnd = uint64(float64(c.congestionWindow) * (2.0 - c.betaCubic) / 2.0)
	} else {
		c.lastMaxCwnd = c.congestionWindow
	}
}

// isCwndLimitedLocked 检查是否受拥塞窗口限制（已持有锁）
func (c *CubicCongestionControl) isCwndLimitedLocked(priorInFlight uint64) bool {
	congestionWindow := c.congestionWindow
	if c.state == SlowStart {
		// 慢启动时，如果正在传输的数据超过拥塞窗口的一半，认为受限制
		return priorInFlight >= congestionWindow/2
	}

	// 拥塞避免时，如果正在传输的数据接近拥塞窗口，认为受限制
	return priorInFlight >= congestionWindow-c.maxDatagramSize
}

// UpdateRtt 更新RTT测量
func (c *CubicCongestionControl) UpdateRtt(rtt time.Duration) {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	if rtt < c.minRtt {
		c.minRtt = rtt
	}

	if c.smoothedRtt == 0 {
		c.smoothedRtt = rtt
	} else {
		// EWMA平滑
		c.smoothedRtt = (7*c.smoothedRtt + rtt) / 8
	}
}

// GetStats 获取拥塞控制统计信息
type CongestionStats struct {
	State              CubicState
	CongestionWindow   uint64
	SlowStartThreshold uint64
	BytesInFlight      uint64
	PacketsAcked       uint64
	PacketsLost        uint64
	MinRtt             time.Duration
	SmoothedRtt        time.Duration
	LastMaxCwnd        uint64
}

func (c *CubicCongestionControl) GetStats() CongestionStats {
	c.mutex.RLock()
	defer c.mutex.RUnlock()

	return CongestionStats{
		State:              c.state,
		CongestionWindow:   c.congestionWindow,
		SlowStartThreshold: c.slowStartThreshold,
		BytesInFlight:      c.bytesInFlight,
		PacketsAcked:       c.packetsAcked,
		PacketsLost:        c.packetsLost,
		MinRtt:             c.minRtt,
		SmoothedRtt:        c.smoothedRtt,
		LastMaxCwnd:        c.lastMaxCwnd,
	}
}
