package congestion

import (
	"testing"
	"time"

	"github.com/quic-go/quic/internal/congestion"
)

func TestNewCubicCongestionControl(t *testing.T) {
	maxDatagramSize := uint64(1200)
	cc := NewCubicCongestionControl(maxDatagramSize)

	if cc.maxDatagramSize != maxDatagramSize {
		t.Errorf("期望最大数据包大小 %d，但得到 %d", maxDatagramSize, cc.maxDatagramSize)
	}

	if !cc.InSlowStart() {
		t.Error("新连接应该处于慢启动状态")
	}

	if cc.InRecovery() {
		t.Error("新连接不应该处于恢复状态")
	}

	// 检查初始拥塞窗口
	expectedInitialCwnd := 10 * maxDatagramSize
	if cc.GetCongestionWindow() != expectedInitialCwnd {
		t.Errorf("期望初始拥塞窗口 %d，但得到 %d",
			expectedInitialCwnd, cc.GetCongestionWindow())
	}
}

func TestSlowStart(t *testing.T) {
	cc := NewCubicCongestionControl(1200)
	initialCwnd := cc.GetCongestionWindow()

	// 模拟发送数据包
	now := time.Now()
	cc.OnPacketSent(now, 1200, 1, 1200, true)

	// 模拟收到ACK
	ackTime := now.Add(50 * time.Millisecond)
	cc.OnAck(1, 1200, 1200, ackTime)

	// 慢启动阶段，拥塞窗口应该增加
	newCwnd := cc.GetCongestionWindow()
	if newCwnd <= initialCwnd {
		t.Errorf("慢启动阶段拥塞窗口应该增加，初始: %d，当前: %d",
			initialCwnd, newCwnd)
	}

	if !cc.InSlowStart() {
		t.Error("应该仍然处于慢启动状态")
	}
}

func TestPacketLoss(t *testing.T) {
	cc := NewCubicCongestionControl(1200)
	initialCwnd := cc.GetCongestionWindow()

	// 模拟数据包丢失
	cc.OnPacketLost(1, 1200, 1200)

	// 应该进入恢复状态
	if !cc.InRecovery() {
		t.Error("丢包后应该进入恢复状态")
	}

	// 拥塞窗口应该减小
	newCwnd := cc.GetCongestionWindow()
	if newCwnd >= initialCwnd {
		t.Errorf("丢包后拥塞窗口应该减小，初始: %d，当前: %d",
			initialCwnd, newCwnd)
	}

	// 不再处于慢启动
	if cc.InSlowStart() {
		t.Error("丢包后不应该处于慢启动状态")
	}
}

func TestCongestionAvoidance(t *testing.T) {
	cc := NewCubicCongestionControl(1200)

	// 强制退出慢启动
	cc.slowStartThreshold = cc.congestionWindow / 2
	cc.mutex.Lock()
	cc.state = CongestionAvoidance
	cc.epochStart = time.Time{}
	cc.mutex.Unlock()

	if cc.InSlowStart() {
		t.Error("应该已退出慢启动状态")
	}

	initialCwnd := cc.GetCongestionWindow()

	// 模拟多次ACK（拥塞避免阶段增长较慢）
	now := time.Now()
	for i := 0; i < 10; i++ {
		packetNum := uint64(i + 1)
		cc.OnPacketSent(now, 1200*packetNum, packetNum, 1200, true)

		ackTime := now.Add(time.Duration(i+1) * 10 * time.Millisecond)
		cc.OnAck(packetNum, 1200, 1200*packetNum, ackTime)
	}

	newCwnd := cc.GetCongestionWindow()

	// 拥塞避免阶段增长应该比慢启动慢
	// 但仍应有所增长
	if newCwnd <= initialCwnd {
		t.Errorf("拥塞避免阶段窗口应该有所增长，初始: %d，当前: %d",
			initialCwnd, newCwnd)
	}
}

func TestRecoveryExit(t *testing.T) {
	cc := NewCubicCongestionControl(1200)

	// 进入恢复状态
	cc.OnPacketLost(1, 1200, 1200)

	if !cc.InRecovery() {
		t.Error("应该处于恢复状态")
	}

	// 设置恢复结束序号
	cc.endOfRecovery = 5

	// ACK大于恢复结束序号的包
	now := time.Now()
	exitRecovery := cc.OnAck(6, 1200, 1200, now)

	if !exitRecovery {
		t.Error("应该退出恢复状态")
	}

	if cc.InRecovery() {
		t.Error("不应该再处于恢复状态")
	}
}

func TestCanSend(t *testing.T) {
	cc := NewCubicCongestionControl(1200)
	cwnd := cc.GetCongestionWindow()

	// 正在传输的数据小于拥塞窗口，应该可以发送
	if !cc.CanSend(cwnd / 2) {
		t.Error("应该可以发送数据")
	}

	// 正在传输的数据等于拥塞窗口，不应该发送
	if cc.CanSend(cwnd) {
		t.Error("不应该发送数据")
	}

	// 正在传输的数据超过拥塞窗口，不应该发送
	if cc.CanSend(cwnd + 1) {
		t.Error("不应该发送数据")
	}
}

func TestUpdateRTT(t *testing.T) {
	cc := NewCubicCongestionControl(1200)

	// 更新RTT
	rtt1 := 100 * time.Millisecond
	cc.UpdateRtt(rtt1)

	stats := cc.GetStats()
	if stats.MinRtt != rtt1 {
		t.Errorf("期望最小RTT %v，但得到 %v", rtt1, stats.MinRtt)
	}

	if stats.SmoothedRtt != rtt1 {
		t.Errorf("期望平滑RTT %v，但得到 %v", rtt1, stats.SmoothedRtt)
	}

	// 更新更小的RTT
	rtt2 := 50 * time.Millisecond
	cc.UpdateRtt(rtt2)

	stats = cc.GetStats()
	if stats.MinRtt != rtt2 {
		t.Errorf("最小RTT应该更新为 %v，但得到 %v", rtt2, stats.MinRtt)
	}

	// 平滑RTT应该在两个值之间
	if stats.SmoothedRtt >= rtt1 || stats.SmoothedRtt <= rtt2 {
		t.Errorf("平滑RTT应该在 %v 和 %v 之间，但得到 %v",
			rtt2, rtt1, stats.SmoothedRtt)
	}
}

func TestCongestionStats(t *testing.T) {
	cc := NewCubicCongestionControl(1200)

	// 初始统计
	stats := cc.GetStats()
	if stats.State != SlowStart {
		t.Errorf("期望状态 %v，但得到 %v", SlowStart, stats.State)
	}

	if stats.PacketsAcked != 0 {
		t.Errorf("期望确认包数 0，但得到 %d", stats.PacketsAcked)
	}

	if stats.PacketsLost != 0 {
		t.Errorf("期望丢包数 0，但得到 %d", stats.PacketsLost)
	}

	// 模拟一些活动
	now := time.Now()
	cc.OnPacketSent(now, 1200, 1, 1200, true)
	cc.OnAck(1, 1200, 1200, now.Add(50*time.Millisecond))
	cc.OnPacketLost(2, 1200, 2400)

	// 检查更新的统计
	stats = cc.GetStats()
	if stats.PacketsAcked != 1 {
		t.Errorf("期望确认包数 1，但得到 %d", stats.PacketsAcked)
	}

	if stats.PacketsLost != 1 {
		t.Errorf("期望丢包数 1，但得到 %d", stats.PacketsLost)
	}

	if stats.State != FastRecovery {
		t.Errorf("丢包后期望状态 %v，但得到 %v", FastRecovery, stats.State)
	}
}

func TestCubicBetaReduction(t *testing.T) {
	cc := NewCubicCongestionControl(1200)
	initialCwnd := cc.GetCongestionWindow()

	// 触发拥塞窗口减小
	cc.OnPacketLost(1, 1200, 1200)

	newCwnd := cc.GetCongestionWindow()
	expectedCwnd := uint64(float64(initialCwnd) * cc.betaCubic)

	if newCwnd != expectedCwnd {
		t.Errorf("期望拥塞窗口减小到 %d，但得到 %d", expectedCwnd, newCwnd)
	}
}
