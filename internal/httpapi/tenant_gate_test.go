package httpapi

import (
	"context"
	"sync"
	"testing"
)

// 只读闸门的进程内缓存必须能被并发安全地首次初始化。
//
// 曾经的写法在 RLock 之外做了 `if a.gate.m == nil { a.gate.m = make(...) }`，
// 两个请求同时到达就是一次对 map 字段的数据竞争；它不会崩，只会让缓存
// 偶尔被替换掉（等于闸门失效一小会儿）。这类问题只有 -race + 并发才会暴露，
// 所以这里刻意用空 API（Tenants/Metering 为 nil，不触库）打满并发。
func TestTenantGateConcurrentInit(t *testing.T) {
	a := &API{}

	const workers = 64
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			for j := 0; j < 20; j++ {
				if blocked, _ := a.tenantWriteBlocked(context.Background(), "tenant-a"); blocked {
					t.Errorf("未配置租户服务时不应判定为只读")
					return
				}
				a.invalidateGate("tenant-a")
			}
		}()
	}
	close(start)
	wg.Wait()
}

// 只读闸门的语义：判定失败一律放行（可用性优先），
// 且"放行"这个结论同样要能被缓存命中，否则每个写请求都打两次库。
func TestTenantGateCachesDecision(t *testing.T) {
	a := &API{}
	if blocked, _ := a.tenantWriteBlocked(context.Background(), "tenant-b"); blocked {
		t.Fatal("首次判定应为放行")
	}
	a.gate.mu.RLock()
	_, cached := a.gate.m["tenant-b"]
	a.gate.mu.RUnlock()
	if !cached {
		t.Fatal("判定结果应写入缓存")
	}
	a.invalidateGate("tenant-b")
	a.gate.mu.RLock()
	_, stillCached := a.gate.m["tenant-b"]
	a.gate.mu.RUnlock()
	if stillCached {
		t.Fatal("invalidateGate 应清除缓存")
	}
}
