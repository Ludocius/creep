package gateway

import (
	"context"
	"errors"
	"net/http"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
)

func TestNextLimit(t *testing.T) {
	tests := []struct {
		name               string
		limit, max, status int
		want               int
	}{
		{"success adds one", 2, 4, http.StatusOK, 3},
		{"success stops at max", 4, 4, http.StatusOK, 4},
		{"429 halves", 4, 4, http.StatusTooManyRequests, 2},
		{"503 halves", 3, 4, http.StatusServiceUnavailable, 1},
		{"500 halves", 4, 8, http.StatusInternalServerError, 2},
		{"halving stops at one", 1, 4, http.StatusTooManyRequests, 1},
		{"client error keeps", 3, 4, http.StatusBadRequest, 3},
		{"no signal keeps", 3, 4, 0, 3},
	}
	for _, tt := range tests {
		if got := nextLimit(tt.limit, tt.max, tt.status); got != tt.want {
			t.Errorf("%s: nextLimit(%d, %d, %d) = %d, want %d", tt.name, tt.limit, tt.max, tt.status, got, tt.want)
		}
	}
}

func TestCongestionSignal(t *testing.T) {
	tests := []struct {
		status int
		err    error
		want   int
	}{
		{http.StatusOK, nil, http.StatusOK},
		{http.StatusOK, ErrResponseTooLarge, 0},
		{http.StatusTooManyRequests, nil, http.StatusTooManyRequests},
		{http.StatusBadGateway, errors.New("read body"), http.StatusBadGateway},
		{0, errors.New("dial"), 0},
	}
	for _, tt := range tests {
		if got := congestionSignal(tt.status, tt.err); got != tt.want {
			t.Errorf("congestionSignal(%d, %v) = %d, want %d", tt.status, tt.err, got, tt.want)
		}
	}
}

// Acceptance (#84): through Send, the endpoint's concurrency limit halves on
// 429 and 5xx and grows back by one on each success, within [1, max].
func TestSendAdjustsConcurrency(t *testing.T) {
	steps := []struct {
		status, want int
	}{
		{200, 2}, {200, 3}, {200, 4}, {200, 4},
		{429, 2}, {200, 3}, {503, 1}, {429, 1}, {400, 1}, {200, 2},
	}
	m := newModelServer(t, `{}`)
	b := newBudget(t, BudgetOptions{MaxTokens: 1 << 20, MaxCalls: 100, MaxConcurrency: 4})
	l := openBudgetLog(t, runDir(t), b)
	slot := b.limiter("http://127.0.0.1:" + m.port)
	for i, s := range steps {
		reply, err := l.Send(context.Background(), m.client(t), testCall(m.url("/status/"+strconv.Itoa(s.status))))
		if err != nil || reply.Status != s.status {
			t.Fatalf("step %d: Send = %+v, %v; want status %d", i, reply, err, s.status)
		}
		slot.mu.Lock()
		got := slot.limit
		slot.mu.Unlock()
		if got != s.want {
			t.Fatalf("step %d: after %d limit = %d, want %d", i, s.status, got, s.want)
		}
	}
}

// Many goroutines sharing one limiter never exceed its ceiling in flight.
func TestAIMDBoundsInFlight(t *testing.T) {
	const maxLimit, workers = 3, 32
	a := newAIMD(maxLimit)
	var inFlight, peak atomic.Int32
	var wg sync.WaitGroup
	for range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := a.acquire(context.Background()); err != nil {
				t.Error(err)
				return
			}
			n := inFlight.Add(1)
			for p := peak.Load(); n > p && !peak.CompareAndSwap(p, n); p = peak.Load() {
			}
			inFlight.Add(-1)
			a.release(http.StatusOK)
		}()
	}
	wg.Wait()
	if p := peak.Load(); p > maxLimit || p < 1 {
		t.Fatalf("peak in flight %d, want 1..%d", p, maxLimit)
	}
}

// A waiter blocked on a full limiter proceeds once a slot is released.
func TestAIMDWakesWaiter(t *testing.T) {
	a := newAIMD(1)
	if err := a.acquire(context.Background()); err != nil {
		t.Fatal(err)
	}
	done := make(chan error)
	go func() { done <- a.acquire(context.Background()) }()
	a.release(http.StatusOK)
	if err := <-done; err != nil {
		t.Fatalf("waiter: %v", err)
	}
}
