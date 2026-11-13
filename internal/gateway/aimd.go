package gateway

import (
	"context"
	"net/http"
	"sync"
)

// aimd bounds the calls in flight to one endpoint origin. The limit starts
// at 1, grows by one after each success up to max, and halves (never below
// 1) when the endpoint answers 429 or 5xx, so creep backs off an overloaded
// or rate-limiting endpoint instead of hammering it.
type aimd struct {
	mu       sync.Mutex
	limit    int
	max      int
	inFlight int
	wake     chan struct{} // closed and replaced on every release
}

func newAIMD(maxLimit int) *aimd {
	return &aimd{limit: 1, max: maxLimit, wake: make(chan struct{})}
}

// acquire waits until fewer than limit calls are in flight, or ctx ends.
func (a *aimd) acquire(ctx context.Context) error {
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		a.mu.Lock()
		if a.inFlight < a.limit {
			a.inFlight++
			a.mu.Unlock()
			return nil
		}
		wake := a.wake
		a.mu.Unlock()
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-wake:
		}
	}
}

// release frees a slot, adjusts the limit for status (0: no signal) and
// wakes every waiter to recheck.
func (a *aimd) release(status int) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.inFlight--
	a.limit = nextLimit(a.limit, a.max, status)
	close(a.wake)
	a.wake = make(chan struct{})
}

// nextLimit is the AIMD rule: halve on 429 or 5xx, add one on 2xx, keep the
// limit on anything else, always within [1, maxLimit].
func nextLimit(limit, maxLimit, status int) int {
	switch {
	case status == http.StatusTooManyRequests || status >= 500:
		limit /= 2
	case status >= 200 && status < 300:
		limit++
	}
	return min(max(limit, 1), maxLimit)
}

// congestionSignal is the status release adjusts for. A 2xx whose body could
// not be used is no success; an overload status counts even when reading
// its body failed.
func congestionSignal(status int, sendErr error) int {
	if sendErr != nil && status != http.StatusTooManyRequests && status < 500 {
		return 0
	}
	return status
}
