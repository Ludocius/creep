package gateway

import (
	"context"
	"errors"
	"math"
	"sync/atomic"
	"testing"
)

const testOrigin = "https://api.example.com:443"

func (b *Budget) counters(key string) (tokens, calls, endpoint int64) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.tokens, b.calls, b.endpoint[key]
}

func (a *aimd) state() (limit, inFlight int) {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.limit, a.inFlight
}

// Reported usage replaces the reservation in both the run and the endpoint
// counters; a missing or negative report keeps the reservation.
func TestSettle(t *testing.T) {
	tests := []struct {
		name string
		used *Usage
		want int64
	}{
		{"reported", &Usage{InputTokens: 7, OutputTokens: 3}, 10},
		{"none", nil, 100},
		{"negative input", &Usage{InputTokens: -50, OutputTokens: 1}, 100},
		{"negative output", &Usage{InputTokens: 1, OutputTokens: -50}, 100},
	}
	for _, tt := range tests {
		b := newBudget(t, BudgetOptions{MaxTokens: 1000, MaxCalls: 9, EndpointMaxTokens: 150})
		if err := b.reserve(testOrigin, 100); err != nil {
			t.Fatal(err)
		}
		b.settle(testOrigin, 100, tt.used)
		if tokens, _, endpoint := b.counters(testOrigin); tokens != tt.want || endpoint != tt.want {
			t.Errorf("%s: run %d, endpoint %d tokens; want %d", tt.name, tokens, endpoint, tt.want)
		}
	}
}

// With every call of a run in flight and each reporting the largest usage,
// the counters neither wrap nor admit another call.
func TestHugeUsageCannotOverflow(t *testing.T) {
	const inFlight = 13
	b := newBudget(t, BudgetOptions{MaxTokens: maxBudgetLimit, MaxCalls: maxBudgetLimit, EndpointMaxTokens: maxBudgetLimit})
	for range inFlight {
		if err := b.reserve(testOrigin, 1); err != nil {
			t.Fatal(err)
		}
	}
	for range inFlight {
		b.settle(testOrigin, 1, &Usage{InputTokens: math.MaxInt, OutputTokens: math.MaxInt})
	}
	err := b.reserve(testOrigin, 1)
	tokens, _, endpoint := b.counters(testOrigin)
	want := int64(inFlight) * maxBudgetLimit
	if !errors.Is(err, ErrBudgetExhausted) || tokens != want || endpoint != want {
		t.Fatalf("reserve = %v with run %d, endpoint %d tokens; want refused at %d", err, tokens, endpoint, want)
	}
	if err := b.reserve(testOrigin, math.MaxInt); !errors.Is(err, ErrBudgetExhausted) {
		t.Fatalf("reserve(MaxInt) = %v, want refused", err)
	}
}

// When the write-ahead log fails, nothing was sent: the call, its tokens
// and its concurrency slot all come back.
func TestFailedLogWriteRefunds(t *testing.T) {
	m := newModelServer(t, `{}`)
	b := newBudget(t, BudgetOptions{MaxTokens: 1000, MaxCalls: 1})
	l := openBudgetLog(t, runDir(t), b)
	_ = l.Close()
	if _, err := l.Send(context.Background(), m.client(t), testCall(m.url("/v1"))); err == nil {
		t.Fatal("Send on a closed log succeeded")
	}
	key := "http://127.0.0.1:" + m.port
	tokens, calls, endpoint := b.counters(key)
	limit, inFlight := b.limiter(key).state()
	if tokens != 0 || calls != 0 || endpoint != 0 || inFlight != 0 || limit != 1 {
		t.Fatalf("after failed log write: tokens %d, calls %d, endpoint %d, in flight %d, limit %d; want all refunded, limit 1",
			tokens, calls, endpoint, inFlight, limit)
	}
	if _, bodies := m.stats(); len(bodies) != 0 {
		t.Fatalf("server saw %d bodies, want none", len(bodies))
	}
}

// A context already ended takes no slot, even a free one.
func TestAcquireCancelledTakesNoSlot(t *testing.T) {
	a := newAIMD(4)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := a.acquire(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("acquire = %v, want context.Canceled", err)
	}
	if _, inFlight := a.state(); inFlight != 0 {
		t.Fatalf("in flight %d, want 0", inFlight)
	}
}

// endsAfterFirstCheck is live at acquire's first check and ended after it,
// so acquire's result shows whether it took the slot or waited.
type endsAfterFirstCheck struct {
	context.Context
	checks atomic.Int32
	done   chan struct{}
}

func (c *endsAfterFirstCheck) Done() <-chan struct{} { return c.done }

func (c *endsAfterFirstCheck) Err() error {
	if c.checks.Add(1) == 1 {
		return nil
	}
	return context.Canceled
}

// A full limiter makes acquire wait instead of letting one more call in.
func TestAcquireWaitsWhenFull(t *testing.T) {
	a := newAIMD(4)
	if err := a.acquire(context.Background()); err != nil {
		t.Fatal(err)
	}
	ctx := &endsAfterFirstCheck{Context: context.Background(), done: make(chan struct{})}
	close(ctx.done)
	if err := a.acquire(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("acquire on a full limiter = %v, want it to wait and see context.Canceled", err)
	}
	if limit, inFlight := a.state(); inFlight != 1 || limit != 1 {
		t.Fatalf("limit %d, in flight %d; want 1 and 1", limit, inFlight)
	}
}
