package gateway

import (
	"context"
	"errors"
	"fmt"
	"math"
	"sync"
	"testing"
)

func newBudget(t *testing.T, opts BudgetOptions) *Budget {
	t.Helper()
	b, err := NewBudget(opts)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// roomyBudget never limits the tests that are not about the budget.
func roomyBudget(t *testing.T) *Budget {
	t.Helper()
	return newBudget(t, BudgetOptions{MaxTokens: maxBudgetLimit, MaxCalls: maxBudgetLimit})
}

func openBudgetLog(t *testing.T, dir string, b *Budget) *EgressLog {
	t.Helper()
	l, err := OpenEgressLog(dir, allowAllConsent(t), b)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.Close() })
	return l
}

// usageOf reports n input tokens for every reply.
func usageOf(n int) func([]byte) (Usage, bool) {
	return func([]byte) (Usage, bool) { return Usage{InputTokens: n}, true }
}

// Acceptance (#84): a call that would exceed the budget is not sent, writes
// nothing to egress.log or payloads, and is reported as a *BudgetError
// naming the limit.
func TestSendRefusesOverBudget(t *testing.T) {
	tests := []struct {
		name    string
		opts    BudgetOptions
		reserve int
		usage   func([]byte) (Usage, bool)
		want    BudgetLimit
	}{
		{"run calls", BudgetOptions{MaxTokens: 1000, MaxCalls: 1}, 10, nil, LimitRunCalls},
		{"run tokens, reservation kept without usage", BudgetOptions{MaxTokens: 150, MaxCalls: 9}, 100, nil, LimitRunTokens},
		{"run tokens, reported usage charged", BudgetOptions{MaxTokens: 150, MaxCalls: 9}, 50, usageOf(140), LimitRunTokens},
		{"endpoint tokens", BudgetOptions{MaxTokens: 1000, MaxCalls: 9, EndpointMaxTokens: 150}, 100, nil, LimitEndpointTokens},
		{"reported usage overflowing is capped", BudgetOptions{MaxTokens: 1000, MaxCalls: 9}, 1, func([]byte) (Usage, bool) {
			return Usage{InputTokens: 1 << 62, OutputTokens: 1 << 62}, true
		}, LimitRunTokens},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := newModelServer(t, `{}`)
			dir := runDir(t)
			l := openBudgetLog(t, dir, newBudget(t, tt.opts))
			call := testCall(m.url("/v1"))
			call.ReserveTokens, call.Usage = tt.reserve, tt.usage
			if _, err := l.Send(context.Background(), m.client(t), call); err != nil {
				t.Fatalf("first Send: %v", err)
			}
			_, err := l.Send(context.Background(), m.client(t), call)
			checkBudgetRefusal(t, err, tt.want)
			if _, bodies := m.stats(); len(bodies) != 1 || len(readLines(t, dir)) != 2 {
				t.Fatalf("server saw %d bodies, log has %d lines; want 1 and 2", len(bodies), len(readLines(t, dir)))
			}
		})
	}
}

func checkBudgetRefusal(t *testing.T, err error, want BudgetLimit) {
	t.Helper()
	var be *BudgetError
	if !errors.As(err, &be) || be.Limit != want || !errors.Is(err, ErrBudgetExhausted) {
		t.Fatalf("Send = %v, want *BudgetError %s", err, want)
	}
}

// Reported usage below the reservation gives the difference back, so the
// budget is not spent on output the model never produced.
func TestReportedUsageRefundsReservation(t *testing.T) {
	m := newModelServer(t, `{}`)
	l := openBudgetLog(t, runDir(t), newBudget(t, BudgetOptions{MaxTokens: 150, MaxCalls: 9}))
	call := testCall(m.url("/v1"))
	call.ReserveTokens, call.Usage = 100, usageOf(10)
	for i := range 5 {
		if _, err := l.Send(context.Background(), m.client(t), call); err != nil {
			t.Fatalf("Send %d: %v", i, err)
		}
	}
}

func TestSendNeedsBudgetAndReservation(t *testing.T) {
	m := newModelServer(t, `{}`)
	dir := runDir(t)
	l, err := OpenEgressLog(dir, allowAllConsent(t), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	if _, err := l.Send(context.Background(), m.client(t), testCall(m.url("/v1"))); err == nil {
		t.Fatal("Send without a budget succeeded")
	}
	call := testCall(m.url("/v1"))
	call.ReserveTokens = 0
	if _, err := openLog(t, runDir(t)).Send(context.Background(), m.client(t), call); !errors.Is(err, ErrReserveTokens) {
		t.Fatalf("Send reserving 0 tokens = %v, want ErrReserveTokens", err)
	}
	checkNothingWritten(t, dir)
	if _, bodies := m.stats(); len(bodies) != 0 {
		t.Fatalf("server saw %d bodies, want none", len(bodies))
	}
}

func TestNewBudgetRejects(t *testing.T) {
	for _, opts := range []BudgetOptions{
		{MaxCalls: 1},
		{MaxTokens: 1},
		{MaxTokens: 1, MaxCalls: 1, EndpointMaxTokens: -1},
		{MaxTokens: 1, MaxCalls: 1, MaxConcurrency: -1},
		{MaxTokens: math.MaxInt, MaxCalls: 1},
		{MaxTokens: 1, MaxCalls: maxBudgetLimit + 1},
		{MaxTokens: 1, MaxCalls: 1, EndpointMaxTokens: maxBudgetLimit + 1},
		{MaxTokens: 1, MaxCalls: 1, MaxConcurrency: maxBudgetLimit + 1},
	} {
		if _, err := NewBudget(opts); err == nil {
			t.Errorf("NewBudget(%+v) succeeded", opts)
		}
	}
}

// A call whose context ends while it waits for a slot sends and logs
// nothing and gives its reservation back.
func TestCancelledWaitRefunds(t *testing.T) {
	m := newModelServer(t, `{}`)
	dir := runDir(t)
	b := newBudget(t, BudgetOptions{MaxTokens: 100, MaxCalls: 1})
	l := openBudgetLog(t, dir, b)
	slot := b.limiter("http://127.0.0.1:" + m.port)
	if err := slot.acquire(context.Background()); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := l.Send(ctx, m.client(t), testCall(m.url("/v1"))); !errors.Is(err, context.Canceled) {
		t.Fatalf("Send while every slot is busy = %v, want context.Canceled", err)
	}
	checkNothingWritten(t, dir)
	slot.release(0)
	if _, err := l.Send(context.Background(), m.client(t), testCall(m.url("/v1"))); err != nil {
		t.Fatalf("Send after refund: %v", err)
	}
}

// Concurrent Sends never overspend: with a budget of n calls exactly n
// bodies reach the server.
func TestConcurrentSendsStayInBudget(t *testing.T) {
	const calls, budget = 12, 5
	m := newModelServer(t, `{}`)
	dir := runDir(t)
	l := openBudgetLog(t, dir, newBudget(t, BudgetOptions{MaxTokens: 1 << 20, MaxCalls: budget}))
	client := m.client(t)
	var wg sync.WaitGroup
	errs := make(chan error, calls)
	for range calls {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := l.Send(context.Background(), client, testCall(m.url("/v1")))
			errs <- err
		}()
	}
	wg.Wait()
	close(errs)
	refused := 0
	for err := range errs {
		if errors.Is(err, ErrBudgetExhausted) {
			refused++
		}
	}
	if _, bodies := m.stats(); len(bodies) != budget || refused != calls-budget || len(readLines(t, dir)) != 2*budget {
		t.Fatalf("server saw %d bodies, %d refused, %d log lines; want %d, %d, %d",
			len(bodies), refused, len(readLines(t, dir)), budget, calls-budget, 2*budget)
	}
}

// Acceptance (#84): the run reports a budget stop as incomplete, with the
// file that hit it and every later one listed as not scanned.
func TestScanReportsBudgetStop(t *testing.T) {
	m := newModelServer(t, `{}`)
	l := openBudgetLog(t, runDir(t), newBudget(t, BudgetOptions{MaxTokens: 1000, MaxCalls: 1}))
	scan := FileScan{
		Redactor:         newRedactor(t),
		MaxFragmentBytes: 1024,
		Read:             func(string) ([]byte, error) { return []byte(goodFile), nil },
		Send: func(f Fragment) error {
			call := testCall(m.url("/v1"))
			call.Payload = []byte(f.Text)
			_, err := l.Send(context.Background(), m.client(t), call)
			return err
		},
	}
	rep, err := scan.Run([]string{"a.go", "b.go", "c.go"})
	want := []NotScanned{{"b.go", SkipBudget}, {"c.go", SkipBudget}}
	if !errors.Is(err, ErrBudgetExhausted) || !rep.Incomplete || rep.Fragments != 1 || fmt.Sprint(rep.NotScanned) != fmt.Sprint(want) {
		t.Fatalf("Run = %+v, %v; want incomplete, not scanned %v", rep, err, want)
	}
}

func TestSpentTokens(t *testing.T) {
	tests := []struct {
		in, out, limit, want int
	}{
		{10, 20, 100, 30},
		{60, 40, 100, 100},
		{100, 0, 100, 100},
		{1 << 62, 1 << 62, 100, 100},
		{0, 1<<63 - 1, 100, 100},
	}
	for _, tt := range tests {
		if got := spentTokens(Usage{tt.in, tt.out}, tt.limit); got != tt.want {
			t.Errorf("spentTokens(%d, %d, %d) = %d, want %d", tt.in, tt.out, tt.limit, got, tt.want)
		}
	}
}
