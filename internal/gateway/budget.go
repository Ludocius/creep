package gateway

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"sync"
)

// defaultMaxConcurrency is the per-endpoint AIMD ceiling when
// BudgetOptions.MaxConcurrency is zero.
const defaultMaxConcurrency = 4

// ErrBudgetExhausted means a call would exceed the run's token or call
// budget, or the endpoint's token budget. Nothing was sent or logged.
var ErrBudgetExhausted = errors.New("model budget exhausted")

// ErrReserveTokens means Call.ReserveTokens is not positive.
var ErrReserveTokens = errors.New("call must reserve at least one token")

// BudgetLimit names the limit a refused call would have exceeded. It is a
// closed set, so run output never quotes anything else.
type BudgetLimit string

// The limits a call can exceed.
const (
	LimitRunTokens      BudgetLimit = "run_tokens"      // budget.max_tokens
	LimitRunCalls       BudgetLimit = "run_calls"       // budget.max_calls
	LimitEndpointTokens BudgetLimit = "endpoint_tokens" // BudgetOptions.EndpointMaxTokens
)

// BudgetError is returned by Send when a call would exceed a limit. Like a
// consent refusal it is not written to egress.log: nothing was attempted.
type BudgetError struct {
	Endpoint string // normalized origin
	Limit    BudgetLimit
}

func (e *BudgetError) Error() string {
	return fmt.Sprintf("%s: %v (%s); nothing was sent", e.Endpoint, ErrBudgetExhausted, e.Limit)
}

func (e *BudgetError) Unwrap() error { return ErrBudgetExhausted }

// BudgetOptions configures NewBudget. MaxTokens and MaxCalls come from the
// resolved config (budget.max_tokens, budget.max_calls), which the project
// file cannot raise.
type BudgetOptions struct {
	MaxTokens         int // per run; required
	MaxCalls          int // per run; required
	EndpointMaxTokens int // per endpoint origin; 0 means only the run limit
	MaxConcurrency    int // AIMD ceiling per endpoint origin; 0 means 4
}

// Budget is a run's token and call budget and the AIMD concurrency limit of
// each endpoint origin. It is safe for concurrent use.
//
// Send reserves Call.ReserveTokens and one call before writing anything, so
// concurrent calls can never jointly overspend. When the reply reports
// usage, the reservation is replaced by the reported tokens; otherwise
// (no Usage, transport error) the reservation stays spent.
type Budget struct {
	mu          sync.Mutex
	opts        BudgetOptions
	tokens      int            // spent or reserved in this run
	calls       int            // started in this run
	endpoint    map[string]int // tokens spent or reserved per origin
	concurrency map[string]*aimd
}

// NewBudget validates opts.
func NewBudget(opts BudgetOptions) (*Budget, error) {
	if opts.MaxTokens <= 0 || opts.MaxCalls <= 0 || opts.EndpointMaxTokens < 0 || opts.MaxConcurrency < 0 {
		return nil, errors.New("gateway budget: MaxTokens and MaxCalls must be positive, the rest not negative")
	}
	if opts.MaxConcurrency == 0 {
		opts.MaxConcurrency = defaultMaxConcurrency
	}
	return &Budget{opts: opts, endpoint: map[string]int{}, concurrency: map[string]*aimd{}}, nil
}

// ticket is one admitted call: its reservation and its concurrency slot.
type ticket struct {
	b        *Budget
	key      string
	reserved int
	slot     *aimd
}

// admit reserves the call's tokens, then waits for a concurrency slot. A
// wait ended by ctx returns the reservation.
func (l *EgressLog) admit(ctx context.Context, call Call) (*ticket, error) {
	if l.budget == nil {
		return nil, errors.New("gateway call: no budget configured; nothing was sent")
	}
	u, _ := url.Parse(call.Endpoint) // checkCall parsed it already
	key, err := origin(u)
	if err != nil {
		return nil, fmt.Errorf("gateway call: %w", err)
	}
	b := l.budget
	if err := b.reserve(key, call.ReserveTokens); err != nil {
		return nil, fmt.Errorf("gateway call: %w", err)
	}
	slot := b.limiter(key)
	if err := slot.acquire(ctx); err != nil {
		b.refund(key, call.ReserveTokens)
		return nil, fmt.Errorf("gateway call: wait for a concurrency slot: %w", err)
	}
	return &ticket{b: b, key: key, reserved: call.ReserveTokens, slot: slot}, nil
}

// reserve charges one call and n tokens, or refuses when any limit would be
// exceeded.
func (b *Budget) reserve(key string, n int) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	switch {
	case b.calls >= b.opts.MaxCalls:
		return &BudgetError{Endpoint: key, Limit: LimitRunCalls}
	case n > b.opts.MaxTokens-b.tokens:
		return &BudgetError{Endpoint: key, Limit: LimitRunTokens}
	case b.opts.EndpointMaxTokens > 0 && n > b.opts.EndpointMaxTokens-b.endpoint[key]:
		return &BudgetError{Endpoint: key, Limit: LimitEndpointTokens}
	}
	b.calls++
	b.tokens += n
	b.endpoint[key] += n
	return nil
}

// refund returns a reservation for a call that sent nothing.
func (b *Budget) refund(key string, n int) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.calls--
	b.tokens -= n
	b.endpoint[key] -= n
}

// settle replaces a reservation with the tokens the provider reported. A
// missing or negative report keeps the reservation.
func (b *Budget) settle(key string, reserved int, used *Usage) {
	if used == nil || used.InputTokens < 0 || used.OutputTokens < 0 {
		return
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	delta := spentTokens(*used, b.opts.MaxTokens) - reserved
	b.tokens += delta
	b.endpoint[key] += delta
}

// spentTokens adds a reported usage, capped at limit so a huge report
// cannot overflow the counters; the cap alone exhausts the run.
func spentTokens(u Usage, limit int) int {
	if u.InputTokens >= limit || u.OutputTokens >= limit-u.InputTokens {
		return limit
	}
	return u.InputTokens + u.OutputTokens
}

func (b *Budget) limiter(key string) *aimd {
	b.mu.Lock()
	defer b.mu.Unlock()
	a, ok := b.concurrency[key]
	if !ok {
		a = newAIMD(b.opts.MaxConcurrency)
		b.concurrency[key] = a
	}
	return a
}

// cancel ends a call that sent nothing: slot and reservation come back and
// the concurrency limit is unchanged.
func (t *ticket) cancel() {
	t.slot.release(0)
	t.b.refund(t.key, t.reserved)
}

// finish ends a call that was sent.
func (t *ticket) finish(status int, sendErr error, used *Usage) {
	t.slot.release(congestionSignal(status, sendErr))
	t.b.settle(t.key, t.reserved, used)
}
