package state

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
)

// Version is the "v" written on every line. Bump it only for a change that
// old readers cannot ignore; adding a field does not need a bump.
const Version = 1

// MaxLineBytes caps one event line, so a damaged or hostile file cannot make
// the reader buffer without limit.
const MaxLineBytes = 64 << 10

// Kind is the type of an event line.
type Kind string

// Event kinds: one start, any number of steps, at most one end, in order.
const (
	KindStart Kind = "start"
	KindStep  Kind = "step"
	KindEnd   Kind = "end"
)

// Outcome says whether a run evaluated everything it set out to.
type Outcome string

// A run without an end line is incomplete: it never reads as clean.
const (
	OutcomeComplete   Outcome = "complete"
	OutcomeIncomplete Outcome = "incomplete"
)

// Mode is how a run treats recorded model responses.
type Mode string

const (
	// ModeLive serves cached responses and records new ones.
	ModeLive Mode = "live"
	// ModeRecord always calls the model and overwrites the recording.
	ModeRecord Mode = "record"
	// ModeReplay serves only recorded responses and never calls the model.
	ModeReplay Mode = "replay"
)

// Event is one line of events.jsonl, the v1 contract. Fields are added, never
// removed or retyped (TestV1FixtureDecodes).
type Event struct {
	V       int     `json:"v"`
	Seq     uint64  `json:"seq"`
	Kind    Kind    `json:"kind"`
	Mode    Mode    `json:"mode,omitempty"`    // start only
	Step    string  `json:"step,omitempty"`    // step only: an ID, never repository text
	Outcome Outcome `json:"outcome,omitempty"` // end only
	Reason  string  `json:"reason,omitempty"`  // end only: an ID such as "redact_run_full"
	MAC     string  `json:"mac,omitempty"`     // HMAC-SHA256 of the line; always the last field
}

// idPattern is the alphabet of Step, Reason and run IDs: enough for
// identifiers, too narrow for free text, paths or terminal escapes.
var idPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)

func validID(s string) bool { return idPattern.MatchString(s) }

// runIDPattern is the one spelling NewRun produces. Matching it exactly
// before touching the filesystem means no second name (Windows drops a
// trailing dot or space and ignores case) can reach the same run.
var runIDPattern = regexp.MustCompile(`^[0-9]{8}T[0-9]{6}Z-[0-9a-f]{8}$`)

func validRunID(s string) bool { return runIDPattern.MatchString(s) }

func validMode(m Mode) bool {
	return m == ModeLive || m == ModeRecord || m == ModeReplay
}

// Summary is what a run's log says about it.
type Summary struct {
	ID      string
	Mode    Mode
	Steps   []string // completed steps, in order
	Ended   bool     // an end line was written
	Outcome Outcome  // OutcomeIncomplete unless the end line says complete
	Reason  string
}

// Complete reports whether the run ended and evaluated everything.
func (s Summary) Complete() bool {
	return s.Ended && s.Outcome == OutcomeComplete
}

// decodeEvents reads a whole log and checks its order. Any problem is
// ErrCorrupt (or ErrUnsupportedVersion): nothing is skipped or repaired.
func decodeEvents(r io.Reader, secret []byte, id string) (Summary, error) {
	sum := Summary{Outcome: OutcomeIncomplete}
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 4096), MaxLineBytes+1)
	sc.Split(scanLines)
	var seq uint64
	for sc.Scan() {
		seq++
		ev, err := decodeEvent(sc.Bytes(), secret, runDomain(id))
		if err == nil {
			err = sum.apply(ev, seq)
		}
		if err != nil {
			return Summary{}, fmt.Errorf("line %d: %w", seq, err)
		}
	}
	if err := sc.Err(); err != nil {
		return Summary{}, fmt.Errorf("line %d: %w: %w", seq+1, ErrCorrupt, err)
	}
	if seq == 0 {
		return Summary{}, fmt.Errorf("empty log: %w", ErrCorrupt)
	}
	return sum, nil
}

var errTorn = errors.New("last line has no newline (torn write)")

// scanLines is bufio.ScanLines without its leniency: a final line with no
// newline is a torn write, and a carriage return is not stripped.
func scanLines(data []byte, atEOF bool) (int, []byte, error) {
	if i := bytes.IndexByte(data, '\n'); i >= 0 {
		return i + 1, data[:i], nil
	}
	if atEOF && len(data) > 0 {
		return 0, nil, errTorn
	}
	return 0, nil, nil
}

func decodeEvent(line, secret, domain []byte) (Event, error) {
	if len(line) > MaxLineBytes {
		return Event{}, fmt.Errorf("line over %d bytes: %w", MaxLineBytes, ErrCorrupt)
	}
	body, err := verify(secret, domain, line)
	if err != nil {
		return Event{}, fmt.Errorf("%w: %w", ErrCorrupt, err)
	}
	var ev Event
	if err := json.Unmarshal(body, &ev); err != nil {
		return Event{}, fmt.Errorf("%w: %w", ErrCorrupt, err)
	}
	if ev.V > Version {
		return Event{}, fmt.Errorf("v %d (this creep reads up to %d): %w", ev.V, Version, ErrUnsupportedVersion)
	}
	if ev.V < 1 {
		return Event{}, fmt.Errorf("missing or invalid v: %w", ErrCorrupt)
	}
	return ev, nil
}

// apply folds one event into the summary, refusing anything out of order.
func (s *Summary) apply(ev Event, seq uint64) error {
	if ev.Seq != seq {
		return fmt.Errorf("seq %d, want %d: %w", ev.Seq, seq, ErrCorrupt)
	}
	if s.Ended {
		return fmt.Errorf("event after end: %w", ErrCorrupt)
	}
	if (seq == 1) != (ev.Kind == KindStart) {
		return fmt.Errorf("start must be the first line and only there: %w", ErrCorrupt)
	}
	switch ev.Kind {
	case KindStart:
		return s.applyStart(ev)
	case KindStep:
		return s.applyStep(ev)
	case KindEnd:
		return s.applyEnd(ev)
	}
	return fmt.Errorf("unknown kind: %w", ErrCorrupt)
}

func (s *Summary) applyStart(ev Event) error {
	if !validMode(ev.Mode) {
		return fmt.Errorf("invalid mode: %w", ErrCorrupt)
	}
	s.Mode = ev.Mode
	return nil
}

func (s *Summary) applyStep(ev Event) error {
	if !validID(ev.Step) {
		return fmt.Errorf("invalid step id: %w", ErrCorrupt)
	}
	s.Steps = append(s.Steps, ev.Step)
	return nil
}

func (s *Summary) applyEnd(ev Event) error {
	if ev.Outcome != OutcomeComplete && ev.Outcome != OutcomeIncomplete {
		return fmt.Errorf("invalid outcome: %w", ErrCorrupt)
	}
	if ev.Reason != "" && !validID(ev.Reason) {
		return fmt.Errorf("invalid reason: %w", ErrCorrupt)
	}
	s.Ended, s.Outcome, s.Reason = true, ev.Outcome, ev.Reason
	return nil
}
