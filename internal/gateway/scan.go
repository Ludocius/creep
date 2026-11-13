package gateway

import (
	"errors"
	"fmt"
	"strings"

	"github.com/sneakercreepers/creep/internal/redact"
)

// SkipReason says why a file was not scanned. It is a closed set, so run
// output never quotes error text that could carry repository bytes.
type SkipReason string

// The reasons a file is listed as not scanned.
const (
	SkipReadFailed   SkipReason = "read_failed"   // Read returned an error
	SkipTooLarge     SkipReason = "too_large"     // redact.ErrFileTooLarge
	SkipLineTooLong  SkipReason = "line_too_long" // redact.ErrLineTooLong: minified, binary or CR-only
	SkipRedactFailed SkipReason = "redact_failed" // any other redact.File error
	SkipRunFull      SkipReason = "run_full"      // redact.ErrRunFull: the run stopped here
	SkipSendFailed   SkipReason = "send_failed"   // Send failed: the run stopped here
	SkipBudget       SkipReason = "budget"        // ErrBudgetExhausted: the run stopped here
)

// NotScanned is a file the model never saw in full. Path comes from the
// scanned repository: callers must escape it before printing.
type NotScanned struct {
	Path   string
	Reason SkipReason
}

// ScanReport is the outcome of FileScan.Run, for run output and exit status.
type ScanReport struct {
	Fragments  int          // fragments sent
	NotScanned []NotScanned // in input order
	// Incomplete means the run stopped before its last file (run_full,
	// budget or send_failed): it must never be reported as a clean result.
	Incomplete bool
}

// Fragment is a piece of redact.File output, cut at line ends, ready to be
// a Call.Payload.
type Fragment struct {
	Path       string
	Text       string         // redacted
	Redactions map[string]int // marker label -> count in Text, for Call.Redactions
}

// FileScan sends repository files to a model, fragment by fragment. Each file
// is redacted whole with redact.File before it is cut, so no fragment
// boundary can split a secret, and only File output is ever cut.
type FileScan struct {
	Redactor         *redact.Redactor // one per run
	MaxFragmentBytes int              // fragments are whole lines up to this size
	// Read returns a file's content; the caller opens it without blocking.
	Read func(path string) ([]byte, error)
	// Send delivers one fragment, normally through EgressLog.Send. An error
	// stops the run; one wrapping redact.ErrRunFull (from a Redact of other
	// text for the same call) is reported as run_full.
	Send func(Fragment) error
}

// Run scans paths in order. A file that cannot be read or that redact.File
// rejects is never sent, raw or truncated: it is listed as not scanned and
// the run goes on. ErrRunFull or a Send error stops the run: that file and
// every later one are listed as not scanned, the report is Incomplete and
// the error is returned.
func (s FileScan) Run(paths []string) (ScanReport, error) {
	if s.Redactor == nil || s.Read == nil || s.Send == nil || s.MaxFragmentBytes <= 0 {
		return ScanReport{}, errors.New("file scan: Redactor, Read, Send and MaxFragmentBytes are required")
	}
	var rep ScanReport
	for i, path := range paths {
		reason, err := s.scanFile(path, &rep)
		if err != nil {
			rep.stop(paths[i:], reason)
			return rep, fmt.Errorf("file scan stopped at %q: %w", path, err)
		}
		if reason != "" {
			rep.NotScanned = append(rep.NotScanned, NotScanned{Path: path, Reason: reason})
		}
	}
	return rep, nil
}

// stop lists the file that stopped the run with reason and every later file
// as not scanned, with the same reason.
func (r *ScanReport) stop(rest []string, reason SkipReason) {
	r.Incomplete = true
	for _, path := range rest {
		r.NotScanned = append(r.NotScanned, NotScanned{Path: path, Reason: reason})
	}
}

// scanFile sends one file. It returns a reason when the file is not scanned,
// with an error only when the run must stop.
func (s FileScan) scanFile(path string, rep *ScanReport) (SkipReason, error) {
	content, err := s.Read(path)
	if err != nil {
		return SkipReadFailed, nil
	}
	text, err := s.Redactor.File(content)
	if err != nil {
		return redactSkip(err)
	}
	for _, f := range s.fragments(path, text) {
		if err := s.Send(f); err != nil {
			return sendSkip(err)
		}
		rep.Fragments++
	}
	return "", nil
}

// redactSkip maps a redact.File error to its reason. Only ErrRunFull stops
// the run: it holds for every later call on the Redactor.
func redactSkip(err error) (SkipReason, error) {
	switch {
	case errors.Is(err, redact.ErrRunFull):
		return SkipRunFull, err
	case errors.Is(err, redact.ErrFileTooLarge):
		return SkipTooLarge, nil
	case errors.Is(err, redact.ErrLineTooLong):
		return SkipLineTooLong, nil
	}
	return SkipRedactFailed, nil
}

// sendSkip maps a Send error to its reason; every Send error stops the run.
func sendSkip(err error) (SkipReason, error) {
	switch {
	case errors.Is(err, redact.ErrRunFull):
		return SkipRunFull, err
	case errors.Is(err, ErrBudgetExhausted):
		return SkipBudget, err
	}
	return SkipSendFailed, err
}

// fragments cuts redacted text into whole lines of at most MaxFragmentBytes;
// a longer line is one fragment alone, never truncated. Markers hold no
// newline, so no cut falls inside one.
func (s FileScan) fragments(path, text string) []Fragment {
	var out []Fragment
	for text != "" {
		n := fragmentLen(text, s.MaxFragmentBytes)
		part := text[:n]
		out = append(out, Fragment{Path: path, Text: part, Redactions: s.Redactor.MarkerCounts(part)})
		text = text[n:]
	}
	return out
}

// fragmentLen returns the length of the next fragment of text.
func fragmentLen(text string, maxBytes int) int {
	if len(text) <= maxBytes {
		return len(text)
	}
	if i := strings.LastIndexByte(text[:maxBytes], '\n'); i >= 0 {
		return i + 1
	}
	if i := strings.IndexByte(text, '\n'); i >= 0 {
		return i + 1
	}
	return len(text)
}
