package report

import (
	"errors"
	"fmt"
	"regexp"
	"sort"

	"github.com/sneakercreepers/creep/internal/buildinfo"
	"github.com/sneakercreepers/creep/internal/state"
)

// SchemaVersion is the JSON report contract version. Removing or retyping a
// field needs a bump and a new docs/schemas/report-vN.json.
const SchemaVersion = 1

// Status is what the run concluded about a finding.
type Status string

// Finding statuses, strongest first.
const (
	StatusVerified     Status = "verified"
	StatusProbable     Status = "probable"
	StatusDiscarded    Status = "discarded"
	StatusNotEvaluated Status = "not_evaluated"
)

// statusRank orders findings in every format and doubles as the closed set.
var statusRank = map[Status]int{
	StatusVerified: 0, StatusProbable: 1, StatusDiscarded: 2, StatusNotEvaluated: 3,
}

// ClassStatus is how much of one vulnerability class the run evaluated.
type ClassStatus string

// Class statuses.
const (
	ClassCovered      ClassStatus = "covered"
	ClassPartial      ClassStatus = "partial"
	ClassNotEvaluated ClassStatus = "not_evaluated"
)

// SkipReason mirrors gateway.SkipReason, a closed set. report may not import
// gateway (layer table), so the CLI converts and a test there keeps the two
// sets equal.
type SkipReason string

// Reasons a file was not evaluated.
const (
	SkipReadFailed   SkipReason = "read_failed"
	SkipTooLarge     SkipReason = "too_large"
	SkipLineTooLong  SkipReason = "line_too_long"
	SkipRedactFailed SkipReason = "redact_failed"
	SkipRunFull      SkipReason = "run_full"
	SkipSendFailed   SkipReason = "send_failed"
	SkipBudget       SkipReason = "budget"
)

var skipReasons = map[SkipReason]bool{
	SkipReadFailed: true, SkipTooLarge: true, SkipLineTooLong: true, SkipRedactFailed: true,
	SkipRunFull: true, SkipSendFailed: true, SkipBudget: true,
}

// Incomplete reasons when the run state gives none.
const (
	ReasonScanStopped = "scan_stopped"  // the gateway scan stopped early
	ReasonRunNotEnded = "run_not_ended" // the run state has no end line
)

// idPattern matches finding IDs, class names and reasons: identifiers, never
// free text, so `creep why <id>` and every format can print them safely.
var idPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)

// ErrInvalid is wrapped by every validation error from New.
var ErrInvalid = errors.New("invalid report input")

// Tool identifies the creep build that wrote the report.
type Tool struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	Commit  string `json:"commit"`
}

// RunInfo says whether the report can be read as a clean result.
type RunInfo struct {
	Incomplete bool   `json:"incomplete"`
	Reason     string `json:"reason,omitempty"` // an ID; empty when complete
}

// Finding is one hypothesis and its verdict. Path comes from the scanned
// repository (slash-separated, relative); Line is 1-based, 0 for the file.
type Finding struct {
	ID     string `json:"id"`
	Class  string `json:"class"`
	Status Status `json:"status"`
	Path   string `json:"path"`
	Line   int    `json:"line"`
}

// ClassCoverage is one class's status and its calibration result: Detected
// of Tasks seeded tasks found, with a 95% Wilson interval for the recall.
type ClassCoverage struct {
	Class    string      `json:"class"`
	Status   ClassStatus `json:"status"`
	Detected int         `json:"detected"`
	Tasks    int         `json:"tasks"`
	CILow    float64     `json:"ci_low"`
	CIHigh   float64     `json:"ci_high"`
}

// NotEvaluated is a file the model never saw in full. Path comes from the
// scanned repository.
type NotEvaluated struct {
	Path   string     `json:"path"`
	Reason SkipReason `json:"reason"`
}

// Coverage is what was and was not evaluated.
type Coverage struct {
	Classes      []ClassCoverage `json:"classes"`
	NotEvaluated []NotEvaluated  `json:"not_evaluated"`
}

// Report is the JSON contract (schema_version 1) and the input of every
// format. Build it with New.
type Report struct {
	SchemaVersion int          `json:"schema_version"`
	Tool          Tool         `json:"tool"`
	Run           RunInfo      `json:"run"`
	Findings      []Finding    `json:"findings"`
	Coverage      Coverage     `json:"coverage"`
	DataHandling  DataHandling `json:"data_handling"`
}

// Input is what a run hands to New. Classes are in the caller's fixed order;
// NotEvaluated in scan order. Only Detected and Tasks of each class are
// read; the interval is computed here.
type Input struct {
	Run            state.Summary
	ScanIncomplete bool // gateway.ScanReport.Incomplete
	Findings       []Finding
	Classes        []ClassCoverage
	NotEvaluated   []NotEvaluated
	DataHandling   DataHandling
}

// New validates in and builds the report. Unknown statuses, reasons or
// malformed IDs are errors: a report never guesses.
func New(in Input) (*Report, error) {
	run := runInfo(in.Run, in.ScanIncomplete)
	findings, err := checkFindings(in.Findings)
	if err != nil {
		return nil, err
	}
	classes, err := checkClasses(in.Classes, run.Incomplete)
	if err != nil {
		return nil, err
	}
	skipped, err := checkNotEvaluated(in.NotEvaluated)
	if err != nil {
		return nil, err
	}
	info := buildinfo.Get()
	return &Report{
		SchemaVersion: SchemaVersion,
		Tool:          Tool{Name: "creep", Version: info.Version, Commit: info.Commit},
		Run:           run,
		Findings:      findings,
		Coverage:      Coverage{Classes: classes, NotEvaluated: skipped},
		DataHandling:  in.DataHandling.normalized(),
	}, nil
}

// runInfo is incomplete unless the run state ended complete and the scan
// did not stop. The state's reason is an ID (state checks its alphabet).
func runInfo(sum state.Summary, scanIncomplete bool) RunInfo {
	if sum.Complete() && !scanIncomplete {
		return RunInfo{}
	}
	reason := sum.Reason
	switch {
	case reason != "" && idPattern.MatchString(reason):
	case scanIncomplete:
		reason = ReasonScanStopped
	default:
		reason = ReasonRunNotEnded
	}
	return RunInfo{Incomplete: true, Reason: reason}
}

func checkFindings(in []Finding) ([]Finding, error) {
	out := make([]Finding, len(in))
	seen := make(map[string]bool, len(in))
	for i, f := range in {
		if err := checkFinding(f, seen); err != nil {
			return nil, err
		}
		out[i] = f
	}
	sort.SliceStable(out, func(i, j int) bool { return findingLess(out[i], out[j]) })
	return out, nil
}

func checkFinding(f Finding, seen map[string]bool) error {
	switch {
	case !idPattern.MatchString(f.ID):
		return fmt.Errorf("%w: finding ID %q", ErrInvalid, f.ID)
	case seen[f.ID]:
		return fmt.Errorf("%w: duplicate finding ID %q", ErrInvalid, f.ID)
	case !idPattern.MatchString(f.Class):
		return fmt.Errorf("%w: finding %s: class %q", ErrInvalid, f.ID, f.Class)
	case f.Path == "":
		return fmt.Errorf("%w: finding %s: empty path", ErrInvalid, f.ID)
	case f.Line < 0:
		return fmt.Errorf("%w: finding %s: line %d", ErrInvalid, f.ID, f.Line)
	}
	if _, ok := statusRank[f.Status]; !ok {
		return fmt.Errorf("%w: finding %s: status %q", ErrInvalid, f.ID, f.Status)
	}
	seen[f.ID] = true
	return nil
}

func findingLess(a, b Finding) bool {
	if ra, rb := statusRank[a.Status], statusRank[b.Status]; ra != rb {
		return ra < rb
	}
	if a.Path != b.Path {
		return a.Path < b.Path
	}
	if a.Line != b.Line {
		return a.Line < b.Line
	}
	return a.ID < b.ID
}

// checkClasses validates each class and, for an incomplete run, downgrades
// covered to partial: a run that stopped early cannot claim full coverage.
func checkClasses(in []ClassCoverage, incomplete bool) ([]ClassCoverage, error) {
	out := make([]ClassCoverage, len(in))
	seen := make(map[string]bool, len(in))
	for i, c := range in {
		if err := checkClass(c, seen); err != nil {
			return nil, err
		}
		if incomplete && c.Status == ClassCovered {
			c.Status = ClassPartial
		}
		c.CILow, c.CIHigh = wilson(c.Detected, c.Tasks)
		out[i] = c
	}
	return out, nil
}

func checkClass(c ClassCoverage, seen map[string]bool) error {
	switch {
	case !idPattern.MatchString(c.Class):
		return fmt.Errorf("%w: class %q", ErrInvalid, c.Class)
	case seen[c.Class]:
		return fmt.Errorf("%w: duplicate class %q", ErrInvalid, c.Class)
	case c.Status != ClassCovered && c.Status != ClassPartial && c.Status != ClassNotEvaluated:
		return fmt.Errorf("%w: class %s: status %q", ErrInvalid, c.Class, c.Status)
	case c.Tasks < 0 || c.Detected < 0 || c.Detected > c.Tasks:
		return fmt.Errorf("%w: class %s: detected %d of %d", ErrInvalid, c.Class, c.Detected, c.Tasks)
	}
	seen[c.Class] = true
	return nil
}

// checkNotEvaluated keeps scan order and drops exact repeats (SARIF
// notifications must be unique); a path is never dropped otherwise.
func checkNotEvaluated(in []NotEvaluated) ([]NotEvaluated, error) {
	out := make([]NotEvaluated, 0, len(in))
	seen := make(map[NotEvaluated]bool, len(in))
	for i, n := range in {
		if !skipReasons[n.Reason] {
			return nil, fmt.Errorf("%w: not-evaluated file %d: reason %q", ErrInvalid, i, n.Reason)
		}
		if !seen[n] {
			seen[n] = true
			out = append(out, n)
		}
	}
	return out, nil
}
