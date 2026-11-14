package report

import (
	"bufio"
	"fmt"
	"io"
	"sort"
	"strings"
)

// WriteMarkdown writes r as a human report: run status, findings, coverage
// by class with the 95% interval, not-evaluated files and data handling.
// Every string from the repository or egress.log is a code span (codeSpan).
func WriteMarkdown(w io.Writer, r *Report) error {
	bw := bufio.NewWriter(w)
	fmt.Fprintf(bw, "# creep report\n\n%s %s (commit %s) · report schema %d\n\n",
		r.Tool.Name, codeSpan(r.Tool.Version), codeSpan(r.Tool.Commit), r.SchemaVersion)
	writeRunStatus(bw, r.Run)
	writeFindings(bw, r.Findings)
	writeClasses(bw, r.Coverage.Classes)
	writeNotEvaluated(bw, r.Coverage.NotEvaluated)
	writeDataHandling(bw, r.DataHandling)
	if err := bw.Flush(); err != nil {
		return fmt.Errorf("write Markdown report: %w", err)
	}
	return nil
}

func writeRunStatus(w io.Writer, run RunInfo) {
	if !run.Incomplete {
		fmt.Fprint(w, "**Run complete.** Every planned step and file was evaluated, except the files listed under Not evaluated.\n\n")
		return
	}
	fmt.Fprintf(w, "> **INCOMPLETE RUN** (reason %s): not everything was evaluated. This is not a clean result, whatever the findings below say.\n\n",
		codeSpan(run.Reason))
}

func writeFindings(w io.Writer, findings []Finding) {
	fmt.Fprint(w, "## Findings\n\n")
	if len(findings) == 0 {
		fmt.Fprint(w, "No findings. This says nothing about what was not evaluated; read the coverage below.\n\n")
		return
	}
	fmt.Fprint(w, "| ID | Class | Status | Location |\n|---|---|---|---|\n")
	for _, f := range findings {
		loc := f.Path
		if f.Line > 0 {
			loc = fmt.Sprintf("%s:%d", f.Path, f.Line)
		}
		fmt.Fprintf(w, "| %s | %s | %s | %s |\n", codeSpan(f.ID), codeSpan(f.Class), statusText(string(f.Status)), codeSpan(loc))
	}
	fmt.Fprintf(w, "\nRun `creep why <id>` for the evidence behind a finding.\n\n")
}

func writeClasses(w io.Writer, classes []ClassCoverage) {
	fmt.Fprint(w, "## Coverage by class\n\n")
	if len(classes) == 0 {
		fmt.Fprint(w, "No class was evaluated.\n\n")
		return
	}
	fmt.Fprint(w, "| Class | Status | Calibration detected / tasks | Recall 95% CI |\n|---|---|---|---|\n")
	for _, c := range classes {
		fmt.Fprintf(w, "| %s | %s | %d / %d | %.3f – %.3f |\n",
			codeSpan(c.Class), statusText(string(c.Status)), c.Detected, c.Tasks, c.CILow, c.CIHigh)
	}
	fmt.Fprint(w, "\n")
}

func writeNotEvaluated(w io.Writer, files []NotEvaluated) {
	fmt.Fprint(w, "## Not evaluated\n\n")
	if len(files) == 0 {
		fmt.Fprint(w, "Every file was evaluated.\n\n")
		return
	}
	fmt.Fprintf(w, "%d files were not evaluated; nothing in them is covered by this report.\n\n| File | Reason |\n|---|---|\n", len(files))
	for _, n := range files {
		fmt.Fprintf(w, "| %s | %s |\n", codeSpan(n.Path), statusText(string(n.Reason)))
	}
	fmt.Fprint(w, "\n")
}

func writeDataHandling(w io.Writer, d DataHandling) {
	fmt.Fprint(w, "## Data handling\n\n")
	if d.Requests == 0 {
		fmt.Fprint(w, "No data left the machine: `egress.log` records no request.\n")
		return
	}
	fmt.Fprintf(w, "%d requests, %d bytes after redaction, sent to %d endpoints (from `egress.log`; each payload is in `payloads/`).\n\n",
		d.Requests, d.Bytes, len(d.Endpoints))
	fmt.Fprint(w, "| Endpoint | Models | Requests | Bytes | Tokens in / out | Outcomes |\n|---|---|---|---|---|---|\n")
	for _, ep := range d.Endpoints {
		fmt.Fprintf(w, "| %s | %s | %d | %d | %d / %d | %s |\n", codeSpan(ep.Endpoint), codeList(ep.Models),
			ep.Requests, ep.Bytes, ep.InputTokens, ep.OutputTokens, countList(ep.Outcomes))
	}
	fmt.Fprintf(w, "\nRedacted before sending: %s.\n", countList(d.Redactions))
}

// statusText prints a closed-enum value; underscores read as spaces.
func statusText(s string) string { return codeSpan(strings.ReplaceAll(s, "_", " ")) }

func codeList(items []string) string {
	if len(items) == 0 {
		return "none"
	}
	out := make([]string, len(items))
	for i, s := range items {
		out[i] = codeSpan(s)
	}
	return strings.Join(out, ", ")
}

// countList prints label counts sorted by label.
func countList(m map[string]int64) string {
	if len(m) == 0 {
		return "none"
	}
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	out := make([]string, len(keys))
	for i, k := range keys {
		out[i] = fmt.Sprintf("%s %d", codeSpan(k), m[k])
	}
	return strings.Join(out, ", ")
}
