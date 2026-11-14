package cli

import (
	"github.com/sneakercreepers/creep/internal/gateway"
	"github.com/sneakercreepers/creep/internal/report"
)

// notEvaluatedFrom converts the gateway's scan outcome into the report's
// coverage input. report may not import gateway (layer table), so the CLI,
// which sits above both, owns the conversion; scan will call it once the
// pipeline exists. Every not-scanned file is kept, in scan order; report.New
// rejects a reason it does not know, so a new gateway reason cannot vanish.
func notEvaluatedFrom(rep gateway.ScanReport) (files []report.NotEvaluated, incomplete bool) {
	files = make([]report.NotEvaluated, len(rep.NotScanned))
	for i, n := range rep.NotScanned {
		files[i] = report.NotEvaluated{Path: n.Path, Reason: report.SkipReason(n.Reason)}
	}
	return files, rep.Incomplete
}
