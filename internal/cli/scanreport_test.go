package cli

import (
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/sneakercreepers/creep/internal/exitcode"
	"github.com/sneakercreepers/creep/internal/gateway"
	"github.com/sneakercreepers/creep/internal/report"
	"github.com/sneakercreepers/creep/internal/state"
)

// declaredSkipReasons reads every SkipReason constant from the gateway
// source, so a reason added there is checked here without editing this test.
func declaredSkipReasons(t *testing.T) []gateway.SkipReason {
	t.Helper()
	f, err := parser.ParseFile(token.NewFileSet(), filepath.Join("..", "gateway", "scan.go"), nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	var reasons []gateway.SkipReason
	ast.Inspect(f, func(n ast.Node) bool {
		spec, ok := n.(*ast.ValueSpec)
		if !ok || len(spec.Values) != 1 {
			return true
		}
		if id, ok := spec.Type.(*ast.Ident); ok && id.Name == "SkipReason" {
			lit := spec.Values[0].(*ast.BasicLit)
			v, _ := strconv.Unquote(lit.Value)
			reasons = append(reasons, gateway.SkipReason(v))
		}
		return true
	})
	if len(reasons) < 7 {
		t.Fatalf("found %d SkipReason constants in gateway/scan.go, want at least 7", len(reasons))
	}
	return reasons
}

func TestEveryGatewayReasonReachesTheReport(t *testing.T) {
	gatewayReasons := declaredSkipReasons(t)
	var scan gateway.ScanReport
	for i, r := range gatewayReasons {
		scan.NotScanned = append(scan.NotScanned, gateway.NotScanned{Path: string(rune('a'+i)) + "\x1b.py", Reason: r})
	}
	files, _ := notEvaluatedFrom(scan)
	rep, err := report.New(report.Input{NotEvaluated: files})
	if err != nil {
		t.Fatalf("report rejects a gateway reason: %v", err)
	}
	if len(rep.Coverage.NotEvaluated) != len(gatewayReasons) {
		t.Fatalf("%d files listed, want %d", len(rep.Coverage.NotEvaluated), len(gatewayReasons))
	}
	for i, n := range rep.Coverage.NotEvaluated {
		if n.Path != scan.NotScanned[i].Path || string(n.Reason) != string(gatewayReasons[i]) {
			t.Errorf("file %d = %+v, want %+v", i, n, scan.NotScanned[i])
		}
	}
}

// An incomplete gateway scan makes an incomplete report, whose exit code is
// never OK, even when the run state ended complete.
func TestIncompleteScanNeverExitsClean(t *testing.T) {
	scan := gateway.ScanReport{
		NotScanned: []gateway.NotScanned{{Path: "x.py", Reason: gateway.SkipSendFailed}},
		Incomplete: true,
	}
	files, incomplete := notEvaluatedFrom(scan)
	rep, err := report.New(report.Input{
		Run:            state.Summary{Ended: true, Outcome: state.OutcomeComplete},
		ScanIncomplete: incomplete,
		NotEvaluated:   files,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !rep.Run.Incomplete {
		t.Fatal("report not marked incomplete")
	}
	if code := exitcode.ForReport(rep.Run.Incomplete, false); code != exitcode.Incomplete {
		t.Errorf("exit code %d, want %d", code, exitcode.Incomplete)
	}
}
