package report

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"testing"
)

// Contract fitness function (architecture §9): each released schema_version
// has a committed fixture, testdata/contract/vN.json, that must stay valid
// against docs/schemas/report-vN.json. The current version's fixture must
// also decode into Report with no unknown field, so removing or retyping a
// field without a bump fails; and fresh output must validate against the
// schema (TestJSONValidatesAgainstPublishedSchema), so adding a field without
// publishing it fails too.
func TestContractFixturesStayValid(t *testing.T) {
	fixtures, err := filepath.Glob(filepath.Join("testdata", "contract", "v*.json"))
	if err != nil {
		t.Fatal(err)
	}
	versionOf := regexp.MustCompile(`^v([0-9]+)\.json$`)
	found := map[int]bool{}
	for _, path := range fixtures {
		m := versionOf.FindStringSubmatch(filepath.Base(path))
		if m == nil {
			t.Errorf("%s: fixture name must be vN.json", path)
			continue
		}
		v, err := strconv.Atoi(m[1])
		if err != nil {
			t.Fatal(err)
		}
		found[v] = true
		t.Run(filepath.Base(path), func(t *testing.T) { checkFixture(t, path, v) })
	}
	for v := 1; v <= SchemaVersion; v++ {
		if !found[v] {
			t.Errorf("no committed fixture for schema_version %d", v)
		}
	}
}

func checkFixture(t *testing.T, path string, version int) {
	schema := loadJSON(t, filepath.Join("..", "..", "docs", "schemas", fmt.Sprintf("report-v%d.json", version)))
	doc := loadJSON(t, path)
	for _, e := range validateSchema(schema, doc) {
		t.Error(e)
	}
	if m, _ := doc.(map[string]any); m["schema_version"] != float64(version) {
		t.Errorf("schema_version %v, want %d", m["schema_version"], version)
	}
	if version != SchemaVersion {
		return
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var r Report
	if err := dec.Decode(&r); err != nil {
		t.Fatalf("fixture no longer decodes into Report (removed or retyped field needs a schema_version bump): %v", err)
	}
}

// The fixture must exercise every field, or a removed field could pass.
func TestContractFixtureUsesEveryField(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("testdata", "contract", fmt.Sprintf("v%d.json", SchemaVersion)))
	if err != nil {
		t.Fatal(err)
	}
	var r Report
	if err := json.Unmarshal(data, &r); err != nil {
		t.Fatal(err)
	}
	switch {
	case !r.Run.Incomplete || r.Run.Reason == "":
		t.Error("fixture run must be incomplete with a reason")
	case len(r.Findings) == 0 || len(r.Coverage.Classes) == 0 || len(r.Coverage.NotEvaluated) == 0:
		t.Error("fixture needs findings, classes and not-evaluated files")
	case len(r.DataHandling.Endpoints) == 0 || len(r.DataHandling.Redactions) == 0:
		t.Error("fixture needs endpoints and redactions")
	case len(r.DataHandling.Endpoints[0].Models) == 0 || len(r.DataHandling.Endpoints[0].Outcomes) == 0:
		t.Error("fixture endpoint needs models and outcomes")
	}
}
