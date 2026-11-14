package state

import (
	"bufio"
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// TestV1FixtureDecodes is the run-state contract fitness function (#8, #138):
// files written by v1 must decode in every later version. Each fixture line
// is decoded with unknown fields disallowed, so removing or renaming a field
// of Event or entry fails here, and so does retyping one; adding a field
// does not. Never edit the v1 fixtures: add a v2 directory instead.
func TestV1FixtureDecodes(t *testing.T) {
	tests := []struct {
		file string
		into func() any
	}{
		{"events.jsonl", func() any { return &Event{} }},
		{"cache-entry.json", func() any { return &entry{} }},
	}
	for _, tt := range tests {
		data, err := os.ReadFile(filepath.Join("testdata", "v1", tt.file))
		if err != nil {
			t.Fatal(err)
		}
		sc := bufio.NewScanner(bytes.NewReader(data))
		for sc.Scan() {
			dec := json.NewDecoder(bytes.NewReader(sc.Bytes()))
			dec.DisallowUnknownFields()
			if err := dec.Decode(tt.into()); err != nil {
				t.Errorf("%s: %q no longer decodes strictly: %v", tt.file, sc.Text(), err)
			}
		}
	}
}

// The fixture must also mean the same thing: same kinds, outcomes and key
// semantics, not only the same field names.
func TestV1FixtureMeaning(t *testing.T) {
	f, err := os.Open(filepath.Join("testdata", "v1", "events.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	sum, err := decodeEvents(f)
	if err != nil {
		t.Fatal(err)
	}
	if sum.Mode != ModeReplay || len(sum.Steps) != 1 || sum.Steps[0] != "route:42" ||
		!sum.Ended || sum.Complete() || sum.Reason != "redact_run_full" {
		t.Fatalf("v1 events decode to %+v", sum)
	}

	data, err := os.ReadFile(filepath.Join("testdata", "v1", "cache-entry.json"))
	if err != nil {
		t.Fatal(err)
	}
	data = bytes.ReplaceAll(data, []byte("\r\n"), []byte("\n")) // tolerate a CRLF checkout
	resp, err := decodeEntry(data, testKey("x"))
	if err != nil || string(resp) != "{\"finding\":1}\n" {
		t.Fatalf("v1 cache entry = %q, %v", resp, err)
	}
	if name := filepath.Base(testKey("x").fileName()); len(name) != 64+len(".json") {
		t.Fatalf("cache file name %q changed shape", name)
	}
}
