package state

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func testKey(content string) Key {
	sum := sha256.Sum256([]byte(content))
	return Key{ContentHash: hex.EncodeToString(sum[:]), Model: "anthropic/claude-x@2026", PromptVersion: "reader.v3"}
}

func cachePath(s *Store, k Key) string {
	return filepath.Join(s.dir, filepath.FromSlash(k.fileName()))
}

// countingCall returns a model stand-in that answers with fixed bytes and
// counts its calls.
func countingCall(resp string, calls *int) func() ([]byte, error) {
	return func() ([]byte, error) {
		*calls++
		return []byte(resp), nil
	}
}

// A run recorded in one process replays byte for byte in another, with no
// model call: the basis for byte-identical reports.
func TestReplayIsByteIdenticalWithoutCalls(t *testing.T) {
	dir := filepath.Join(t.TempDir(), ".creep")
	recorder, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	responses := map[string]string{"a": "{\"finding\":1}\n", "b": "\x00\xff binary \r\n", "c": ""}
	calls := 0
	for content, resp := range responses {
		if _, err := recorder.Respond(ModeRecord, testKey(content), countingCall(resp, &calls)); err != nil {
			t.Fatal(err)
		}
	}
	_ = recorder.Close()

	replayer, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer replayer.Close()
	for content, want := range responses {
		got, err := replayer.Respond(ModeReplay, testKey(content), func() ([]byte, error) {
			t.Fatal("replay called the model")
			return nil, nil
		})
		if err != nil || !bytes.Equal(got, []byte(want)) {
			t.Errorf("replay %q = %q, %v; want %q", content, got, err, want)
		}
	}
	if calls != len(responses) {
		t.Errorf("record made %d calls; want %d", calls, len(responses))
	}
}

func TestRespondModes(t *testing.T) {
	tests := []struct {
		name      string
		mode      Mode
		recorded  bool
		want      string
		wantCalls int
		wantErr   error
	}{
		{"replay miss never calls", ModeReplay, false, "", 0, ErrNotRecorded},
		{"replay hit", ModeReplay, true, "old", 0, nil},
		{"live hit is free", ModeLive, true, "old", 0, nil},
		{"live miss calls", ModeLive, false, "new", 1, nil},
		{"record overwrites a hit", ModeRecord, true, "new", 1, nil},
		{"unknown mode", "fast", true, "", 0, ErrInvalidID},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := openStore(t)
			k := testKey("x")
			if tt.recorded {
				if err := s.Record(k, []byte("old")); err != nil {
					t.Fatal(err)
				}
			}
			calls := 0
			got, err := s.Respond(tt.mode, k, countingCall("new", &calls))
			if !errors.Is(err, tt.wantErr) || string(got) != tt.want || calls != tt.wantCalls {
				t.Fatalf("Respond = %q, %v with %d calls; want %q, %v with %d", got, err, calls, tt.want, tt.wantErr, tt.wantCalls)
			}
			if tt.wantErr == nil {
				if again, _, _ := s.Lookup(k); string(again) != tt.want {
					t.Errorf("recorded %q; want %q", again, tt.want)
				}
			}
		})
	}
}

// A failed call or an unrecordable response records nothing and returns no
// response, so a later replay cannot silently differ from the live run.
func TestRespondFailuresRecordNothing(t *testing.T) {
	s := openStore(t)
	boom := errors.New("model down")
	k := testKey("x")
	if _, err := s.Respond(ModeLive, k, func() ([]byte, error) { return nil, boom }); !errors.Is(err, boom) {
		t.Fatalf("err = %v; want the call error", err)
	}
	huge := func() ([]byte, error) { return make([]byte, MaxResponseBytes+1), nil }
	if got, err := s.Respond(ModeLive, k, huge); !errors.Is(err, ErrTooLarge) || got != nil {
		t.Fatalf("huge = %d bytes, %v; want nil, ErrTooLarge", len(got), err)
	}
	if _, ok, err := s.Lookup(k); ok || err != nil {
		t.Fatalf("Lookup after failures = %v, %v; want miss", ok, err)
	}
}

func TestInvalidKeysRefused(t *testing.T) {
	good := testKey("x")
	bad := []Key{
		{ContentHash: "XYZ", Model: good.Model, PromptVersion: good.PromptVersion},
		{ContentHash: good.ContentHash, Model: "../../etc", PromptVersion: good.PromptVersion},
		{ContentHash: good.ContentHash, Model: "m\x1b[0m", PromptVersion: good.PromptVersion},
		{ContentHash: good.ContentHash, Model: good.Model, PromptVersion: ""},
	}
	s := openStore(t)
	for _, k := range bad {
		if err := s.Record(k, []byte("r")); !errors.Is(err, ErrInvalidID) {
			t.Errorf("Record(%+v) err = %v; want ErrInvalidID", k, err)
		}
		if _, _, err := s.Lookup(k); !errors.Is(err, ErrInvalidID) {
			t.Errorf("Lookup(%+v) err = %v; want ErrInvalidID", k, err)
		}
	}
}

// A damaged cache entry is an error, not a miss: treating it as a miss would
// make replay call the network or record over evidence of tampering.
func TestCorruptCacheEntryFailsClosed(t *testing.T) {
	k := testKey("x")
	other := testKey("y")
	tests := []struct {
		name  string
		entry string
		want  error
	}{
		{"truncated", `{"v":1,"key":{"content_hash":"`, ErrCorrupt},
		{"no newline", `{"v":1,"key":` + keyJSON(k) + `,"response":"cg=="}`, ErrCorrupt},
		{"two lines", `{"v":1,"key":` + keyJSON(k) + `,"response":"cg=="}` + "\n\n", ErrCorrupt},
		{"other key", `{"v":1,"key":` + keyJSON(other) + `,"response":"cg=="}` + "\n", ErrCorrupt},
		{"null response", `{"v":1,"key":` + keyJSON(k) + `,"response":null}` + "\n", ErrCorrupt},
		{"newer version", `{"v":2,"key":` + keyJSON(k) + `,"response":"cg=="}` + "\n", ErrUnsupportedVersion},
		{"oversized file", strings.Repeat(" ", maxEntryBytes+1), ErrCorrupt},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := openStore(t)
			if err := s.Record(k, []byte("r")); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(cachePath(s, k), []byte(tt.entry), 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := s.Respond(ModeReplay, k, nil); !errors.Is(err, tt.want) {
				t.Errorf("Respond err = %v; want %v", err, tt.want)
			}
		})
	}
}

// Record leaves no temporary files behind and replaces an entry whole.
func TestRecordIsAtomic(t *testing.T) {
	s := openStore(t)
	k := testKey("x")
	for _, resp := range []string{"first", "second"} {
		if err := s.Record(k, []byte(resp)); err != nil {
			t.Fatal(err)
		}
	}
	entries, err := os.ReadDir(filepath.Join(s.dir, cacheDir))
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || strings.HasPrefix(entries[0].Name(), ".tmp-") {
		t.Fatalf("cache dir = %v; want one entry", entries)
	}
	if got, _, _ := s.Lookup(k); string(got) != "second" {
		t.Fatalf("Lookup = %q; want second", got)
	}
}

func keyJSON(k Key) string {
	return `{"content_hash":"` + k.ContentHash + `","model":"` + k.Model + `","prompt_version":"` + k.PromptVersion + `"}`
}
