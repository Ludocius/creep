package state

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"path"
	"regexp"
)

// MaxResponseBytes caps one recorded response. Larger ones are not recorded,
// and a cache file that would decode to more is refused as corrupt.
const MaxResponseBytes = 4 << 20

// maxEntryBytes bounds a cache file: base64 grows 4/3, plus the key.
const maxEntryBytes = MaxResponseBytes/3*4 + 8<<10

var (
	// ErrNotRecorded means replay found no recording for a key. Replay never
	// falls back to the network.
	ErrNotRecorded = errors.New("response not recorded")
	// ErrTooLarge means a response is over MaxResponseBytes.
	ErrTooLarge = errors.New("response too large to record")
)

// Key identifies a model response: the hash of the redacted request content,
// the model, and the prompt version. Changing any of them misses the cache.
type Key struct {
	ContentHash   string `json:"content_hash"`
	Model         string `json:"model"`
	PromptVersion string `json:"prompt_version"`
}

// entry is one cache file, the v1 contract (TestV1FixtureDecodes).
type entry struct {
	V        int    `json:"v"`
	Key      Key    `json:"key"`
	Response []byte `json:"response"`
}

var (
	hexPattern   = regexp.MustCompile(`^[0-9a-f]{16,128}$`)
	modelPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:/@-]{0,127}$`)
)

func (k Key) validate() error {
	if !hexPattern.MatchString(k.ContentHash) || !modelPattern.MatchString(k.Model) || !validID(k.PromptVersion) {
		return fmt.Errorf("cache key: %w", ErrInvalidID)
	}
	return nil
}

// fileName is cache/<sha256 of the key>.json. Hashing the key's JSON keeps
// field boundaries unambiguous and the name free of path characters.
func (k Key) fileName() string {
	b, _ := json.Marshal(k) // a struct of strings always marshals
	sum := sha256.Sum256(b)
	return path.Join(cacheDir, hex.EncodeToString(sum[:])+".json")
}

// Lookup returns the recorded response for k, if any.
func (s *Store) Lookup(k Key) ([]byte, bool, error) {
	if err := k.validate(); err != nil {
		return nil, false, err
	}
	name := k.fileName()
	data, err := s.readBounded(name, maxEntryBytes)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, fmt.Errorf("cache: %w", err)
	}
	resp, err := decodeEntry(data, k)
	if err != nil {
		return nil, false, fmt.Errorf("cache %s: %w", name, err)
	}
	return resp, true, nil
}

func decodeEntry(data []byte, k Key) ([]byte, error) {
	if len(data) == 0 || data[len(data)-1] != '\n' || bytes.Count(data, []byte("\n")) != 1 {
		return nil, fmt.Errorf("not one complete line: %w", ErrCorrupt)
	}
	var e entry
	if err := json.Unmarshal(data, &e); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrCorrupt, err)
	}
	if e.V > Version {
		return nil, fmt.Errorf("v %d: %w", e.V, ErrUnsupportedVersion)
	}
	if e.V < 1 || e.Key != k || e.Response == nil {
		return nil, fmt.Errorf("version, key or response mismatch: %w", ErrCorrupt)
	}
	if len(e.Response) > MaxResponseBytes {
		return nil, fmt.Errorf("response over %d bytes: %w", MaxResponseBytes, ErrCorrupt)
	}
	return e.Response, nil
}

// Record stores resp for k atomically, replacing any earlier recording.
// resp must be what the gateway returned for an already redacted request.
func (s *Store) Record(k Key, resp []byte) error {
	if err := k.validate(); err != nil {
		return err
	}
	if len(resp) > MaxResponseBytes {
		return fmt.Errorf("cache: %d bytes: %w", len(resp), ErrTooLarge)
	}
	if resp == nil {
		resp = []byte{}
	}
	line, err := json.Marshal(entry{V: Version, Key: k, Response: resp})
	if err != nil {
		return fmt.Errorf("cache: %w", err)
	}
	if err := s.ensureDir(cacheDir); err != nil {
		return err
	}
	return s.writeAtomic(k.fileName(), append(line, '\n'))
}

// Respond returns the response for k according to mode: replay serves only
// recordings and never calls; record always calls and records; live serves a
// recording when there is one and otherwise calls and records.
func (s *Store) Respond(mode Mode, k Key, call func() ([]byte, error)) ([]byte, error) {
	if !validMode(mode) {
		return nil, fmt.Errorf("respond: mode %q: %w", mode, ErrInvalidID)
	}
	if mode != ModeRecord {
		resp, ok, err := s.Lookup(k)
		if err != nil || ok {
			return resp, err
		}
		if mode == ModeReplay {
			return nil, fmt.Errorf("replay %s: %w", k.Model, ErrNotRecorded)
		}
	}
	if err := k.validate(); err != nil {
		return nil, err
	}
	resp, err := call()
	if err != nil {
		return nil, err
	}
	// A response that cannot be recorded fails the call: a later replay
	// would otherwise miss it.
	if err := s.Record(k, resp); err != nil {
		return nil, err
	}
	return resp, nil
}
