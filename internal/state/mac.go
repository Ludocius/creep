package state

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

// SecretBytes is the length of the per-user state secret.
const SecretBytes = 32

// ErrUnauthenticated means a line's MAC is missing or wrong: the file was not
// written by this user's creep (for example, it was committed in the scanned
// repository). Live mode treats such a cache entry as a miss; everywhere
// else it is also ErrCorrupt.
var ErrUnauthenticated = errors.New("state line not written by this user's creep")

// macSuffix ends every signed line: `,"mac":"<64 hex>"}`.
const macField = `,"mac":"`

var macLen = len(macField) + 2*sha256.Size + len(`"}`)

// Domain prefixes keep a run line from verifying as a cache entry and a line
// of one run from verifying in another.
func runDomain(id string) []byte { return []byte("creep run v1\x00" + id + "\x00") }

var cacheDomain = []byte("creep cache v1\x00")

// sign appends a MAC over domain and body as the last field of the JSON
// object body.
func sign(secret, domain, body []byte) []byte {
	m := hmac.New(sha256.New, secret)
	m.Write(domain)
	m.Write(body)
	line := append(bytes.Clone(body[:len(body)-1]), macField...)
	line = hex.AppendEncode(line, m.Sum(nil))
	return append(line, `"}`...)
}

// verify checks a line written by sign and returns its body without the MAC.
// The MAC covers the raw bytes, so fields added by a later version stay
// authenticated without re-encoding.
func verify(secret, domain, line []byte) ([]byte, error) {
	n := len(line) - macLen
	if n < 2 || !bytes.Equal(line[n:n+len(macField)], []byte(macField)) || !bytes.HasSuffix(line, []byte(`"}`)) {
		return nil, fmt.Errorf("no mac: %w", ErrUnauthenticated)
	}
	got, err := hex.DecodeString(string(line[n+len(macField) : len(line)-2]))
	if err != nil {
		return nil, fmt.Errorf("bad mac: %w", ErrUnauthenticated)
	}
	body := append(bytes.Clone(line[:n]), '}')
	m := hmac.New(sha256.New, secret)
	m.Write(domain)
	m.Write(body)
	if !hmac.Equal(got, m.Sum(nil)) {
		return nil, fmt.Errorf("mac mismatch: %w", ErrUnauthenticated)
	}
	return body, nil
}

// UserSecret returns the per-user state secret from
// <os.UserConfigDir>/creep/state.key, creating it (0600, in a 0700
// directory) on first use. It lives outside every repository, so state
// shipped inside a scanned repo can never carry a valid MAC.
func UserSecret() ([]byte, error) {
	base, err := os.UserConfigDir()
	if err != nil {
		return nil, fmt.Errorf("state secret: %w", err)
	}
	dir := filepath.Join(base, "creep")
	if err := os.MkdirAll(dir, dirMode); err != nil {
		return nil, fmt.Errorf("state secret: %w", err)
	}
	s, err := Open(dir, make([]byte, SecretBytes))
	if err != nil {
		return nil, fmt.Errorf("state secret: %w", err)
	}
	defer s.Close()
	return s.readOrCreateSecret("state.key")
}

func (s *Store) readOrCreateSecret(name string) ([]byte, error) {
	secret, err := s.readSecret(name)
	if !errors.Is(err, os.ErrNotExist) {
		return secret, err
	}
	if err := s.createSecret(name); err != nil && !errors.Is(err, os.ErrExist) {
		return nil, err
	}
	return s.readSecret(name)
}

func (s *Store) readSecret(name string) ([]byte, error) {
	f, err := s.openRegular(name, false)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if looseSecret(info) {
		return nil, fmt.Errorf("%s: readable by others: %w", name, ErrUnsafePath)
	}
	data, err := io.ReadAll(io.LimitReader(f, 2*SecretBytes+1))
	if err != nil {
		return nil, err
	}
	secret, err := hex.DecodeString(string(data))
	if err != nil || len(secret) != SecretBytes {
		return nil, fmt.Errorf("%s: not a %d-byte hex secret: %w", name, SecretBytes, ErrCorrupt)
	}
	return secret, nil
}

// createSecret writes a fresh secret to a temporary file and links it into
// place, so a concurrent reader sees either no file or a whole one, and two
// creators agree on the first.
func (s *Store) createSecret(name string) error {
	secret := make([]byte, SecretBytes)
	_, _ = rand.Read(secret) // crypto/rand.Read never fails on supported platforms
	tmp := ".tmp-" + randomHex(8)
	f, err := s.root.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, fileMode)
	if err != nil {
		return err
	}
	defer func() { _ = s.root.Remove(tmp) }()
	_, err = f.Write([]byte(hex.EncodeToString(secret)))
	if err == nil {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return err
	}
	return os.Link(s.abs(tmp), s.abs(name))
}
