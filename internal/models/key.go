package models

import (
	"errors"
	"fmt"
	"io"
	"strings"
)

// KeyEnv is the only place creep reads a model API key from. It is creep's
// own name on purpose: reading OPENAI_API_KEY would hand that key to any
// OpenAI-compatible endpoint the user configures, such as a third party.
const KeyEnv = "CREEP_API_KEY"

// maxKeyBytes bounds a key; real keys are a few hundred bytes at most.
const maxKeyBytes = 1024

// redactedKey is how a Key prints, whatever the verb.
const redactedKey = "[redacted]"

// ErrInvalidKey means CREEP_API_KEY holds something that cannot be a header
// value. The error never quotes the value.
var ErrInvalidKey = errors.New(KeyEnv + " must be 1-1024 printable ASCII characters without spaces")

// Key is a model API key. It never prints its value: String, GoString,
// Format and MarshalText all give "[redacted]", so a key passed to fmt, a
// logger or a JSON encoder by mistake does not leak.
type Key struct {
	value string
}

// KeyFromEnv reads CREEP_API_KEY through getenv (os.Getenv in production).
// An unset or blank variable gives the zero Key, for local endpoints that
// need none. Surrounding whitespace, such as a newline from a file, is
// trimmed.
func KeyFromEnv(getenv func(string) string) (Key, error) {
	v := strings.TrimSpace(getenv(KeyEnv))
	if v == "" {
		return Key{}, nil
	}
	if !validKey(v) {
		return Key{}, ErrInvalidKey
	}
	return Key{value: v}, nil
}

// validKey accepts visible ASCII only, so a key can never inject a header
// line (CR, LF) or smuggle a second value.
func validKey(v string) bool {
	if len(v) > maxKeyBytes {
		return false
	}
	for i := 0; i < len(v); i++ {
		if v[i] <= ' ' || v[i] > '~' {
			return false
		}
	}
	return true
}

// IsZero reports whether no key is set.
func (k Key) IsZero() bool { return k.value == "" }

func (Key) String() string   { return redactedKey }
func (Key) GoString() string { return redactedKey }

// Format covers every verb, %x and %q included, which would otherwise
// bypass String.
func (Key) Format(f fmt.State, _ rune) { _, _ = io.WriteString(f, redactedKey) }

func (Key) MarshalText() ([]byte, error) { return []byte(redactedKey), nil }
