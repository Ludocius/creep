package gateway

import (
	"errors"
	"fmt"
	"net/url"
	"sync"

	"github.com/sneakercreepers/creep/internal/exitcode"
)

// ErrNoConsent means the endpoint has no consent: the user declined, could
// not be asked, or (in CI) the policy does not list it.
var ErrNoConsent = errors.New("no consent to send code to this endpoint")

// ConsentError is returned by Send when consent is missing or cannot be
// determined (an unreadable or unsafe consent store, Err). Both fail closed
// the same way: nothing is sent and ExitCode is exitcode.ConfigError (2),
// because the fix is in configuration, not in the model.
type ConsentError struct {
	Endpoint string // normalized origin, e.g. "https://api.example.com:443"
	CI       bool
	Err      error // why consent could not be read; nil for a plain refusal
}

func (e *ConsentError) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("%s: %v: %v; nothing was sent", e.Endpoint, ErrNoConsent, e.Err)
	}
	if e.CI {
		return fmt.Sprintf("%s: %v; in CI consent comes only from the policy file (CREEP_POLICY, key consent)", e.Endpoint, ErrNoConsent)
	}
	return fmt.Sprintf("%s: %v; nothing was sent", e.Endpoint, ErrNoConsent)
}

func (e *ConsentError) Unwrap() []error { return []error{ErrNoConsent, e.Err} }

// ExitCode is the process exit code for a run stopped by missing consent.
func (e *ConsentError) ExitCode() int { return exitcode.ConfigError }

// Prompt asks the user whether redacted code may be sent to endpoint (a
// normalized origin). Anything but an explicit yes is a decline; an error
// is a decline too.
type Prompt func(endpoint string) (bool, error)

// ConsentOptions configures NewConsent.
type ConsentOptions struct {
	CI        bool     // from config.InCI: never prompt, consult only Policy
	Policy    []string // config.Resolved.PolicyConsent()
	StorePath string   // local consent file; "" keeps answers for this run only
	Prompt    Prompt   // nil declines every endpoint not already consented
}

// Consent decides, per endpoint origin (scheme, host and effective port,
// normalized as the egress.allow check does), whether Send may proceed.
//
// In CI only the policy grants consent and nothing prompts. Locally the
// policy, then the stored answers, then the prompt; a yes is stored so each
// endpoint is asked once, a no is remembered for this run only, so a later
// run asks again.
type Consent struct {
	mu      sync.Mutex
	ci      bool
	policy  map[string]bool
	store   string
	prompt  Prompt
	session map[string]bool // answers given during this run
}

// NewConsent validates the policy entries. Each is an origin URL such as
// "https://api.example.com" or "https://10.0.0.5:8443", with no path,
// userinfo, query or fragment.
func NewConsent(opts ConsentOptions) (*Consent, error) {
	c := &Consent{
		ci:      opts.CI,
		policy:  map[string]bool{},
		store:   opts.StorePath,
		prompt:  opts.Prompt,
		session: map[string]bool{},
	}
	for _, s := range opts.Policy {
		key, err := parseOrigin(s)
		if err != nil {
			return nil, fmt.Errorf("policy consent entry %q: %w", s, err)
		}
		c.policy[key] = true
	}
	return c, nil
}

// check returns nil when endpoint may receive a request, and a
// *ConsentError otherwise. It holds the lock while prompting, so concurrent
// calls to one endpoint ask once.
func (c *Consent) check(endpoint *url.URL) error {
	key, err := origin(endpoint)
	if err != nil {
		return &ConsentError{Endpoint: "(invalid endpoint)", CI: c.ci, Err: err}
	}
	if c.policy[key] {
		return nil
	}
	if c.ci {
		return &ConsentError{Endpoint: key, CI: true}
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	ok, err := c.local(key)
	if err != nil {
		return &ConsentError{Endpoint: key, Err: err}
	}
	if !ok {
		return &ConsentError{Endpoint: key}
	}
	return nil
}

// local consults this run's answers, the store, then the prompt.
func (c *Consent) local(key string) (bool, error) {
	if ok, asked := c.session[key]; asked {
		return ok, nil
	}
	stored, err := c.stored(key)
	if err != nil || stored {
		return stored, err
	}
	ok := c.ask(key)
	c.session[key] = ok
	if !ok || c.store == "" {
		return ok, nil
	}
	// Failing to store a yes refuses the call: the user was told the answer
	// is kept, and a silent failure would ask again on every run.
	if err := addStoredConsent(c.store, key); err != nil {
		delete(c.session, key)
		return false, err
	}
	return true, nil
}

func (c *Consent) stored(key string) (bool, error) {
	if c.store == "" {
		return false, nil
	}
	keys, err := readConsentStore(c.store)
	if err != nil {
		return false, err
	}
	return keys[key], nil
}

func (c *Consent) ask(key string) bool {
	if c.prompt == nil {
		return false
	}
	ok, err := c.prompt(key)
	return err == nil && ok
}

// parseOrigin accepts scheme://host[:port] with an optional trailing "/"
// and returns it normalized like the allowlist: lowercase host, canonical
// IP, explicit port.
func parseOrigin(s string) (string, error) {
	u, err := url.Parse(s)
	if err != nil {
		return "", fmt.Errorf("%w: not a URL", ErrInvalidHost)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return "", fmt.Errorf("scheme %q: want http or https", u.Scheme)
	}
	bare := u.Host != "" && u.User == nil && (u.Path == "" || u.Path == "/") &&
		u.RawQuery == "" && !u.ForceQuery && u.Fragment == ""
	if !bare {
		return "", errors.New("want scheme://host[:port] with no path, userinfo, query or fragment")
	}
	return origin(u)
}
