package config

import (
	"fmt"
	"slices"
	"strings"
	"unicode"
)

// validate checks every key of c; the error names the key.
func validate(c *Config) error {
	for _, key := range Keys() {
		if err := validateKey(c, key); err != nil {
			return fmt.Errorf("%s: %w", key, err)
		}
	}
	return nil
}

func validateKey(c *Config, key string) error {
	if allowed, ok := enums[key]; ok {
		return checkEnum(field(c, key).Interface(), allowed)
	}
	switch key {
	case "gates.pr", "gates.nightly":
		_, err := parseGate(field(c, key).String())
		return err
	case "model.endpoint":
		return checkEndpoint(c.Model.Endpoint)
	case "model.name":
		return checkPlain(c.Model.Name)
	case "egress.allow":
		return checkHosts(c.Egress.Allow)
	case "budget.max_tokens", "budget.max_calls":
		return checkPositive(field(c, key).Int())
	case "calibration.cache_days":
		return checkRange(c.Calibration.CacheDays, minCacheDays, maxCacheDays)
	}
	return nil
}

func checkEnum(v any, allowed []string) error {
	values, ok := v.([]string)
	if !ok {
		values = []string{v.(string)}
	}
	for _, s := range values {
		if !slices.Contains(allowed, s) {
			return fmt.Errorf("invalid value %q: want one of %s", s, strings.Join(allowed, ", "))
		}
	}
	return nil
}

// checkEndpoint accepts an empty endpoint (not configured yet) or an http(s)
// URL without spaces or control characters.
func checkEndpoint(s string) error {
	if s == "" {
		return nil
	}
	if !strings.HasPrefix(s, "https://") && !strings.HasPrefix(s, "http://") {
		return fmt.Errorf("invalid endpoint %q: want an http:// or https:// URL", s)
	}
	return checkPlain(s)
}

// checkPlain rejects whitespace and control characters, which have no place
// in names or URLs and could hide content in logs and terminals.
func checkPlain(s string) error {
	if strings.IndexFunc(s, func(r rune) bool { return unicode.IsSpace(r) || !unicode.IsPrint(r) }) >= 0 {
		return fmt.Errorf("invalid value %q: contains whitespace or control characters", s)
	}
	return nil
}

func checkHosts(hosts []string) error {
	for _, h := range hosts {
		if h == "" || strings.ContainsFunc(h, notHostRune) {
			return fmt.Errorf("invalid host %q: want host or host:port", h)
		}
	}
	return nil
}

// notHostRune allows DNS names, IPv4, bracketed IPv6 and a port.
func notHostRune(r rune) bool {
	isAlnum := r < unicode.MaxASCII && (unicode.IsLetter(r) || unicode.IsDigit(r))
	return !isAlnum && !strings.ContainsRune(".-:[]", r)
}

func checkPositive(n int64) error {
	if n <= 0 {
		return fmt.Errorf("invalid value %d: must be greater than 0", n)
	}
	return nil
}

func checkRange(n, lo, hi int) error {
	if n < lo || n > hi {
		return fmt.Errorf("invalid value %d: want %d to %d", n, lo, hi)
	}
	return nil
}
