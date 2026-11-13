package config

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"reflect"
	"strings"

	"go.yaml.in/yaml/v3"
)

// policyFile is the org policy. Its defaults use the same keys as Config.
// Consent lists the model endpoints the organization consents to sending
// redacted code to; it is the only source of consent in CI (see
// Resolved.PolicyConsent). It is not a Config key, so no user, project or
// --config file can express it.
type policyFile struct {
	Locked   []string `yaml:"locked"`
	Limits   Limits   `yaml:"limits"`
	Defaults Config   `yaml:"defaults"`
	Consent  []string `yaml:"consent"`
}

// Limits are the loosest values a later layer may choose.
type Limits struct {
	Gates Gates `yaml:"gates"`
}

// decodeConfig strictly decodes a user, project or --config file and returns
// the keys it sets.
func decodeConfig(data []byte) (Config, []string, error) {
	var c Config
	keys, err := decodeStrict(data, &c)
	return c, keys, err
}

// decodePolicy strictly decodes a policy file and returns the keys its
// defaults set.
func decodePolicy(data []byte) (policyFile, []string, error) {
	var p policyFile
	keys, err := decodeStrict(data, &p)
	if err != nil {
		return policyFile{}, nil, err
	}
	var defaults []string
	for _, k := range keys {
		if rest, ok := strings.CutPrefix(k, "defaults."); ok {
			defaults = append(defaults, rest)
		}
	}
	return p, defaults, nil
}

// decodeStrict checks the keys first, for a clear "unknown key" message,
// then decodes with KnownFields as a second guard and for type errors. An
// empty file sets nothing; a second YAML document is rejected because it
// would otherwise be ignored.
func decodeStrict(data []byte, out any) ([]string, error) {
	var root yaml.Node
	dec := yaml.NewDecoder(bytes.NewReader(data))
	if err := dec.Decode(&root); errors.Is(err, io.EOF) {
		return nil, nil
	} else if err != nil {
		return nil, fmt.Errorf("parse: %w", err)
	}
	if err := dec.Decode(new(yaml.Node)); !errors.Is(err, io.EOF) {
		return nil, errors.New("parse: only one YAML document is allowed")
	}
	if len(root.Content) == 0 {
		return nil, nil
	}
	keys, err := setKeys(root.Content[0], reflect.TypeOf(out).Elem(), "")
	if err != nil {
		return nil, err
	}
	strict := yaml.NewDecoder(bytes.NewReader(data))
	strict.KnownFields(true)
	if err := strict.Decode(out); err != nil {
		return nil, fmt.Errorf("decode: %w", err)
	}
	return keys, nil
}
