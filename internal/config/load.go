package config

import (
	"fmt"
	"reflect"
)

// File is the raw content of one config file. Name is how messages and
// `config explain` refer to it; it is shown quoted.
type File struct {
	Name string
	Data []byte
}

// Flag is a CLI flag the user passed explicitly.
type Flag struct {
	Name  string // as typed, e.g. "--format"
	Key   string // config key it sets, e.g. "output.format"
	Value string
}

// Inputs are the layers above the defaults. A nil file is an absent layer.
// Explicit is the --config file; when set, User and Project are ignored.
type Inputs struct {
	Policy   *File
	User     *File
	Project  *File
	Explicit *File
	Flags    []Flag
}

// Resolved is the effective configuration and the source of each key.
type Resolved struct {
	Config  Config
	sources map[string]string
}

// layer is one file layer after the policy.
type layer struct {
	kind    string // user, project, --config
	file    *File
	project bool
}

// state carries what the policy decided while later layers apply.
type state struct {
	Resolved
	locked map[string]string // key -> policy source
	limits Limits
	limSrc string
}

// Load applies the layers in order and returns the validated result.
func Load(in Inputs) (*Resolved, error) {
	s := &state{Resolved: Resolved{Config: Defaults(), sources: map[string]string{}}}
	for _, k := range Keys() {
		s.sources[k] = "default"
	}
	if in.Policy != nil {
		if err := s.applyPolicy(in.Policy); err != nil {
			return nil, err
		}
	}
	for _, l := range fileLayers(in) {
		if err := s.applyFile(l); err != nil {
			return nil, err
		}
	}
	if err := s.applyFlags(in.Flags); err != nil {
		return nil, err
	}
	if err := s.checkLimits(); err != nil {
		return nil, err
	}
	return &s.Resolved, nil
}

func fileLayers(in Inputs) []layer {
	if in.Explicit != nil {
		return []layer{{kind: "--config", file: in.Explicit}}
	}
	var ls []layer
	if in.User != nil {
		ls = append(ls, layer{kind: "user", file: in.User})
	}
	if in.Project != nil {
		ls = append(ls, layer{kind: "project", file: in.Project, project: true})
	}
	return ls
}

func label(kind string, f *File) string {
	return fmt.Sprintf("%s %q", kind, f.Name)
}

func (s *state) applyPolicy(f *File) error {
	src := label("policy", f)
	p, keys, err := decodePolicy(f.Data)
	if err != nil {
		return fmt.Errorf("%s: %w", src, err)
	}
	if err := checkPolicy(p); err != nil {
		return fmt.Errorf("%s: %w", src, err)
	}
	if err := s.merge(&p.Defaults, keys, src); err != nil {
		return err
	}
	s.locked = map[string]string{}
	for _, k := range p.Locked {
		s.locked[k] = src
	}
	s.limits, s.limSrc = p.Limits, src
	return nil
}

// checkPolicy validates the parts of a policy that are not config values.
func checkPolicy(p policyFile) error {
	for _, k := range p.Locked {
		if !isKey(k) {
			return fmt.Errorf("locked: unknown key %q", k)
		}
	}
	for _, g := range []string{p.Limits.Gates.PR, p.Limits.Gates.Nightly} {
		if g == "" {
			continue
		}
		if _, err := parseGate(g); err != nil {
			return fmt.Errorf("limits: %w", err)
		}
	}
	return nil
}

func (s *state) applyFile(l layer) error {
	src := label(l.kind, l.file)
	c, keys, err := decodeConfig(l.file.Data)
	if err != nil {
		return fmt.Errorf("%s: %w", src, err)
	}
	for _, k := range keys {
		if l.project && projectForbidden[k] {
			return fmt.Errorf("%s: key %q cannot be set in the project file, because the scanned repository must not choose where its code is sent; set it in the user file, --config or policy", src, k)
		}
	}
	return s.merge(&c, keys, src)
}

func (s *state) applyFlags(flags []Flag) error {
	for _, f := range flags {
		var c Config
		v := field(&c, f.Key)
		if v.Kind() != reflect.String {
			return fmt.Errorf("flag %s: key %q is not a string", f.Name, f.Key)
		}
		v.SetString(f.Value)
		if err := s.merge(&c, []string{f.Key}, "flag "+f.Name); err != nil {
			return err
		}
	}
	return nil
}

// merge copies keys from c after checking locks and values, so every error
// names the layer that caused it.
func (s *state) merge(c *Config, keys []string, src string) error {
	for _, k := range keys {
		if pol, ok := s.locked[k]; ok {
			return fmt.Errorf("%s: key %q is locked by %s and cannot be overridden", src, k, pol)
		}
		if err := validateKey(c, k); err != nil {
			return fmt.Errorf("%s: %s: %w", src, k, err)
		}
	}
	for _, k := range keys {
		copyKey(&s.Config, c, k)
		s.sources[k] = src
	}
	return nil
}

// checkLimits rejects a final gate looser than the policy limit, whichever
// layer set it (including the built-in default).
func (s *state) checkLimits() error {
	limits := []struct{ key, limit string }{
		{"gates.pr", s.limits.Gates.PR},
		{"gates.nightly", s.limits.Gates.Nightly},
	}
	for _, l := range limits {
		if l.limit == "" {
			continue
		}
		limit, _ := parseGate(l.limit) // checked in checkPolicy
		value := field(&s.Config, l.key).String()
		g, _ := parseGate(value) // checked in merge, or a valid default
		if !g.atLeastAsStrict(limit) {
			return fmt.Errorf("%s: %s %q is looser than the limit %q set by %s", s.sources[l.key], l.key, value, l.limit, s.limSrc)
		}
	}
	return nil
}
