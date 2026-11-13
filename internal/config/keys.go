package config

import (
	"fmt"
	"reflect"
	"strings"

	"go.yaml.in/yaml/v3"
)

// Keys returns every config key in struct order.
func Keys() []string {
	return leafKeys(reflect.TypeOf(Config{}), "")
}

func leafKeys(t reflect.Type, prefix string) []string {
	var keys []string
	for i := range t.NumField() {
		f := t.Field(i)
		key := joinKey(prefix, yamlName(f))
		if f.Type.Kind() == reflect.Struct {
			keys = append(keys, leafKeys(f.Type, key)...)
			continue
		}
		keys = append(keys, key)
	}
	return keys
}

func joinKey(prefix, name string) string {
	if prefix == "" {
		return name
	}
	return prefix + "." + name
}

func yamlName(f reflect.StructField) string {
	name, _, _ := strings.Cut(f.Tag.Get("yaml"), ",")
	return name
}

// fieldByName returns the field of struct t whose yaml name is name.
func fieldByName(t reflect.Type, name string) (reflect.StructField, bool) {
	for i := range t.NumField() {
		if f := t.Field(i); yamlName(f) == name {
			return f, true
		}
	}
	return reflect.StructField{}, false
}

// field returns the addressable value of key inside c.
func field(c *Config, key string) reflect.Value {
	v := reflect.ValueOf(c).Elem()
	for _, name := range strings.Split(key, ".") {
		f, ok := fieldByName(v.Type(), name)
		if !ok {
			panic("config: no key " + key) // callers pass keys from Keys()
		}
		v = v.FieldByIndex(f.Index)
	}
	return v
}

// copyKey sets key in dst to its value in src. Slices are copied so later
// layers cannot alias earlier ones.
func copyKey(dst, src *Config, key string) {
	from := field(src, key)
	if from.Kind() == reflect.Slice {
		cp := reflect.MakeSlice(from.Type(), from.Len(), from.Len())
		reflect.Copy(cp, from)
		from = cp
	}
	field(dst, key).Set(from)
}

func isKey(key string) bool {
	for _, k := range Keys() {
		if k == key {
			return true
		}
	}
	return false
}

// setKeys walks a YAML mapping against struct t and returns the dotted leaf
// keys it sets. Unknown keys and null values are errors, so a typo or a
// fixed protection (sandbox.internet) can never be silently ignored.
func setKeys(n *yaml.Node, t reflect.Type, prefix string) ([]string, error) {
	n = resolveAlias(n)
	if n.Kind != yaml.MappingNode {
		return nil, fmt.Errorf("line %d: %s must be a mapping", n.Line, describe(prefix))
	}
	var keys []string
	for i := 0; i+1 < len(n.Content); i += 2 {
		k, v := n.Content[i], resolveAlias(n.Content[i+1])
		key := joinKey(prefix, k.Value)
		f, ok := fieldByName(t, k.Value)
		if !ok || k.Kind != yaml.ScalarNode {
			return nil, fmt.Errorf("line %d: unknown key %q", k.Line, key)
		}
		if v.Kind == yaml.ScalarNode && v.Tag == "!!null" {
			return nil, fmt.Errorf("line %d: key %q has no value", k.Line, key)
		}
		if f.Type.Kind() != reflect.Struct {
			keys = append(keys, key)
			continue
		}
		sub, err := setKeys(v, f.Type, key)
		if err != nil {
			return nil, err
		}
		keys = append(keys, sub...)
	}
	return keys, nil
}

func resolveAlias(n *yaml.Node) *yaml.Node {
	for n.Kind == yaml.AliasNode && n.Alias != nil {
		n = n.Alias
	}
	return n
}

func describe(prefix string) string {
	if prefix == "" {
		return "the top level"
	}
	return fmt.Sprintf("key %q", prefix)
}
