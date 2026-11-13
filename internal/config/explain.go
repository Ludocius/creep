package config

import (
	"fmt"
	"reflect"
	"strings"
)

// Entry is one line of `creep config explain`.
type Entry struct {
	Key    string `json:"key"`
	Value  any    `json:"value"`
	Source string `json:"source"`
}

// Explain returns every key with its final value and the layer that set it,
// in struct order.
func (r *Resolved) Explain() []Entry {
	keys := Keys()
	entries := make([]Entry, 0, len(keys))
	for _, k := range keys {
		entries = append(entries, Entry{Key: k, Value: field(&r.Config, k).Interface(), Source: r.sources[k]})
	}
	return entries
}

// FormatValue renders a value for text output. Strings are quoted, so empty
// values and spaces stay visible and control characters are escaped.
func FormatValue(v any) string {
	rv := reflect.ValueOf(v)
	switch rv.Kind() {
	case reflect.String:
		return fmt.Sprintf("%q", rv.String())
	case reflect.Slice:
		parts := make([]string, rv.Len())
		for i := range parts {
			parts[i] = FormatValue(rv.Index(i).Interface())
		}
		return "[" + strings.Join(parts, ", ") + "]"
	default:
		return fmt.Sprint(v)
	}
}
