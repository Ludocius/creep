package report

import (
	"encoding/json"
	"fmt"
	"math"
	"os"
	"reflect"
	"regexp"
	"sort"
	"strings"
	"testing"
	"time"
)

// This file is a small JSON Schema validator (draft-04 and draft-07 subset)
// for tests only: no network and no new dependency (AGENTS.md invariant 6).
// It covers every keyword the official SARIF 2.1.0 schema and
// docs/schemas/report-v1.json use, and reports any other keyword as an
// error, so a schema change it cannot check fails instead of passing.

type schemaChecker struct {
	root map[string]any
	errs []string
}

// ignoredKeywords are annotations or containers reached only through $ref.
var ignoredKeywords = map[string]bool{
	"$schema": true, "$id": true, "id": true, "title": true, "description": true,
	"default": true, "definitions": true,
}

func loadJSON(t *testing.T, path string) any {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var v any
	if err := json.Unmarshal(data, &v); err != nil {
		t.Fatalf("%s: %v", path, err)
	}
	return v
}

// validateSchema returns every violation of doc against schema.
func validateSchema(schema, doc any) []string {
	root, _ := schema.(map[string]any)
	return validateSchemaAt(root, schema, doc)
}

func (c *schemaChecker) fail(at, format string, args ...any) {
	c.errs = append(c.errs, at+": "+fmt.Sprintf(format, args...))
}

func (c *schemaChecker) check(schema, v any, at string) {
	if b, ok := schema.(bool); ok {
		if !b {
			c.fail(at, "schema false")
		}
		return
	}
	s, ok := schema.(map[string]any)
	if !ok {
		c.fail(at, "schema is %T", schema)
		return
	}
	keys := make([]string, 0, len(s))
	for k := range s {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		c.keyword(s, k, v, at)
	}
}

func (c *schemaChecker) keyword(s map[string]any, k string, v any, at string) {
	arg := s[k]
	switch k {
	case "$ref":
		c.check(c.resolve(arg.(string), at), v, at)
	case "type":
		c.checkType(arg, v, at)
	case "enum":
		c.checkEnum(arg.([]any), v, at)
	case "const":
		if !reflect.DeepEqual(arg, v) {
			c.fail(at, "want const %v, got %v", arg, v)
		}
	case "anyOf", "oneOf":
		c.checkCombinator(k, arg.([]any), v, at)
	case "properties", "additionalProperties", "required":
		c.checkObject(s, k, v, at)
	case "items", "minItems", "maxItems", "uniqueItems":
		c.checkArray(k, arg, v, at)
	case "minimum", "maximum":
		c.checkNumber(k, arg.(float64), v, at)
	case "minLength", "pattern", "format":
		c.checkString(k, arg, v, at)
	default:
		if !ignoredKeywords[k] {
			c.fail(at, "unsupported schema keyword %q", k)
		}
	}
}

func (c *schemaChecker) resolve(ref, at string) any {
	name, ok := strings.CutPrefix(ref, "#/definitions/")
	defs, _ := c.root["definitions"].(map[string]any)
	if !ok || defs[name] == nil {
		c.fail(at, "unresolvable $ref %q", ref)
		return true
	}
	return defs[name]
}

func (c *schemaChecker) checkType(arg, v any, at string) {
	types, ok := arg.([]any)
	if !ok {
		types = []any{arg}
	}
	for _, t := range types {
		if hasType(t.(string), v) {
			return
		}
	}
	c.fail(at, "want type %v, got %T", arg, v)
}

func hasType(t string, v any) bool {
	switch t {
	case "object":
		_, ok := v.(map[string]any)
		return ok
	case "array":
		_, ok := v.([]any)
		return ok
	case "string":
		_, ok := v.(string)
		return ok
	case "boolean":
		_, ok := v.(bool)
		return ok
	case "number":
		_, ok := v.(float64)
		return ok
	case "integer":
		f, ok := v.(float64)
		return ok && f == math.Trunc(f)
	case "null":
		return v == nil
	}
	return false
}

func (c *schemaChecker) checkEnum(values []any, v any, at string) {
	for _, e := range values {
		if reflect.DeepEqual(e, v) {
			return
		}
	}
	c.fail(at, "%v not in enum %v", v, values)
}

func (c *schemaChecker) checkCombinator(k string, subs []any, v any, at string) {
	matched := 0
	for _, sub := range subs {
		if len(validateSchemaAt(c.root, sub, v)) == 0 {
			matched++
		}
	}
	if matched == 0 || (k == "oneOf" && matched != 1) {
		c.fail(at, "%s matched %d of %d", k, matched, len(subs))
	}
}

func validateSchemaAt(root map[string]any, schema, v any) []string {
	c := &schemaChecker{root: root}
	c.check(schema, v, "$")
	return c.errs
}

func (c *schemaChecker) checkObject(s map[string]any, k string, v any, at string) {
	obj, ok := v.(map[string]any)
	if !ok {
		return
	}
	props, _ := s["properties"].(map[string]any)
	switch k {
	case "required":
		for _, name := range s[k].([]any) {
			if _, ok := obj[name.(string)]; !ok {
				c.fail(at, "missing required %q", name)
			}
		}
	case "properties":
		for name, sub := range props {
			if val, ok := obj[name]; ok {
				c.check(sub, val, at+"."+name)
			}
		}
	case "additionalProperties":
		for name, val := range obj {
			if _, declared := props[name]; !declared {
				c.check(s[k], val, at+"."+name)
			}
		}
	}
}

func (c *schemaChecker) checkArray(k string, arg, v any, at string) {
	arr, ok := v.([]any)
	if !ok {
		return
	}
	switch k {
	case "items":
		for i, item := range arr {
			c.check(arg, item, fmt.Sprintf("%s[%d]", at, i))
		}
	case "minItems":
		if float64(len(arr)) < arg.(float64) {
			c.fail(at, "fewer than %v items", arg)
		}
	case "maxItems":
		if float64(len(arr)) > arg.(float64) {
			c.fail(at, "more than %v items", arg)
		}
	case "uniqueItems":
		c.checkUnique(arg.(bool), arr, at)
	}
}

func (c *schemaChecker) checkUnique(want bool, arr []any, at string) {
	if !want {
		return
	}
	for i := range arr {
		for j := i + 1; j < len(arr); j++ {
			if reflect.DeepEqual(arr[i], arr[j]) {
				c.fail(at, "items %d and %d are equal", i, j)
			}
		}
	}
}

func (c *schemaChecker) checkNumber(k string, limit float64, v any, at string) {
	f, ok := v.(float64)
	if !ok {
		return
	}
	if (k == "minimum" && f < limit) || (k == "maximum" && f > limit) {
		c.fail(at, "%v violates %s %v", f, k, limit)
	}
}

var uriScheme = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9+.-]*:`)

func (c *schemaChecker) checkString(k string, arg, v any, at string) {
	str, ok := v.(string)
	if !ok {
		return
	}
	switch k {
	case "minLength":
		if float64(len([]rune(str))) < arg.(float64) {
			c.fail(at, "shorter than %v", arg)
		}
	case "pattern":
		if !regexp.MustCompile(arg.(string)).MatchString(str) {
			c.fail(at, "%q does not match %q", str, arg)
		}
	case "format":
		if msg := formatProblem(arg.(string), str); msg != "" {
			c.fail(at, "%q: %s", str, msg)
		}
	}
}

// formatProblem checks the formats SARIF uses. A URI may not hold spaces,
// controls or non-ASCII bytes (they must be percent-encoded).
func formatProblem(format, s string) string {
	switch format {
	case "date-time":
		if _, err := time.Parse(time.RFC3339, s); err != nil {
			return "not RFC 3339"
		}
		return ""
	case "uri", "uri-reference":
		for i := 0; i < len(s); i++ {
			if s[i] <= ' ' || s[i] >= 0x7f || strings.IndexByte(`"<>\^{|}`+"`", s[i]) >= 0 {
				return fmt.Sprintf("byte %#x not allowed in a URI", s[i])
			}
		}
		if format == "uri" && !uriScheme.MatchString(s) {
			return "not an absolute URI"
		}
		return ""
	}
	return "unsupported format " + format
}

// TestSchemaCheckerRejects keeps the validator honest: each document breaks
// one keyword and must be reported.
func TestSchemaCheckerRejects(t *testing.T) {
	schema := map[string]any{
		"type": "object", "required": []any{"a"}, "additionalProperties": false,
		"properties": map[string]any{
			"a": map[string]any{"$ref": "#/definitions/n"},
			"b": map[string]any{"type": "array", "uniqueItems": true, "minItems": 1.0, "items": map[string]any{"enum": []any{"x", "y"}}},
			"c": map[string]any{"type": "string", "format": "uri", "pattern": "^h"},
			"d": map[string]any{"anyOf": []any{map[string]any{"required": []any{"p"}}}},
		},
		"definitions": map[string]any{"n": map[string]any{"type": "integer", "minimum": 0.0, "maximum": 1.0}},
	}
	tests := map[string]string{
		"missing required": `{}`,
		"extra property":   `{"a":0,"z":1}`,
		"not integer":      `{"a":0.5}`,
		"below minimum":    `{"a":-1}`,
		"above maximum":    `{"a":2}`,
		"enum":             `{"a":0,"b":["z"]}`,
		"unique":           `{"a":0,"b":["x","x"]}`,
		"min items":        `{"a":0,"b":[]}`,
		"uri space":        `{"a":0,"c":"h ttp:x"}`,
		"uri relative":     `{"a":0,"c":"hx"}`,
		"pattern":          `{"a":0,"c":"x:y"}`,
		"anyOf":            `{"a":0,"d":{}}`,
	}
	for name, doc := range tests {
		t.Run(name, func(t *testing.T) {
			var v any
			if err := json.Unmarshal([]byte(doc), &v); err != nil {
				t.Fatal(err)
			}
			if errs := validateSchema(schema, v); len(errs) == 0 {
				t.Errorf("%s accepted", doc)
			}
		})
	}
	if errs := validateSchema(map[string]any{"maxLength": 1.0}, "x"); len(errs) == 0 {
		t.Error("unsupported keyword accepted")
	}
}
