package config

import (
	"bytes"
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

var update = flag.Bool("update", false, "rewrite schema/config.schema.json from the Config structs")

var schemaPath = filepath.Join("..", "..", "schema", "config.schema.json")

// TestSchemaInSync fails when schema/config.schema.json drifts from the
// structs, enums and defaults. Regenerate with:
//
//	go test ./internal/config -run TestSchemaInSync -update
func TestSchemaInSync(t *testing.T) {
	want, err := generateSchema()
	if err != nil {
		t.Fatal(err)
	}
	if *update {
		if err := os.WriteFile(schemaPath, want, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	got, err := os.ReadFile(schemaPath)
	if err != nil {
		t.Fatal(err)
	}
	got = bytes.ReplaceAll(got, []byte("\r\n"), []byte("\n"))
	if !bytes.Equal(got, want) {
		t.Errorf("%s is out of date; run: go test ./internal/config -run TestSchemaInSync -update", schemaPath)
	}
}

func generateSchema() ([]byte, error) {
	defaults := Defaults()
	root := objectSchema(reflect.TypeOf(Config{}), reflect.ValueOf(defaults), "")
	root["$schema"] = "https://json-schema.org/draft/2020-12/schema"
	root["title"] = "creep project and user configuration"
	root["description"] = "creep.yaml and ~/.creep/config.yaml. Generated from internal/config; do not edit by hand."
	out, err := json.MarshalIndent(root, "", "  ")
	return append(out, '\n'), err
}

func objectSchema(t reflect.Type, v reflect.Value, prefix string) map[string]any {
	props := map[string]any{}
	for i := range t.NumField() {
		f := t.Field(i)
		key := joinKey(prefix, yamlName(f))
		if f.Type.Kind() == reflect.Struct {
			props[yamlName(f)] = objectSchema(f.Type, v.Field(i), key)
			continue
		}
		props[yamlName(f)] = leafSchema(f, v.Field(i).Interface(), key)
	}
	return map[string]any{"type": "object", "additionalProperties": false, "properties": props}
}

func leafSchema(f reflect.StructField, def any, key string) map[string]any {
	s := map[string]any{"description": f.Tag.Get("desc"), "default": def}
	switch f.Type.Kind() {
	case reflect.String:
		s["type"] = "string"
		addEnum(s, key)
	case reflect.Int:
		s["type"] = "integer"
		s["minimum"] = 1
	case reflect.Bool:
		s["type"] = "boolean"
	case reflect.Slice:
		item := map[string]any{"type": "string"}
		addEnum(item, key)
		s["type"], s["items"] = "array", item
	}
	if key == "gates.pr" || key == "gates.nightly" {
		s["pattern"] = gatePattern()
	}
	if key == "calibration.cache_days" {
		s["minimum"], s["maximum"] = minCacheDays, maxCacheDays
	}
	return s
}

func addEnum(s map[string]any, key string) {
	if values, ok := enums[key]; ok {
		s["enum"] = values
	}
}

// TestSchemaCoversEveryKey guards the generator itself: each key appears.
func TestSchemaCoversEveryKey(t *testing.T) {
	data, err := generateSchema()
	if err != nil {
		t.Fatal(err)
	}
	var root map[string]any
	if err := json.Unmarshal(data, &root); err != nil {
		t.Fatal(err)
	}
	for _, key := range Keys() {
		node := root
		for _, part := range strings.Split(key, ".") {
			props, _ := node["properties"].(map[string]any)
			next, ok := props[part].(map[string]any)
			if !ok {
				t.Fatalf("schema has no %s", key)
			}
			node = next
		}
		if node["description"] == "" {
			t.Errorf("key %s has no desc tag", key)
		}
	}
}
