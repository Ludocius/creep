package static

import (
	"encoding/binary"
	"errors"
	"testing"
)

var testGrammar = &grammar{symbols: []string{"end", "module", "x"}, fields: []string{"", "body"}}

// encode writes records in the glue.c layout.
func encode(recs ...[recordWords]uint32) []byte {
	out := make([]byte, 0, len(recs)*recordBytes)
	for _, r := range recs {
		for _, w := range r {
			out = binary.LittleEndian.AppendUint32(out, w)
		}
	}
	return out
}

func TestDecodeTree(t *testing.T) {
	words := encode(
		[recordWords]uint32{1, 0, flagNamed, noParent, 0, 4, 0, 0, 1, 0},
		[recordWords]uint32{2, 1, flagNamed, 0, 0, 1, 0, 0, 0, 1},
		[recordWords]uint32{symError, 0, flagError, 0, 1, 3, 0, 1, 0, 3},
		[recordWords]uint32{2, 0, flagMissing, 2, 3, 3, 0, 3, 0, 3},
	)
	tree, err := decodeTree(words, testGrammar, 4)
	if err != nil {
		t.Fatal(err)
	}
	root := tree.Root
	if root.Type != "module" || len(root.Children) != 2 || tree.NodeCount != 4 || !tree.HasError {
		t.Fatalf("root %+v count %d HasError %v", root, tree.NodeCount, tree.HasError)
	}
	if c := root.Children[0]; c.Type != "x" || c.Field != "body" || !c.Named {
		t.Errorf("child 0 = %+v", c)
	}
	if c := root.Children[1]; c.Type != "ERROR" || !c.Error || len(c.Children) != 1 || !c.Children[0].Missing {
		t.Errorf("child 1 = %+v", c)
	}
}

// TestDecodeTreeRejects feeds records a compromised module could write;
// each must fail with ErrInvalidTree rather than panic or misbuild.
func TestDecodeTreeRejects(t *testing.T) {
	root := [recordWords]uint32{1, 0, flagNamed, noParent, 0, 4, 0, 0, 0, 4}
	child := func(mod func(*[recordWords]uint32)) []byte {
		c := [recordWords]uint32{2, 0, flagNamed, 0, 0, 1, 0, 0, 0, 1}
		mod(&c)
		return encode(root, c)
	}
	tests := []struct {
		name  string
		words []byte
	}{
		{"no records", nil},
		{"partial record", encode(root)[:recordBytes-1]},
		{"root with parent", encode([recordWords]uint32{1, 0, 0, 0, 0, 0, 0, 0, 0, 0})},
		{"self parent", child(func(c *[recordWords]uint32) { c[3] = 1 })},
		{"forward parent", child(func(c *[recordWords]uint32) { c[3] = 7 })},
		{"second root", child(func(c *[recordWords]uint32) { c[3] = noParent })},
		{"symbol out of range", child(func(c *[recordWords]uint32) { c[0] = 3 })},
		{"symbol near error", child(func(c *[recordWords]uint32) { c[0] = 0xFFFD })},
		{"field out of range", child(func(c *[recordWords]uint32) { c[1] = 2 })},
		{"unknown flag", child(func(c *[recordWords]uint32) { c[2] = 1 << 4 })},
		{"start after end", child(func(c *[recordWords]uint32) { c[4], c[5] = 3, 2 })},
		{"end past source", child(func(c *[recordWords]uint32) { c[5] = 5 })},
		{"end wraps", child(func(c *[recordWords]uint32) { c[5] = ^uint32(0) })},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tree, err := decodeTree(tt.words, testGrammar, 4)
			if !errors.Is(err, ErrInvalidTree) || tree != nil {
				t.Fatalf("decodeTree = %v, %v; want ErrInvalidTree", tree, err)
			}
		})
	}
}

func TestParseResult(t *testing.T) {
	tests := []struct {
		code  int32
		want  uint32
		limit bool
		ok    bool
	}{
		{1, 1, false, true},
		{1 << 20, 1 << 20, false, true},
		{0, 0, false, false},
		{codeNodes, 0, true, false},
		{codeMemory, 0, true, false},
		{codeLanguage, 0, false, false},
		{codeParse, 0, false, false},
		{-99, 0, false, false},
	}
	for _, tt := range tests {
		got, err := parseResult(tt.code)
		if got != tt.want || (err == nil) != tt.ok || errors.Is(err, ErrResourceLimit) != tt.limit {
			t.Errorf("parseResult(%d) = %d, %v", tt.code, got, err)
		}
	}
}
