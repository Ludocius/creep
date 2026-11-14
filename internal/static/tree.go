package static

import (
	"encoding/binary"
	"fmt"
)

// Tree is a parsed file. It holds grammar node types and positions only;
// node text is src[StartByte:EndByte] in the caller's buffer.
type Tree struct {
	Language Language
	Root     *Node
	// HasError is set when any node is an ERROR or a MISSING token.
	HasError bool
	// NodeCount is the number of nodes in the tree.
	NodeCount int
}

// Node is one syntax node.
type Node struct {
	// Type is the grammar's node type, such as "call" or "(".
	Type string
	// Field is the node's field name in its parent, or "".
	Field                 string
	Named, Error, Missing bool
	Extra                 bool // comments and other tokens outside the grammar
	StartByte, EndByte    uint32
	Start, End            Point
	Children              []*Node
}

// Point is a zero-based row and byte column.
type Point struct {
	Row, Column uint32
}

// Record layout written by grammars/glue.c: ten little-endian uint32 words.
const (
	recordWords = 10
	recordBytes = recordWords * 4
	noParent    = ^uint32(0)
)

const (
	flagNamed = 1 << iota
	flagError
	flagMissing
	flagExtra
	knownFlags = flagNamed | flagError | flagMissing | flagExtra
)

// tree-sitter's built-in error symbols sit outside the grammar's range.
const (
	symErrorRepeat = 0xFFFE
	symError       = 0xFFFF
)

func (g *grammar) symbolName(symbol uint32) string {
	switch symbol {
	case symError:
		return "ERROR"
	case symErrorRepeat:
		return "_ERROR"
	}
	return g.symbols[symbol]
}

type record struct {
	symbol, field, flags, parent uint32
	startByte, endByte           uint32
	start, end                   Point
}

func readRecord(words []byte, i int) record {
	w := func(k int) uint32 { return binary.LittleEndian.Uint32(words[i*recordBytes+k*4:]) }
	return record{
		symbol: w(0), field: w(1), flags: w(2), parent: w(3),
		startByte: w(4), endByte: w(5),
		start: Point{Row: w(6), Column: w(7)},
		end:   Point{Row: w(8), Column: w(9)},
	}
}

// decodeTree builds a Tree from preorder records. The guest parsed untrusted
// input, so every index and offset is checked before use.
func decodeTree(words []byte, g *grammar, srcLen int) (*Tree, error) {
	n := len(words) / recordBytes
	if n == 0 || len(words)%recordBytes != 0 {
		return nil, fmt.Errorf("%d record bytes: %w", len(words), ErrInvalidTree)
	}
	nodes := make([]Node, n)
	tree := &Tree{Root: &nodes[0], NodeCount: n}
	for i := range nodes {
		r := readRecord(words, i)
		if err := checkRecord(r, i, g, srcLen); err != nil {
			return nil, fmt.Errorf("record %d: %w", i, err)
		}
		nodes[i] = newNode(r, g)
		tree.HasError = tree.HasError || r.flags&(flagError|flagMissing) != 0
		if i > 0 {
			parent := &nodes[r.parent]
			parent.Children = append(parent.Children, &nodes[i])
		}
	}
	return tree, nil
}

func checkRecord(r record, i int, g *grammar, srcLen int) error {
	switch {
	case i == 0 && r.parent != noParent, i > 0 && int(r.parent) >= i:
		return fmt.Errorf("parent %d: %w", r.parent, ErrInvalidTree)
	case int(r.symbol) >= len(g.symbols) && r.symbol != symError && r.symbol != symErrorRepeat:
		return fmt.Errorf("symbol %d: %w", r.symbol, ErrInvalidTree)
	case int(r.field) >= len(g.fields):
		return fmt.Errorf("field %d: %w", r.field, ErrInvalidTree)
	case r.flags&^knownFlags != 0:
		return fmt.Errorf("flags %#x: %w", r.flags, ErrInvalidTree)
	case r.startByte > r.endByte || int(r.endByte) > srcLen:
		return fmt.Errorf("bytes %d..%d of %d: %w", r.startByte, r.endByte, srcLen, ErrInvalidTree)
	}
	return nil
}

func newNode(r record, g *grammar) Node {
	return Node{
		Type:      g.symbolName(r.symbol),
		Field:     g.fields[r.field],
		Named:     r.flags&flagNamed != 0,
		Error:     r.flags&flagError != 0,
		Missing:   r.flags&flagMissing != 0,
		Extra:     r.flags&flagExtra != 0,
		StartByte: r.startByte,
		EndByte:   r.endByte,
		Start:     r.start,
		End:       r.end,
	}
}
