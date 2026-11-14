package static

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"
)

// sharedParser compiles each grammar once for the whole test binary.
var sharedParser = sync.OnceValues(func() (*Parser, error) {
	return NewParser(context.Background())
})

func testParser(t *testing.T) *Parser {
	t.Helper()
	p, err := sharedParser()
	if err != nil {
		t.Fatal(err)
	}
	return p
}

var samples = []struct {
	lang Language
	src  string
	want []string // node types that must appear
}{
	{Python, "from flask import Flask\napp = Flask(__name__)\n\n@app.route('/u/<id>')\ndef user(id):\n    return db.execute('select 1')\n",
		[]string{"module", "decorated_definition", "function_definition", "call", "string"}},
	{JavaScript, "const app = require('express')();\napp.get('/u/:id', (req, res) => res.send(<b>{req.params.id}</b>));\n",
		[]string{"program", "lexical_declaration", "arrow_function", "member_expression", "jsx_element"}},
	{TypeScript, "import { Router } from 'express';\nconst r: Router = Router();\nr.post('/x', async (req, res): Promise<void> => { res.json(<any>req.body); });\n",
		[]string{"program", "import_statement", "type_annotation", "type_assertion", "arrow_function"}},
	{TSX, "export function App(p: { id: string }) {\n  return <div id={p.id as string}>hi</div>;\n}\n",
		[]string{"program", "export_statement", "function_declaration", "jsx_element", "as_expression"}},
}

func TestParseSamples(t *testing.T) {
	p := testParser(t)
	for _, s := range samples {
		t.Run(s.lang.String(), func(t *testing.T) {
			tree, err := p.Parse(context.Background(), s.lang, []byte(s.src))
			if err != nil {
				t.Fatal(err)
			}
			if tree.HasError || tree.Language != s.lang {
				t.Fatalf("HasError=%v Language=%v", tree.HasError, tree.Language)
			}
			if int(tree.Root.EndByte) != len(s.src) {
				t.Errorf("root ends at %d, want %d", tree.Root.EndByte, len(s.src))
			}
			types := nodeTypes(tree.Root)
			for _, want := range s.want {
				if types[want] == 0 {
					t.Errorf("no %q node; got %v", want, types)
				}
			}
			checkShape(t, tree)
		})
	}
}

func nodeTypes(root *Node) map[string]int {
	types := map[string]int{}
	walkNodes(root, func(n *Node) { types[n.Type]++ })
	return types
}

func walkNodes(root *Node, visit func(*Node)) {
	stack := []*Node{root}
	for len(stack) > 0 {
		n := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		visit(n)
		stack = append(stack, n.Children...)
	}
}

// checkShape asserts children nest inside parents and NodeCount is exact.
func checkShape(t *testing.T, tree *Tree) {
	t.Helper()
	count := 0
	walkNodes(tree.Root, func(n *Node) {
		count++
		for _, c := range n.Children {
			if c.StartByte < n.StartByte || c.EndByte > n.EndByte {
				t.Fatalf("%s [%d,%d] outside parent %s [%d,%d]", c.Type, c.StartByte, c.EndByte, n.Type, n.StartByte, n.EndByte)
			}
		}
	})
	if count != tree.NodeCount {
		t.Fatalf("walked %d nodes, NodeCount %d", count, tree.NodeCount)
	}
}

func TestParseFieldNames(t *testing.T) {
	tree, err := testParser(t).Parse(context.Background(), Python, []byte("f(x)\n"))
	if err != nil {
		t.Fatal(err)
	}
	fields := map[string]string{}
	walkNodes(tree.Root, func(n *Node) {
		if n.Field != "" {
			fields[n.Field] = n.Type
		}
	})
	if fields["function"] != "identifier" || fields["arguments"] != "argument_list" {
		t.Fatalf("fields = %v", fields)
	}
}

func TestParseEdgeInputs(t *testing.T) {
	p := testParser(t)
	tests := []struct {
		name      string
		lang      Language
		src       []byte
		wantError bool
	}{
		{"empty", Python, nil, false},
		{"only newline", JavaScript, []byte("\n"), false},
		{"unclosed paren", Python, []byte("def f(:\n  pass\n"), true},
		{"unterminated string", JavaScript, []byte("const s = 'abc\n"), true},
		{"missing brace", TypeScript, []byte("function f() {\n"), true},
		{"binary garbage", TSX, []byte{0x00, 0xff, 0xfe, '<', 0x80, '{'}, true},
		{"invalid utf-8 in string", Python, []byte("s = '\xff\xfe'\n"), false},
		{"nul bytes", Python, bytes.Repeat([]byte{0}, 1024), true},
		{"deep nesting", JavaScript, []byte(strings.Repeat("[", 50_000)), true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tree, err := p.Parse(context.Background(), tt.lang, tt.src)
			if err != nil {
				t.Fatal(err)
			}
			if tree.HasError != tt.wantError {
				t.Fatalf("HasError = %v, want %v", tree.HasError, tt.wantError)
			}
			checkShape(t, tree)
		})
	}
}

func TestParseRejects(t *testing.T) {
	p := testParser(t)
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	tests := []struct {
		name string
		ctx  context.Context
		lang Language
		src  []byte
		want error
	}{
		{"over file cap", context.Background(), Python, make([]byte, MaxFileBytes+1), ErrFileTooLarge},
		{"canceled", canceled, Python, []byte("x = 1\n"), context.Canceled},
		{"unknown language", context.Background(), Language(0), []byte("x"), nil},
		{"out of range language", context.Background(), Language(200), []byte("x"), nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tree, err := p.Parse(tt.ctx, tt.lang, tt.src)
			if err == nil || tree != nil {
				t.Fatalf("Parse = %v, %v; want error", tree, err)
			}
			if tt.want != nil && !errors.Is(err, tt.want) {
				t.Fatalf("err = %v, want %v", err, tt.want)
			}
		})
	}
}

// TestParseLimits runs worst cases against tight limits: each must fail
// closed with ErrResourceLimit instead of exhausting the host.
func TestParseLimits(t *testing.T) {
	ctx := context.Background()
	tests := []struct {
		name  string
		lim   limits
		pages uint32
		src   []byte
	}{
		{"node cap", limits{MaxFileBytes, 100, parseTimeout}, memoryLimitPages, []byte(strings.Repeat("x = 1\n", 100))},
		{"guest memory", limits{MaxFileBytes, maxNodes, parseTimeout}, 64, []byte(strings.Repeat("x = [1, 2, 3]\n", 20_000))},
		{"timeout", limits{MaxFileBytes, maxNodes, time.Nanosecond}, memoryLimitPages, []byte(strings.Repeat("x = 1\n", 1000))},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p, err := newParser(ctx, tt.lim, tt.pages)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = p.Close(ctx) }()
			_, err = p.Parse(ctx, Python, tt.src)
			if !errors.Is(err, ErrResourceLimit) {
				t.Fatalf("err = %v, want ErrResourceLimit", err)
			}
		})
	}
}

// TestParseDensestFileAtCap parses a MaxFileBytes file with the most nodes
// per byte; it must either fit or fail closed at the node cap.
func TestParseDensestFileAtCap(t *testing.T) {
	if testing.Short() {
		t.Skip("parses 1 MiB")
	}
	src := bytes.Repeat([]byte("1\n"), MaxFileBytes/2)
	_, err := testParser(t).Parse(context.Background(), Python, src)
	if err != nil && !errors.Is(err, ErrResourceLimit) {
		t.Fatalf("err = %v", err)
	}
}

func TestParseConcurrent(t *testing.T) {
	p := testParser(t)
	var wg sync.WaitGroup
	errs := make(chan error, 8)
	for i := range 8 {
		wg.Add(1)
		go func(s int) {
			defer wg.Done()
			_, err := p.Parse(context.Background(), samples[s%len(samples)].lang, []byte(samples[s%len(samples)].src))
			errs <- err
		}(i)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
}

func BenchmarkParseMaxFile(b *testing.B) {
	p, err := NewParser(context.Background())
	if err != nil {
		b.Fatal(err)
	}
	defer func() { _ = p.Close(context.Background()) }()
	src := []byte(strings.Repeat("def f(a, b):\n    return db.execute(a + b)\n", MaxFileBytes/44))
	b.SetBytes(int64(len(src)))
	for b.Loop() {
		if _, err := p.Parse(context.Background(), Python, src); err != nil {
			b.Fatal(err)
		}
	}
}
