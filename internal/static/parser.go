package static

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/tetratelabs/wazero"
	"github.com/tetratelabs/wazero/api"
	"github.com/tetratelabs/wazero/imports/wasi_snapshot_preview1"
)

// Limits for one parse of an untrusted file.
const (
	// MaxFileBytes is the largest file Parse accepts. Larger files are
	// usually bundled or generated code, which the scan skips anyway.
	MaxFileBytes = 1 << 20
	// maxNodes caps the tree at about 100 MiB of host memory.
	maxNodes = 1 << 20
	// memoryLimitPages caps guest memory at 256 MiB (64 KiB pages).
	memoryLimitPages = 4096
	// parseTimeout bounds one parse, including instantiation. Guest code
	// runs at a few microseconds per source byte (BenchmarkParseMaxFile), so
	// a MaxFileBytes file takes seconds; the timeout leaves room for a slow
	// or busy machine.
	parseTimeout = 30 * time.Second
)

var (
	// ErrFileTooLarge means the file is over MaxFileBytes and was not parsed.
	ErrFileTooLarge = errors.New("file too large to parse")
	// ErrResourceLimit means a parse hit the node, memory or time limit.
	ErrResourceLimit = errors.New("parse resource limit reached")
	// ErrInvalidTree means the grammar module returned records that fail
	// validation; the module is treated as compromised for that file.
	ErrInvalidTree = errors.New("invalid tree from grammar module")
)

// Error codes returned by creep_parse in grammars/glue.c.
const (
	codeLanguage = -1
	codeParse    = -2
	codeNodes    = -3
	codeMemory   = -4
)

type limits struct {
	fileBytes int
	nodes     uint32
	timeout   time.Duration
}

// Parser parses files with the embedded grammars. It is safe for concurrent
// use; each grammar is compiled once, on first use.
type Parser struct {
	limits  limits
	runtime wazero.Runtime

	mu       sync.Mutex
	grammars map[Language]*grammar
}

// NewParser starts the WebAssembly runtime. Close releases it.
func NewParser(ctx context.Context) (*Parser, error) {
	return newParser(ctx, limits{fileBytes: MaxFileBytes, nodes: maxNodes, timeout: parseTimeout}, memoryLimitPages)
}

func newParser(ctx context.Context, lim limits, pages uint32) (*Parser, error) {
	cfg := wazero.NewRuntimeConfig().WithMemoryLimitPages(pages).WithCloseOnContextDone(true)
	rt := wazero.NewRuntimeWithConfig(ctx, cfg)
	// WASI satisfies the C library's imports. Module configs grant no
	// directories, environment, arguments, real clock or sockets.
	if _, err := wasi_snapshot_preview1.Instantiate(ctx, rt); err != nil {
		_ = rt.Close(ctx)
		return nil, fmt.Errorf("start wasi: %w", err)
	}
	return &Parser{limits: lim, runtime: rt, grammars: map[Language]*grammar{}}, nil
}

// Close releases the runtime and every compiled grammar.
func (p *Parser) Close(ctx context.Context) error {
	return p.runtime.Close(ctx)
}

// Parse parses src as lang. A file with syntax errors still yields a tree,
// with Tree.HasError set.
func (p *Parser) Parse(ctx context.Context, lang Language, src []byte) (*Tree, error) {
	if len(src) > p.limits.fileBytes {
		return nil, fmt.Errorf("parse %s: %d bytes: %w", lang, len(src), ErrFileTooLarge)
	}
	g, err := p.grammar(ctx, lang)
	if err != nil {
		return nil, err
	}
	parseCtx, cancel := context.WithTimeout(ctx, p.limits.timeout)
	defer cancel()
	tree, err := p.parse(parseCtx, g, src)
	if err != nil {
		return nil, fmt.Errorf("parse %s: %w", lang, classify(ctx, parseCtx, err))
	}
	tree.Language = lang
	return tree, nil
}

func (p *Parser) grammar(ctx context.Context, lang Language) (*grammar, error) {
	if _, ok := languageNames[lang]; !ok {
		return nil, fmt.Errorf("parse: unknown language %d", lang)
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if g := p.grammars[lang]; g != nil {
		return g, nil
	}
	g, err := compileGrammar(ctx, p.runtime, lang)
	if err != nil {
		return nil, err
	}
	p.grammars[lang] = g
	return g, nil
}

// parse runs one fresh instance so no state survives from a previous file.
func (p *Parser) parse(ctx context.Context, g *grammar, src []byte) (*Tree, error) {
	mod, err := g.instantiate(ctx, p.runtime)
	if err != nil {
		return nil, err
	}
	defer func() { _ = mod.Close(context.Background()) }()
	ptr, err := writeSource(ctx, mod, src)
	if err != nil {
		return nil, err
	}
	res, err := call(ctx, mod, "creep_parse", api.EncodeU32(ptr), uint64(len(src)), api.EncodeU32(p.limits.nodes))
	if err != nil {
		return nil, err
	}
	n, err := parseResult(api.DecodeI32(uint64(res)))
	if err != nil {
		return nil, err
	}
	words, err := readRecords(ctx, mod, n, p.limits.nodes)
	if err != nil {
		return nil, err
	}
	return decodeTree(words, g, len(src))
}

func writeSource(ctx context.Context, mod api.Module, src []byte) (uint32, error) {
	res, err := call(ctx, mod, "creep_alloc", uint64(max(len(src), 1)))
	if err != nil {
		return 0, err
	}
	ptr := res
	if ptr == 0 {
		return 0, fmt.Errorf("allocate %d bytes: %w", len(src), ErrResourceLimit)
	}
	if !mod.Memory().Write(ptr, src) {
		return 0, fmt.Errorf("write source at %#x: %w", ptr, ErrInvalidTree)
	}
	return ptr, nil
}

func parseResult(code int32) (uint32, error) {
	switch {
	case code > 0:
		return uint32(code), nil
	case code == codeNodes || code == codeMemory:
		return 0, fmt.Errorf("guest code %d: %w", code, ErrResourceLimit)
	case code == codeLanguage:
		return 0, errors.New("grammar ABI not supported by the runtime")
	case code == codeParse:
		return 0, errors.New("parser returned no tree")
	default:
		return 0, fmt.Errorf("guest code %d: %w", code, ErrInvalidTree)
	}
}

func readRecords(ctx context.Context, mod api.Module, n, limit uint32) ([]byte, error) {
	if n > limit {
		return nil, fmt.Errorf("%d records over cap %d: %w", n, limit, ErrInvalidTree)
	}
	res, err := call(ctx, mod, "creep_records")
	if err != nil {
		return nil, err
	}
	words, ok := mod.Memory().Read(res, n*recordBytes)
	if !ok {
		return nil, fmt.Errorf("records at %#x out of memory bounds: %w", res, ErrInvalidTree)
	}
	return words, nil
}

// classify marks a failed guest call as a resource limit. A trap is how the
// guest reports running out of memory (tree-sitter aborts on a failed
// malloc), and the runtime ends the call when parseTimeout passes. If the
// caller's own context ended, its error is returned as is.
func classify(caller, parse context.Context, err error) error {
	if caller.Err() != nil {
		return caller.Err()
	}
	if parse.Err() != nil || errors.Is(err, errGuestCall) {
		return fmt.Errorf("%w: %w", ErrResourceLimit, err)
	}
	return err
}
