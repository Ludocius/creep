package static

import (
	"bytes"
	"context"
	"embed"
	"errors"
	"fmt"

	"github.com/tetratelabs/wazero"
	"github.com/tetratelabs/wazero/api"
)

// grammarFiles holds the modules built by grammars/build.sh. SHA256SUMS pins
// them; TestEmbeddedGrammarsMatchSums keeps the two in step.
//
//go:embed grammars/*.wasm grammars/SHA256SUMS
var grammarFiles embed.FS

const (
	// maxSymbols is the TSSymbol range; a larger count means a broken module.
	maxSymbols = 1 << 16
	// maxNameBytes bounds each grammar name read from guest memory.
	maxNameBytes = 256
)

// errGuestCall marks a trap or forced exit inside the module.
var errGuestCall = errors.New("guest call failed")

// grammar is a compiled module and the names its records refer to by ID.
type grammar struct {
	module  wazero.CompiledModule
	symbols []string
	fields  []string // fields[0] is "" (no field)
}

func (l Language) wasmFile() string {
	return "grammars/" + l.String() + ".wasm"
}

func compileGrammar(ctx context.Context, rt wazero.Runtime, lang Language) (*grammar, error) {
	wasm, err := grammarFiles.ReadFile(lang.wasmFile())
	if err != nil {
		return nil, fmt.Errorf("read %s grammar: %w", lang, err)
	}
	module, err := rt.CompileModule(ctx, wasm)
	if err != nil {
		return nil, fmt.Errorf("compile %s grammar: %w", lang, err)
	}
	g := &grammar{module: module}
	if err := g.loadNames(ctx, rt); err != nil {
		_ = module.Close(ctx)
		return nil, fmt.Errorf("load %s names: %w", lang, err)
	}
	return g, nil
}

func (g *grammar) instantiate(ctx context.Context, rt wazero.Runtime) (api.Module, error) {
	// An empty name lets parses run concurrently; _initialize is the
	// reactor-model constructor that sets up the C runtime.
	cfg := wazero.NewModuleConfig().WithName("").WithStartFunctions("_initialize")
	return rt.InstantiateModule(ctx, g.module, cfg)
}

func (g *grammar) loadNames(ctx context.Context, rt wazero.Runtime) error {
	mod, err := g.instantiate(ctx, rt)
	if err != nil {
		return err
	}
	defer func() { _ = mod.Close(ctx) }()
	if g.symbols, err = readNames(ctx, mod, "creep_symbol_count", "creep_symbol_name", 0); err != nil {
		return err
	}
	g.fields, err = readNames(ctx, mod, "creep_field_count", "creep_field_name", 1)
	if err != nil {
		return err
	}
	g.fields = append([]string{""}, g.fields...)
	return nil
}

// readNames calls countFn, then nameFn for IDs first..first+count-1.
func readNames(ctx context.Context, mod api.Module, countFn, nameFn string, first uint32) ([]string, error) {
	count, err := call(ctx, mod, countFn)
	if err != nil {
		return nil, err
	}
	if count >= maxSymbols {
		return nil, fmt.Errorf("%s returned %d", countFn, count)
	}
	names := make([]string, 0, count)
	for id := first; id < first+count; id++ {
		ptr, err := call(ctx, mod, nameFn, api.EncodeU32(id))
		if err != nil {
			return nil, err
		}
		name, err := readCString(mod.Memory(), ptr)
		if err != nil {
			return nil, fmt.Errorf("%s(%d): %w", nameFn, id, err)
		}
		names = append(names, name)
	}
	return names, nil
}

// call runs an exported function that returns one i32.
func call(ctx context.Context, mod api.Module, name string, args ...uint64) (uint32, error) {
	fn := mod.ExportedFunction(name)
	if fn == nil {
		return 0, fmt.Errorf("module has no export %s", name)
	}
	res, err := fn.Call(ctx, args...)
	if err != nil {
		return 0, fmt.Errorf("call %s: %w: %w", name, errGuestCall, err)
	}
	if len(res) != 1 {
		return 0, fmt.Errorf("call %s: %d results", name, len(res))
	}
	return api.DecodeU32(res[0]), nil
}

// readCString copies a NUL-terminated string of at most maxNameBytes.
func readCString(mem api.Memory, ptr uint32) (string, error) {
	if ptr == 0 || ptr >= mem.Size() {
		return "", fmt.Errorf("bad string pointer %#x", ptr)
	}
	n := min(mem.Size()-ptr, maxNameBytes+1)
	buf, ok := mem.Read(ptr, n)
	if !ok {
		return "", fmt.Errorf("bad string pointer %#x", ptr)
	}
	end := bytes.IndexByte(buf, 0)
	if end < 0 {
		return "", fmt.Errorf("string at %#x longer than %d bytes", ptr, maxNameBytes)
	}
	return string(buf[:end]), nil
}
