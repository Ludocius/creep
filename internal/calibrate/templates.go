package calibrate

import (
	"bytes"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"sort"
	"strings"
)

//go:embed templates
var embeddedTemplates embed.FS

// schemaVersion is the template.json and fillers.json schema this code reads.
const schemaVersion = 1

type variantSpec struct {
	SinkLine int    `json:"sink_line"`
	Marker   string `json:"marker"` // text only this variant contains; may span lines
}

type templateSpec struct {
	Version    int                 `json:"version"`
	ID         string              `json:"id"`
	Class      Class               `json:"class"`
	Language   Language            `json:"language"`
	PadAfter   int                 `json:"pad_after"` // fillers go after this many lines
	Slots      map[string][]string `json:"slots"`
	Vulnerable variantSpec         `json:"vulnerable"`
	Safe       variantSpec         `json:"safe"`
}

type fillersSpec struct {
	Version    int      `json:"version"`
	Python     []string `json:"python"`
	JavaScript []string `json:"javascript"`
}

// variant is one rendered side of a template, before mutation.
type variant struct {
	lines    []string
	sinkLine int
	marker   string
}

type template struct {
	id        string
	class     Class
	language  Language
	padAfter  int
	slotNames []string // sorted, so draws never depend on map order
	slots     map[string][]string
	vuln      variant
	safe      variant
}

func (t template) variant(vulnerable bool) variant {
	if vulnerable {
		return t.vuln
	}
	return t.safe
}

// catalog is every template, sorted by id, and the filler lines per language.
type catalog struct {
	templates []template
	fillers   map[Language][]string
}

func defaultCatalog() (catalog, error) {
	sub, err := fs.Sub(embeddedTemplates, "templates")
	if err != nil {
		return catalog{}, fmt.Errorf("calibration templates: %w", err)
	}
	return loadCatalog(sub)
}

func loadCatalog(fsys fs.FS) (catalog, error) {
	fillers, err := loadFillers(fsys)
	if err != nil {
		return catalog{}, err
	}
	entries, err := fs.ReadDir(fsys, ".")
	if err != nil {
		return catalog{}, fmt.Errorf("calibration templates: %w", err)
	}
	cat := catalog{fillers: fillers}
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		tpl, err := loadTemplate(fsys, e.Name(), fillers)
		if err != nil {
			return catalog{}, fmt.Errorf("calibration template %s: %w", e.Name(), err)
		}
		cat.templates = append(cat.templates, tpl)
	}
	if len(cat.templates) == 0 {
		return catalog{}, errors.New("calibration templates: none found")
	}
	return cat, nil
}

func loadFillers(fsys fs.FS) (map[Language][]string, error) {
	var spec fillersSpec
	if err := decodeFile(fsys, "fillers.json", &spec); err != nil {
		return nil, err
	}
	if spec.Version != schemaVersion {
		return nil, fmt.Errorf("fillers.json: version %d, want %d", spec.Version, schemaVersion)
	}
	fillers := map[Language][]string{LanguagePython: spec.Python, LanguageJavaScript: spec.JavaScript}
	for _, lang := range []Language{LanguagePython, LanguageJavaScript} {
		for _, line := range fillers[lang] {
			if line == "" || strings.ContainsAny(line, "\r\n") || strings.Contains(line, placeholderMark) {
				return nil, fmt.Errorf("fillers.json: %s filler %q is not one plain line", lang, line)
			}
		}
	}
	return fillers, nil
}

func loadTemplate(fsys fs.FS, dir string, fillers map[Language][]string) (template, error) {
	var spec templateSpec
	if err := decodeFile(fsys, dir+"/template.json", &spec); err != nil {
		return template{}, err
	}
	vulnCode, err := readCode(fsys, dir+"/vulnerable.tmpl")
	if err != nil {
		return template{}, err
	}
	safeCode, err := readCode(fsys, dir+"/safe.tmpl")
	if err != nil {
		return template{}, err
	}
	if err := validateTemplate(spec, dir, vulnCode, safeCode, fillers); err != nil {
		return template{}, err
	}
	names := make([]string, 0, len(spec.Slots))
	for name := range spec.Slots {
		names = append(names, name)
	}
	sort.Strings(names)
	return template{
		id: spec.ID, class: spec.Class, language: spec.Language, padAfter: spec.PadAfter,
		slotNames: names, slots: spec.Slots,
		vuln: variant{lines: splitLines(vulnCode), sinkLine: spec.Vulnerable.SinkLine, marker: spec.Vulnerable.Marker},
		safe: variant{lines: splitLines(safeCode), sinkLine: spec.Safe.SinkLine, marker: spec.Safe.Marker},
	}, nil
}

// decodeFile decodes one JSON value and refuses unknown fields and trailing
// data, so a typo in a template fails loudly instead of being ignored.
func decodeFile(fsys fs.FS, name string, v any) error {
	data, err := fs.ReadFile(fsys, name)
	if err != nil {
		return fmt.Errorf("read %s: %w", name, err)
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return fmt.Errorf("decode %s: %w", name, err)
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return fmt.Errorf("decode %s: trailing data", name)
	}
	return nil
}

// readCode returns the file with LF line endings and exactly one final
// newline, so a CRLF checkout yields the same tasks and golden hashes.
func readCode(fsys fs.FS, name string) (string, error) {
	data, err := fs.ReadFile(fsys, name)
	if err != nil {
		return "", fmt.Errorf("read %s: %w", name, err)
	}
	code := strings.ReplaceAll(string(data), "\r\n", "\n")
	code = strings.TrimRight(code, "\n")
	if code == "" {
		return "", fmt.Errorf("%s is empty", name)
	}
	return code + "\n", nil
}

func splitLines(code string) []string {
	return strings.Split(strings.TrimSuffix(code, "\n"), "\n")
}
