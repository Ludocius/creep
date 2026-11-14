package static

import (
	"path"
	"strings"
)

// Language identifies an embedded grammar.
type Language uint8

// Languages with an embedded grammar. The zero value is not a language.
const (
	Python Language = iota + 1
	JavaScript
	TypeScript
	TSX
)

// Languages lists every embedded grammar in a stable order.
var Languages = []Language{Python, JavaScript, TypeScript, TSX}

var languageNames = map[Language]string{
	Python:     "python",
	JavaScript: "javascript",
	TypeScript: "typescript",
	TSX:        "tsx",
}

// extensions maps lowercased file extensions to grammars. JavaScript's
// grammar covers JSX; TSX needs its own because `<T>` casts are ambiguous.
var extensions = map[string]Language{
	".py":  Python,
	".pyi": Python,
	".js":  JavaScript,
	".mjs": JavaScript,
	".cjs": JavaScript,
	".jsx": JavaScript,
	".ts":  TypeScript,
	".mts": TypeScript,
	".cts": TypeScript,
	".tsx": TSX,
}

// String returns the grammar name, or "unknown" for an invalid Language.
func (l Language) String() string {
	if name, ok := languageNames[l]; ok {
		return name
	}
	return "unknown"
}

// LanguageForPath picks a grammar from a slash-separated file name.
func LanguageForPath(name string) (Language, bool) {
	l, ok := extensions[strings.ToLower(path.Ext(name))]
	return l, ok
}
