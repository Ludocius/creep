package report

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"unicode"
	"unicode/utf8"
)

func TestCodeSpan(t *testing.T) {
	tests := []struct{ in, want string }{
		{"a.py", "`a.py`"},
		{"", "`  `"},
		{"a`b", "``a`b``"},
		{"`a", "`` `a ``"},
		{"a``b`", "``` a``b` ```"},
		{"a|b", "`a\\|b`"},
		{"x\x1b[2Jy", "`x\\x1b[2Jy`"},
		{"line\nbreak", "`line\\x0abreak`"},
		{"rlo\u202eexe", "`rlo\\u202eexe`"},
		{"zw\u200bj", "`zw\\u200bj`"},
		{"bad\xff", "`bad\\xff`"},
		{"<script>[x](y)", "`<script>[x](y)`"},
	}
	for _, tt := range tests {
		if got := codeSpan(tt.in); got != tt.want {
			t.Errorf("codeSpan(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

// No hostile path may leave a raw control, format rune or invalid byte in
// any format, or a line break that could start new Markdown.
func TestRenderedOutputIsInert(t *testing.T) {
	for ext, out := range render(t, newTestReport(t, sampleInput(t, true))) {
		if !utf8.Valid(out) {
			t.Errorf("%s: invalid UTF-8", ext)
		}
		for i, r := range string(out) {
			if r != '\n' && (unicode.IsControl(r) || unicode.Is(unicode.Cf, r)) {
				t.Errorf("%s: raw %U at byte %d", ext, r, i)
			}
		}
	}
}

func TestUnicodeFormatRunesEscapedInJSON(t *testing.T) {
	got := escapeFormatRunes([]byte(`{"p":"a` + "\u202e\U000E0041\u00e9" + `"}`))
	want := `{"p":"a\u202e\udb40\udc41` + "\u00e9" + `"}`
	if string(got) != want {
		t.Fatalf("got %s, want %s", got, want)
	}
	var v map[string]string
	if err := json.Unmarshal(got, &v); err != nil || v["p"] != "a\u202e\U000E0041\u00e9" {
		t.Errorf("escaped JSON decodes to %q, %v", v["p"], err)
	}
}

func TestURIPath(t *testing.T) {
	tests := []struct{ in, want string }{
		{"src/app.py", "src/app.py"},
		{"a b#c?d%e", "a%20b%23c%3Fd%25e"},
		{"C:\\x", "C%3A%5Cx"},
		{"é\xff", "%C3%A9%FF"},
		{"javascript:alert(1)", "javascript%3Aalert%281%29"},
	}
	for _, tt := range tests {
		got := uriPath(tt.in)
		if got != tt.want {
			t.Errorf("uriPath(%q) = %q, want %q", tt.in, got, tt.want)
		}
		if strings.ContainsAny(got, ": ") || bytes.ContainsAny([]byte(got), "?#") {
			t.Errorf("uriPath(%q) = %q is not a plain relative path", tt.in, got)
		}
	}
}
