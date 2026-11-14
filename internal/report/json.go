package report

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"unicode"
	"unicode/utf16"
	"unicode/utf8"
)

// WriteJSON writes r as the schema_version 1 JSON report, indented, with a
// trailing newline.
func WriteJSON(w io.Writer, r *Report) error {
	if err := writeInertJSON(w, r); err != nil {
		return fmt.Errorf("write JSON report: %w", err)
	}
	return nil
}

// writeInertJSON encodes v so that printing the file is safe: encoding/json
// escapes C0 controls, invalid UTF-8 and <, >, &, but leaves DEL, C1
// controls (U+009B is an 8-bit CSI) and format runes (bidi overrides,
// zero-width) raw; this escapes them too. Outside strings the encoder writes
// only ASCII punctuation, spaces and the indent newlines, which are kept, so
// the JSON stays equivalent.
func writeInertJSON(w io.Writer, v any) error {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetIndent("", "  ")
	if err := enc.Encode(v); err != nil {
		return err
	}
	_, err := w.Write(escapeInert(buf.Bytes()))
	return err
}

// needsEscape reports controls (C0, DEL, C1) and format runes.
func needsEscape(r rune) bool { return unicode.IsControl(r) || unicode.Is(unicode.Cf, r) }

func escapeInert(data []byte) []byte {
	var out bytes.Buffer
	out.Grow(len(data))
	for len(data) > 0 {
		r, size := utf8.DecodeRune(data)
		switch {
		case r == 0x0a || !needsEscape(r):
			out.Write(data[:size])
		case r > 0xffff:
			hi, lo := utf16.EncodeRune(r)
			fmt.Fprintf(&out, `\u%04x\u%04x`, hi, lo)
		default:
			fmt.Fprintf(&out, `\u%04x`, r)
		}
		data = data[size:]
	}
	return out.Bytes()
}
