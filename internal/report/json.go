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
// already escapes controls, invalid UTF-8 and <, >, &; this also escapes
// format runes (bidi overrides, zero-width), which it leaves raw. They can
// only occur inside strings, so escaping them keeps the JSON equivalent.
func writeInertJSON(w io.Writer, v any) error {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetIndent("", "  ")
	if err := enc.Encode(v); err != nil {
		return err
	}
	_, err := w.Write(escapeFormatRunes(buf.Bytes()))
	return err
}

func escapeFormatRunes(data []byte) []byte {
	var out bytes.Buffer
	out.Grow(len(data))
	for len(data) > 0 {
		r, size := utf8.DecodeRune(data)
		switch {
		case !unicode.Is(unicode.Cf, r):
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
