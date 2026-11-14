package calibrate

import (
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strings"
)

// placeholderMark delimits a slot in a .tmpl file: @@name@@. Neither Python
// nor JavaScript uses "@@", so it cannot clash with code such as f-strings.
const placeholderMark = "@@"

var (
	templateIDRe  = regexp.MustCompile(`^[a-z0-9]+(-[a-z0-9]+)*$`)
	slotNameRe    = regexp.MustCompile(`^[a-z]+$`)
	placeholderRe = regexp.MustCompile(`@@([a-z]+)@@`)
	// identRe is the only shape a slot value may take: a plain identifier
	// is safe in code, in a string literal and in a URL path alike.
	identRe = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_]{0,31}$`)
	wordRe  = regexp.MustCompile(`[A-Za-z0-9_$]+`)
)

// keywordList holds the reserved words and common globals of both languages.
// A slot value that equals one could change what the code means.
const keywordList = `and as assert async await break case catch class
	const constructor continue debugger def default del delete do elif else enum
	except export extends false False finally for from function global if import
	in instanceof is lambda let new None nonlocal not null of or pass print
	prototype raise require return self super switch this throw true True try
	typeof undefined var void while with yield`

func isKeyword(w string) bool {
	return slices.Contains(strings.Fields(keywordList), w)
}

func validateTemplate(spec templateSpec, dir, vulnCode, safeCode string, fillers map[Language][]string) error {
	if err := validateHeader(spec, dir, fillers); err != nil {
		return err
	}
	if err := validateSlots(spec.Slots, codeWords(vulnCode, safeCode, fillers[spec.Language])); err != nil {
		return err
	}
	if err := validatePlaceholders(spec.Slots, vulnCode, safeCode); err != nil {
		return err
	}
	if err := validateVariant("vulnerable", spec.Vulnerable, spec.PadAfter, vulnCode, safeCode); err != nil {
		return err
	}
	return validateVariant("safe", spec.Safe, spec.PadAfter, safeCode, vulnCode)
}

func validateHeader(spec templateSpec, dir string, fillers map[Language][]string) error {
	switch {
	case spec.Version != schemaVersion:
		return fmt.Errorf("version %d, want %d", spec.Version, schemaVersion)
	case spec.ID != dir || !templateIDRe.MatchString(spec.ID):
		return fmt.Errorf("id %q must equal the directory name and be lowercase words joined by -", spec.ID)
	case !slices.Contains(Classes(), spec.Class):
		return fmt.Errorf("unknown class %q", spec.Class)
	case len(fillers[spec.Language]) == 0:
		return fmt.Errorf("language %q has no fillers", spec.Language)
	}
	return nil
}

// validateSlots makes renaming a pure alpha-conversion: every value is a
// fresh plain identifier that no other pool and no template word uses.
func validateSlots(slots map[string][]string, words map[string]bool) error {
	if len(slots) == 0 {
		return errors.New("no slots: every template must be mutable")
	}
	owner := map[string]string{}
	for name, pool := range slots {
		if !slotNameRe.MatchString(name) {
			return fmt.Errorf("slot name %q must be lowercase letters", name)
		}
		if len(pool) < 2 {
			return fmt.Errorf("slot %s: needs at least 2 values to mutate", name)
		}
		for _, v := range pool {
			if err := checkSlotValue(v, words); err != nil {
				return fmt.Errorf("slot %s: %w", name, err)
			}
			if prev, dup := owner[v]; dup {
				return fmt.Errorf("slot %s: value %q repeats in slot %s", name, v, prev)
			}
			owner[v] = name
		}
	}
	return nil
}

func checkSlotValue(v string, words map[string]bool) error {
	switch {
	case !identRe.MatchString(v):
		return fmt.Errorf("value %q is not a plain identifier", v)
	case isKeyword(v):
		return fmt.Errorf("value %q is a keyword", v)
	case words[v]:
		return fmt.Errorf("value %q already appears in the template or fillers", v)
	}
	return nil
}

// codeWords returns every word of both variants, placeholders removed, and
// of the language's fillers.
func codeWords(vulnCode, safeCode string, fillers []string) map[string]bool {
	text := placeholderRe.ReplaceAllString(vulnCode+"\n"+safeCode, " ")
	text += "\n" + strings.Join(fillers, "\n")
	words := map[string]bool{}
	for _, w := range wordRe.FindAllString(text, -1) {
		words[w] = true
	}
	return words
}

func validatePlaceholders(slots map[string][]string, vulnCode, safeCode string) error {
	used := map[string]bool{}
	for _, m := range placeholderRe.FindAllStringSubmatch(vulnCode+safeCode, -1) {
		if _, ok := slots[m[1]]; !ok {
			return fmt.Errorf("placeholder %s has no slot", m[0])
		}
		used[m[1]] = true
	}
	if strings.Contains(placeholderRe.ReplaceAllString(vulnCode+"\n"+safeCode, ""), placeholderMark) {
		return fmt.Errorf("malformed placeholder: %q not followed by a slot name", placeholderMark)
	}
	for name := range slots {
		if !used[name] {
			return fmt.Errorf("slot %s is never used", name)
		}
	}
	return nil
}

// validateVariant checks the ground truth: the sink line exists and comes
// after the filler insertion point, and the marker tells the twins apart.
func validateVariant(name string, v variantSpec, padAfter int, code, twin string) error {
	lines := len(splitLines(code))
	switch {
	case v.SinkLine < 1 || v.SinkLine > lines:
		return fmt.Errorf("%s: sink_line %d outside 1..%d", name, v.SinkLine, lines)
	case padAfter < 0 || padAfter >= v.SinkLine:
		return fmt.Errorf("%s: pad_after %d must be in 0..sink_line-1", name, padAfter)
	case v.Marker == "" || strings.Contains(v.Marker, placeholderMark):
		return fmt.Errorf("%s: marker must be literal text", name)
	case !strings.Contains(code, v.Marker):
		return fmt.Errorf("%s: marker %q not in its code", name, v.Marker)
	case strings.Contains(twin, v.Marker):
		return fmt.Errorf("%s: marker %q also in its twin", name, v.Marker)
	}
	return nil
}
