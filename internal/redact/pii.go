package redact

import (
	"regexp"
	"strings"
)

// Each pattern is LEAD(VALUE)TRAIL with one boundary character on each side,
// so a digit run inside a longer identifier or number does not match. find
// pads the text with newlines so the boundaries also hold at both ends.
var piiDetectors = []patternDetector{
	{
		label: "PII_EMAIL",
		re:    regexp.MustCompile(`[^A-Za-z0-9._%+-]([A-Za-z0-9._%+-]+@[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?)*\.[A-Za-z]{2,24})[^A-Za-z0-9-]`),
	},
	{
		label: "PII_CARD",
		re:    regexp.MustCompile(`[^0-9A-Za-z_.-]([2-6](?:[ -]?[0-9]){12,18})[^0-9A-Za-z_]`),
		valid: validCard,
	},
	{
		label: "PII_US_SSN",
		re:    regexp.MustCompile(`[^0-9A-Za-z_-]([0-9]{3}-[0-9]{2}-[0-9]{4})[^0-9A-Za-z_-]`),
		valid: validSSN,
	},
	{
		label: "PII_ES_DNI",
		re:    regexp.MustCompile(`[^0-9A-Za-z_]([0-9]{8}-?[A-Za-z])[^0-9A-Za-z_]`),
		valid: validDNI,
	},
	{
		label: "PII_ES_NIE",
		re:    regexp.MustCompile(`[^0-9A-Za-z_]([XYZxyz]-?[0-9]{7}-?[A-Za-z])[^0-9A-Za-z_]`),
		valid: validNIE,
	},
	{
		label: "PII_BR_CPF",
		re:    regexp.MustCompile(`[^0-9A-Za-z_.-]([0-9]{3}\.?[0-9]{3}\.?[0-9]{3}-?[0-9]{2})[^0-9A-Za-z_]`),
		valid: validCPF,
	},
}

func digitsOnly(s string) string {
	return strings.Map(func(r rune) rune {
		if r >= '0' && r <= '9' {
			return r
		}
		return -1
	}, s)
}

// validCard applies the Luhn checksum to 13 to 19 digits.
func validCard(s string) bool {
	d := digitsOnly(s)
	if len(d) < 13 || len(d) > 19 {
		return false
	}
	sum := 0
	for i := 0; i < len(d); i++ {
		n := int(d[len(d)-1-i] - '0')
		if i%2 == 1 {
			n *= 2
			if n > 9 {
				n -= 9
			}
		}
		sum += n
	}
	return sum%10 == 0
}

// validSSN rejects numbers the SSA never issues: area 000, 666 or 9xx,
// group 00, serial 0000.
func validSSN(s string) bool {
	area, group, serial := s[0:3], s[4:6], s[7:11]
	return area != "000" && area != "666" && area[0] != '9' && group != "00" && serial != "0000"
}

const dniLetters = "TRWAGMYFPDXBNJZSQVHLCKE"

// validDNI checks the Spanish DNI control letter: number mod 23.
func validDNI(s string) bool {
	return dniLetterOK(digitsOnly(s), s[len(s)-1])
}

// validNIE maps the X/Y/Z prefix to 0/1/2 and applies the DNI check.
func validNIE(s string) bool {
	prefix := strings.IndexByte("XYZ", upper(s[0]))
	return dniLetterOK(string(rune('0'+prefix))+digitsOnly(s), s[len(s)-1])
}

func dniLetterOK(digits string, letter byte) bool {
	n := 0
	for i := 0; i < len(digits); i++ {
		n = n*10 + int(digits[i]-'0')
	}
	return dniLetters[n%23] == upper(letter)
}

func upper(b byte) byte {
	if b >= 'a' && b <= 'z' {
		return b - 'a' + 'A'
	}
	return b
}

// validCPF checks both Brazilian CPF check digits and rejects repeated digits.
func validCPF(s string) bool {
	d := digitsOnly(s)
	if strings.Count(d, d[:1]) == len(d) {
		return false
	}
	return cpfDigit(d[:9]) == d[9] && cpfDigit(d[:10]) == d[10]
}

func cpfDigit(prefix string) byte {
	sum := 0
	weight := len(prefix) + 1
	for i := 0; i < len(prefix); i++ {
		sum += int(prefix[i]-'0') * (weight - i)
	}
	r := sum * 10 % 11
	if r == 10 {
		r = 0
	}
	return byte('0' + r)
}
