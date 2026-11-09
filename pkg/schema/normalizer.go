package schema

import (
	"encoding/base64"
	"encoding/hex"
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"

	"golang.org/x/text/unicode/norm"
)

// Zero-width and invisible control runes commonly weaponized for cloaked prompt injection.
var invisibleRunes = map[rune]bool{
	'\u200B': true, // Zero-width space
	'\u200C': true, // Zero-width non-joiner
	'\u200D': true, // Zero-width joiner
	'\uFEFF': true, // Zero-width no-break space / BOM
	'\u00AD': true, // Soft hyphen
	'\u200E': true, // Left-to-Right mark
	'\u200F': true, // Right-to-Left mark
	'\u202A': true, // LRE
	'\u202B': true, // RLE
	'\u202C': true, // PDF
	'\u202D': true, // LRO
	'\u202E': true, // RLO (Right-to-Left override)
	'\u2060': true, // Word joiner
	'\u2061': true, // Function application
	'\u2062': true, // Invisible times
	'\u2063': true, // Invisible separator
	'\u2064': true, // Invisible plus
	'\u2066': true, // LRI
	'\u2067': true, // RLI
	'\u2068': true, // FSI
	'\u2069': true, // PDI
}

// Regex patterns for HTML/Markdown instruction markers and role hijack tags.
var (
	htmlCommentRegex = regexp.MustCompile(`(?s)<!--.*?-->`)
	mdCommentRegex   = regexp.MustCompile(`(?m)^\[//\]:\s*#\s*\((.*?)\)$`)
	roleMarkersRegex = regexp.MustCompile(`(?i)(</?(?:system|admin|instruction|developer|prompt|context|assistant|user|openclaw_execute|control_panel|system_override|root_exec|openclaw_[a-z0-9_-]+|system_[a-z0-9_-]+|admin_[a-z0-9_-]+)(?:\s+[^>]*)?>|\[/?(?:INSTRUCTION|SYSTEM|ADMIN|DEVELOPER|SYSTEM_OVERRIDE|ROOT_EXEC|CONTROL_PANEL|OPENCLAW_EXECUTE|ADMIN_OVERRIDE|SYSTEM_INSTRUCTION)\]|<<SYS>>|<</SYS>>|<\|(?:im_start|im_end|system|user|assistant)\|>|\{\{\s*/?(?:control_panel|system_override|root_exec|openclaw_execute|system|admin)[^}]*\}\}|\{%\s*(?:control_panel|system_override|root_exec|openclaw_execute|system|admin)[^%]*%\})`)
	blockquoteRegex  = regexp.MustCompile(`(?m)^(\s*>\s*)+`)
	lineContRegex    = regexp.MustCompile(`\\\r?\n`)
	hexPayloadRegex  = regexp.MustCompile(`(?i)(?:0x|\\x)([0-9a-f]{2,})`)
)

// NormalizationResult holds the cleaned AST text along with security telemetry.
type NormalizationResult struct {
	Original         string   `json:"original"`
	Cleaned          string   `json:"cleaned"`
	StrippedRunes    int      `json:"stripped_runes_count"`
	MarkersFound     []string `json:"markers_found"`
	DecodedPayloads  []string `json:"decoded_payloads"`
	UnwrappedContent []string `json:"unwrapped_content"`
}

func isPlainVisibleASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		b := s[i]
		if b >= 0x7F {
			return false
		}
		if b < 0x20 && b != '\n' && b != '\r' && b != '\t' {
			return false
		}
	}
	return true
}

// StripInvisibleUnicode removes all zero-width characters, directional overrides, and Unicode tags.
// It also recovers smuggled Unicode tag characters (U+E0000 to U+E007F) which map directly to ASCII.
func StripInvisibleUnicode(input string) (string, int, []string) {
	// Fast path: pure printable ASCII contains no NFKC compatibility mappings, invisible runes, or tag chars.
	if isPlainVisibleASCII(input) {
		return input, 0, nil
	}

	// ASCII '\n' (U+000A) is an UAX #15 starter boundary (ccc=0, NFKC_QC=Yes).
	// Normalizing only lines that contain non-ASCII/control bytes avoids O(N) NFKC table scans
	// across large predominantly-ASCII files (e.g. git diffs) while producing identical output.
	var sb strings.Builder
	sb.Grow(len(input))
	strippedCount := 0
	var recoveredTagASCII strings.Builder

	start := 0
	for start <= len(input) {
		nlIdx := strings.IndexByte(input[start:], '\n')
		var line string
		hasNewline := false
		if nlIdx >= 0 {
			line = input[start : start+nlIdx]
			hasNewline = true
			start += nlIdx + 1
		} else {
			line = input[start:]
			start = len(input) + 1
		}

		if isPlainVisibleASCII(line) {
			sb.WriteString(line)
		} else {
			normalizedLine := norm.NFKC.String(line)
			for _, r := range normalizedLine {
				// Unicode Tag Characters U+E0000 - U+E007F (Used in invisible ASCII prompt smuggling)
				if r >= 0xE0000 && r <= 0xE007F {
					strippedCount++
					asciiByte := rune(r - 0xE0000)
					if asciiByte >= 32 && asciiByte <= 126 {
						recoveredTagASCII.WriteRune(asciiByte)
					}
					continue
				}
				if isInvisibleOrCloakingRune(r) {
					strippedCount++
					continue
				}
				sb.WriteRune(r)
			}
		}

		if hasNewline {
			sb.WriteByte('\n')
		}
	}

	var recovered []string
	if recoveredTagASCII.Len() > 0 {
		recovered = append(recovered, recoveredTagASCII.String())
	}

	return sb.String(), strippedCount, recovered
}

func isInvisibleOrCloakingRune(r rune) bool {
	if invisibleRunes[r] {
		return true
	}
	// Unicode Format control characters (Cf) — includes zero-width, bidi overrides, soft hyphen, etc.
	if unicode.Is(unicode.Cf, r) {
		return true
	}
	// Variation Selectors (U+FE00..U+FE0F), Variation Selectors Supplement (U+E0100..U+E01EF),
	// Mongolian Free Variation Selectors (U+180B..U+180E), Combining Grapheme Joiner (U+034F),
	// and invisible Hangul / Khmer fillers used for token-splitting prompt evasion.
	if (r >= 0xFE00 && r <= 0xFE0F) ||
		(r >= 0xE0100 && r <= 0xE01EF) ||
		(r >= 0x180B && r <= 0x180E) ||
		r == 0x034F ||
		r == 0x115F || r == 0x1160 || r == 0x3164 || r == 0xFFA0 ||
		r == 0x17B4 || r == 0x17B5 {
		return true
	}
	return false
}

var roleMarkerHints = []string{
	"system", "admin", "instruction", "developer", "prompt",
	"context", "assistant", "user", "openclaw", "control_panel",
	"root_exec", "<<sys>>", "<|im_",
}

func hasRoleMarkerHint(lower string) bool {
	for _, h := range roleMarkerHints {
		if strings.Contains(lower, h) {
			return true
		}
	}
	return false
}

func hasBlockquoteStart(s string) bool {
	atLineStart := true
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '\n':
			atLineStart = true
		case ' ', '\t', '\r':
			// remain at line start if still leading whitespace
		case '>':
			if atLineStart {
				return true
			}
		default:
			atLineStart = false
		}
	}
	return false
}

// FlattenInstructionMarkers strips markdown comments, HTML comments, and LLM role tags.
func FlattenInstructionMarkers(input string) (string, []string) {
	var markers []string
	cleaned := input

	// 1. Extract and strip HTML comments
	if strings.Contains(cleaned, "<!--") && strings.Contains(cleaned, "-->") {
		cleaned = htmlCommentRegex.ReplaceAllStringFunc(cleaned, func(m string) string {
			markers = append(markers, m)
			inner := strings.TrimPrefix(m, "<!--")
			inner = strings.TrimSuffix(inner, "-->")
			return " " + strings.TrimSpace(inner) + " "
		})
	}

	// 2. Extract and strip Markdown comments
	if strings.Contains(cleaned, "[//]:") {
		cleaned = mdCommentRegex.ReplaceAllStringFunc(cleaned, func(m string) string {
			markers = append(markers, m)
			return ""
		})
	}

	// 3. Extract and sanitize role injection tags (line-scoped fast path + iterative nested tag stripping)
	if (strings.IndexByte(cleaned, '<') >= 0 || strings.IndexByte(cleaned, '[') >= 0 || strings.IndexByte(cleaned, '{') >= 0) &&
		hasRoleMarkerHint(strings.ToLower(cleaned)) {
		lines := strings.Split(cleaned, "\n")
		changedAny := false
		for i, ln := range lines {
			if (strings.IndexByte(ln, '<') >= 0 || strings.IndexByte(ln, '[') >= 0 || strings.IndexByte(ln, '{') >= 0) &&
				hasRoleMarkerHint(strings.ToLower(ln)) {
				cur := ln
				for pass := 0; pass < 8; pass++ {
					matched := false
					cur = roleMarkersRegex.ReplaceAllStringFunc(cur, func(m string) string {
						matched = true
						changedAny = true
						markers = append(markers, m)
						return " "
					})
					if !matched {
						break
					}
				}
				lines[i] = cur
			}
		}
		if changedAny {
			cleaned = strings.Join(lines, "\n")
		}
	}

	// 4. Collapse shell backslash-newline continuations and excessive markdown blockquote markers
	if strings.Contains(cleaned, "\\\n") || strings.Contains(cleaned, "\\\r\n") {
		cleaned = lineContRegex.ReplaceAllString(cleaned, "")
	}
	if hasBlockquoteStart(cleaned) {
		cleaned = blockquoteRegex.ReplaceAllString(cleaned, "")
	}

	return strings.TrimSpace(cleaned), markers
}

// ExtractAndDecodePayloads discovers Base64 and Hex encoded payloads in the text,
// validating whether they decode to valid readable instructions.
func ExtractAndDecodePayloads(input string) []string {
	var decodedList []string
	seen := make(map[string]bool)

	// Zero-alloc token scan: only inspect whitespace-delimited tokens of length >= 16
	n := len(input)
	i := 0
	for i < n {
		for i < n && (input[i] == ' ' || input[i] == '\t' || input[i] == '\n' || input[i] == '\r') {
			i++
		}
		start := i
		for i < n && input[i] != ' ' && input[i] != '\t' && input[i] != '\n' && input[i] != '\r' {
			i++
		}
		if i-start < 16 {
			continue
		}
		cleanTok := strings.Trim(input[start:i], "\"',;:()[]{}<>`")
		if len(cleanTok) >= 23 && (cleanTok[0] == 'b' || cleanTok[0] == 'B') && strings.EqualFold(cleanTok[:7], "base64:") {
			cleanTok = cleanTok[7:]
		}
		if len(cleanTok) >= 16 && len(cleanTok)%4 == 0 && isBase64Candidate(cleanTok) {
			if data, err := base64.StdEncoding.DecodeString(cleanTok); err == nil {
				if utf8.Valid(data) && isMostlyPrintable(data) {
					decoded := strings.TrimSpace(string(data))
					if len(decoded) > 3 && !seen[decoded] {
						seen[decoded] = true
						decodedList = append(decodedList, decoded)
					}
				}
			}
		}
	}

	// Check hex encoded payloads only on lines containing a hex prefix followed by >= 8 hex chars
	if strings.Contains(input, "0x") || strings.Contains(input, "0X") || strings.Contains(input, `\x`) || strings.Contains(input, `\X`) {
		start := 0
		for start <= n {
			nl := strings.IndexByte(input[start:], '\n')
			var line string
			if nl >= 0 {
				line = input[start : start+nl]
				start += nl + 1
			} else {
				line = input[start:]
				start = n + 1
			}
			if !strings.Contains(line, "0x") && !strings.Contains(line, "0X") && !strings.Contains(line, `\x`) && !strings.Contains(line, `\X`) {
				continue
			}
			hexMatches := hexPayloadRegex.FindAllStringSubmatch(line, -1)
			for _, match := range hexMatches {
				if len(match) > 1 {
					hexStr := match[1]
					if len(hexStr)%2 == 0 && len(hexStr) >= 8 {
						if data, err := hex.DecodeString(hexStr); err == nil {
							if utf8.Valid(data) && isMostlyPrintable(data) {
								decoded := strings.TrimSpace(string(data))
								if len(decoded) > 3 && !seen[decoded] {
									seen[decoded] = true
									decodedList = append(decodedList, decoded)
								}
							}
						}
					}
				}
			}
		}
	}

	return decodedList
}

func isBase64Candidate(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '+' || c == '/' || c == '=') {
			return false
		}
	}
	return true
}

func isMostlyPrintable(data []byte) bool {
	if len(data) == 0 {
		return false
	}
	printable := 0
	for _, b := range data {
		if (b >= 32 && b <= 126) || b == '\n' || b == '\r' || b == '\t' {
			printable++
		}
	}
	return float64(printable)/float64(len(data)) > 0.85
}

// Normalize cleans and normalizes content, stripping cloaking attempts and recovering hidden payloads.
func Normalize(input string) *NormalizationResult {
	// Step 1: Strip zero-width & invisible unicode and apply NFKC normalization
	withoutUnicode, strippedCount, recoveredTagASCII := StripInvisibleUnicode(input)

	// Step 2: Flatten HTML / Markdown instruction markers
	cleaned, markers := FlattenInstructionMarkers(withoutUnicode)

	// Step 3: Decode embedded Base64/Hex payloads
	decoded := ExtractAndDecodePayloads(withoutUnicode)
	decoded = append(decoded, recoveredTagASCII...)

	return &NormalizationResult{
		Original:         input,
		Cleaned:          cleaned,
		StrippedRunes:    strippedCount,
		MarkersFound:     markers,
		DecodedPayloads:  decoded,
		UnwrappedContent: recoveredTagASCII,
	}
}

// SanitizeText returns the normalized clean text with all cloaking and injection markers neutralized.
func SanitizeText(input string) string {
	res := Normalize(input)
	return res.Cleaned
}
