package schema

import (
	"encoding/base64"
	"encoding/hex"
	"regexp"
	"strings"
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
	roleMarkersRegex = regexp.MustCompile(`(?i)(</?(?:system|admin|instruction|developer|prompt|context|assistant|user)>|\[/?(?:INSTRUCTION|SYSTEM|ADMIN|DEVELOPER)\]|<<SYS>>|<</SYS>>|<\|(?:im_start|im_end|system|user|assistant)\|>)`)
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

// StripInvisibleUnicode removes all zero-width characters, directional overrides, and Unicode tags.
// It also recovers smuggled Unicode tag characters (U+E0000 to U+E007F) which map directly to ASCII.
func StripInvisibleUnicode(input string) (string, int, []string) {
	// Apply Unicode Normalization Form KC (NFKC) to expand compatibility forms and decompose deceptive homoglyphs
	normalized := norm.NFKC.String(input)

	var sb strings.Builder
	strippedCount := 0
	var recoveredTagASCII strings.Builder

	for _, r := range normalized {
		// Unicode Tag Characters U+E0000 - U+E007F (Used in invisible ASCII prompt smuggling)
		if r >= 0xE0000 && r <= 0xE007F {
			strippedCount++
			asciiByte := rune(r - 0xE0000)
			if asciiByte >= 32 && asciiByte <= 126 {
				recoveredTagASCII.WriteRune(asciiByte)
			}
			continue
		}

		if invisibleRunes[r] {
			strippedCount++
			continue
		}

		sb.WriteRune(r)
	}

	recovered := []string{}
	if recoveredTagASCII.Len() > 0 {
		recovered = append(recovered, recoveredTagASCII.String())
	}

	return sb.String(), strippedCount, recovered
}

// FlattenInstructionMarkers strips markdown comments, HTML comments, and LLM role tags.
func FlattenInstructionMarkers(input string) (string, []string) {
	var markers []string

	// 1. Extract and strip HTML comments
	cleaned := htmlCommentRegex.ReplaceAllStringFunc(input, func(m string) string {
		markers = append(markers, m)
		// Extract inside comment for inspection
		inner := strings.TrimPrefix(m, "<!--")
		inner = strings.TrimSuffix(inner, "-->")
		return " " + strings.TrimSpace(inner) + " "
	})

	// 2. Extract and strip Markdown comments
	cleaned = mdCommentRegex.ReplaceAllStringFunc(cleaned, func(m string) string {
		markers = append(markers, m)
		return ""
	})

	// 3. Extract and sanitize role injection tags
	cleaned = roleMarkersRegex.ReplaceAllStringFunc(cleaned, func(m string) string {
		markers = append(markers, m)
		return ""
	})

	// 4. Flatten excessive markdown blockquote markers (e.g., "> > > ")
	blockquoteRegex := regexp.MustCompile(`(?m)^(\s*>\s*)+`)
	cleaned = blockquoteRegex.ReplaceAllString(cleaned, "")

	return strings.TrimSpace(cleaned), markers
}

// ExtractAndDecodePayloads discovers Base64 and Hex encoded payloads in the text,
// validating whether they decode to valid readable instructions.
func ExtractAndDecodePayloads(input string) []string {
	var decodedList []string
	seen := make(map[string]bool)

	// Check words / tokens for base64 candidates
	tokens := strings.Fields(input)
	for _, tok := range tokens {
		cleanTok := strings.Trim(tok, "\"',;:()[]{}<>`")
		if strings.HasPrefix(strings.ToLower(cleanTok), "base64:") {
			cleanTok = cleanTok[7:]
		}

		if len(cleanTok) >= 16 && len(cleanTok)%4 == 0 {
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

	// Check hex encoded payloads
	hexMatches := hexPayloadRegex.FindAllStringSubmatch(input, -1)
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

	return decodedList
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
