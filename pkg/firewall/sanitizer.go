package firewall

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/bonjoski/stormcage/pkg/schema"
)

// SanitizerResult details the outcome of pre-flight context sanitization.
type SanitizerResult struct {
	Original              string   `json:"original"`
	Cleaned               string   `json:"cleaned"`
	WebSocketNeutralized  int      `json:"websocket_neutralized"`
	LocalhostNeutralized  int      `json:"localhost_neutralized"`
	DelimitersNeutralized int      `json:"delimiters_neutralized"`
	TotalNeutralized      int      `json:"total_neutralized"`
	NeutralizedItems      []string `json:"neutralized_items,omitempty"`
}

var (
	// WebSocket URIs (ws:// and wss://)
	wsURIRegex = regexp.MustCompile(`(?i)\b(?:wss?):\/\/[^\s"'<>\` + "`" + `()]+`)

	// Localhost and Cloud Metadata endpoints (URLs and host:port pairs)
	localhostURLRegex = regexp.MustCompile(`(?i)\b(?:https?|tcp|udp|ftp):\/\/(?:127(?:\.[0-9]{1,3}){1,3}|0\.0\.0\.0|localhost|\[::1\]|\[::ffff:(?:127(?:\.[0-9]{1,3}){3}|169\.254\.169\.254)\]|\[fd00:ec2::254\]|169\.254\.169\.254)(?::[0-9]+)?(?:\/[^\s"'<>\` + "`" + `()]*)?`)
	localhostTargetRegex = regexp.MustCompile(`(?i)(?:\b(?:127(?:\.[0-9]{1,3}){1,3}|0\.0\.0\.0|localhost|169\.254\.169\.254)(?::[0-9]+)?\b|\[::1\](?::[0-9]+)?|\[::ffff:(?:127(?:\.[0-9]{1,3}){3}|169\.254\.169\.254)\](?::[0-9]+)?|\[fd00:ec2::254\](?::[0-9]+)?|(?:::1:[0-9]+)\b)`)

	// Artificial prompt-injection delimiters
	xmlDelimiterRegex = regexp.MustCompile(`(?i)<\/?(?:untrusted_artifact|untrusted_code_artifact|untrusted_external_artifact|untrusted_[a-z0-9_-]+|openclaw_execute|control_panel|system_override|root_exec|openclaw_[a-z0-9_-]+|system_[a-z0-9_-]+|admin_[a-z0-9_-]+|system|admin|instruction|developer|prompt|context|assistant|user)(?:\s+[^>]*)?>`)
	bracketDelimiterRegex = regexp.MustCompile(`(?i)\[\/?(?:SYSTEM_OVERRIDE|ROOT_EXEC|CONTROL_PANEL|OPENCLAW_EXECUTE|ADMIN_OVERRIDE|SYSTEM_INSTRUCTION)\]`)
	templateDelimiterRegex = regexp.MustCompile(`(?i)(?:\{\{\s*\/?(?:control_panel|system_override|root_exec|openclaw_execute|system|admin)[^}]*\}\}|\{%\s*(?:control_panel|system_override|root_exec|openclaw_execute|system|admin)[^%]*%\})`)
)

// PreFlightSanitizer detects and neutralizes embedded WebSockets, localhost/loopback targets,
// and artificial prompt injection delimiters (OpenClaw CVE-2026-25253 mitigation).
type PreFlightSanitizer struct {
	wsRegex              *regexp.Regexp
	localhostURLRegex    *regexp.Regexp
	localhostTargetRegex *regexp.Regexp
	xmlDelimiterRegex    *regexp.Regexp
	bracketRegex         *regexp.Regexp
	templateRegex        *regexp.Regexp
}

// NewPreFlightSanitizer initializes a PreFlightSanitizer with standard mitigation patterns.
func NewPreFlightSanitizer() *PreFlightSanitizer {
	return &PreFlightSanitizer{
		wsRegex:              wsURIRegex,
		localhostURLRegex:    localhostURLRegex,
		localhostTargetRegex: localhostTargetRegex,
		xmlDelimiterRegex:    xmlDelimiterRegex,
		bracketRegex:         bracketDelimiterRegex,
		templateRegex:        templateDelimiterRegex,
	}
}

// Sanitize scans and neutralizes dangerous patterns in the input text.
func (s *PreFlightSanitizer) Sanitize(input string) *SanitizerResult {
	// 1. NFKC normalization and zero-width rune stripping to prevent cloaked bypassing
	normalized, _, _ := schema.StripInvisibleUnicode(input)

	result := &SanitizerResult{
		Original: input,
	}

	cleaned := normalized

	// 2. Strip Artificial Delimiters FIRST (iteratively replacing with " " so removed tags
	// can never fuse split tokens like `ws:<admin_x>//127.0.0.1` or `<<openclaw_execute>openclaw_execute>`).
	if strings.IndexByte(cleaned, '<') >= 0 || strings.IndexByte(cleaned, '[') >= 0 || strings.IndexByte(cleaned, '{') >= 0 {
		for pass := 0; pass < 8; pass++ {
			before := cleaned
			if strings.IndexByte(cleaned, '<') >= 0 {
				cleaned = s.xmlDelimiterRegex.ReplaceAllStringFunc(cleaned, func(m string) string {
					result.DelimitersNeutralized++
					result.NeutralizedItems = append(result.NeutralizedItems, m)
					return " "
				})
			}
			if strings.IndexByte(cleaned, '[') >= 0 {
				cleaned = s.bracketRegex.ReplaceAllStringFunc(cleaned, func(m string) string {
					result.DelimitersNeutralized++
					result.NeutralizedItems = append(result.NeutralizedItems, m)
					return " "
				})
			}
			if strings.IndexByte(cleaned, '{') >= 0 {
				cleaned = s.templateRegex.ReplaceAllStringFunc(cleaned, func(m string) string {
					result.DelimitersNeutralized++
					result.NeutralizedItems = append(result.NeutralizedItems, m)
					return " "
				})
			}
			if cleaned == before {
				break
			}
		}
	}

	lowerCleaned := strings.ToLower(cleaned)

	// 3. Neutralize WebSocket URIs (ws://, wss://)
	if strings.Contains(lowerCleaned, "ws://") || strings.Contains(lowerCleaned, "wss://") {
		cleaned = s.wsRegex.ReplaceAllStringFunc(cleaned, func(m string) string {
			result.WebSocketNeutralized++
			lowerM := strings.ToLower(m)
			if strings.Contains(lowerM, "127.") ||
				strings.Contains(lowerM, "0.0.0.0") ||
				strings.Contains(lowerM, "localhost") ||
				strings.Contains(lowerM, "[::1]") ||
				strings.Contains(lowerM, "fd00:ec2::254") ||
				strings.Contains(lowerM, "169.254.169.254") {
				result.LocalhostNeutralized++
			}
			result.NeutralizedItems = append(result.NeutralizedItems, m)
			return "[DEFANGED_WEBSOCKET_URI]"
		})
		lowerCleaned = strings.ToLower(cleaned)
	}

	hasLocalTarget := strings.Contains(lowerCleaned, "127.") ||
		strings.Contains(lowerCleaned, "0.0.0.0") ||
		strings.Contains(lowerCleaned, "localhost") ||
		strings.Contains(lowerCleaned, "::1") ||
		strings.Contains(lowerCleaned, "169.254.169.254") ||
		strings.Contains(lowerCleaned, "fd00:ec2") ||
		strings.Contains(lowerCleaned, "::ffff:")

	if hasLocalTarget {
		// 4. Neutralize Localhost & Cloud Metadata URLs
		cleaned = s.localhostURLRegex.ReplaceAllStringFunc(cleaned, func(m string) string {
			result.LocalhostNeutralized++
			result.NeutralizedItems = append(result.NeutralizedItems, m)
			return "[DEFANGED_LOCAL_ENDPOINT]"
		})

		// 5. Neutralize Bare Localhost & Cloud Metadata targets
		cleaned = s.localhostTargetRegex.ReplaceAllStringFunc(cleaned, func(m string) string {
			result.LocalhostNeutralized++
			result.NeutralizedItems = append(result.NeutralizedItems, m)
			return "[DEFANGED_LOCAL_ENDPOINT]"
		})
	}

	result.Cleaned = strings.TrimSpace(cleaned)
	result.TotalNeutralized = result.WebSocketNeutralized + result.LocalhostNeutralized + result.DelimitersNeutralized

	return result
}

// Neutralize returns the sanitized string directly.
func (s *PreFlightSanitizer) Neutralize(input string) string {
	res := s.Sanitize(input)
	return res.Cleaned
}

// FenceUntrustedArtifact wraps untrusted content inside strict <untrusted_artifact> boundary fences
// after stripping zero-width runes and neutralizing prompt injection delimiters.
func (s *PreFlightSanitizer) FenceUntrustedArtifact(input string) string {
	cleaned := s.Neutralize(input)
	return fmt.Sprintf("<untrusted_artifact>\n%s\n</untrusted_artifact>", cleaned)
}

// FenceUntrustedArtifact wraps untrusted content inside strict <untrusted_artifact> boundary fences.
func FenceUntrustedArtifact(input string) string {
	return NewPreFlightSanitizer().FenceUntrustedArtifact(input)
}
