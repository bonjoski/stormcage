// Package sanitize provides high-level convenience methods for pre-flight context sanitization,
// neutralizing embedded WebSockets, localhost endpoints, and artificial delimiters.
package sanitize

import "github.com/bonjoski/stormcage/pkg/firewall"

// Result is an alias to firewall.SanitizerResult.
type Result = firewall.SanitizerResult

// DefaultSanitizer is the default PreFlightSanitizer instance.
var DefaultSanitizer = firewall.NewPreFlightSanitizer()

// Sanitize scans and neutralizes dangerous patterns in the input text.
func Sanitize(input string) *Result {
	return DefaultSanitizer.Sanitize(input)
}

// Neutralize returns the cleaned sanitized text with all injection vectors neutralized.
func Neutralize(input string) string {
	return DefaultSanitizer.Neutralize(input)
}
