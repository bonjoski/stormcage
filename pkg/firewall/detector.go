package firewall

import (
	"regexp"
	"strings"

	"github.com/bonjoski/stormcage/pkg/schema"
)

// InjectionRule defines a pattern-based rule for catching OWASP LLM01 Prompt Injection attacks.
type InjectionRule struct {
	ID          string
	Name        string
	Keywords    []string
	Regex       *regexp.Regexp
	Weight      float64
	Description string
}

// OWASP LLM01 Injection Catalog: High-confidence static detection patterns.
var defaultInjectionRules = []InjectionRule{
	{
		ID:          "LLM01-001",
		Name:        "InstructionOverride",
		Keywords:    []string{"ignore", "disregard", "forget", "override", "bypass"},
		Regex:       regexp.MustCompile(`(?i)\b(?:ignore|disregard|forget|override|bypass)\s+(?:all\s+)?(?:previous|prior|above|former|system)\s+(?:instructions|directions|directives|commands|rules|prompts)`),
		Weight:      0.95,
		Description: "Imperative command to disregard previous system instructions",
	},
	{
		ID:          "LLM01-002",
		Name:        "RoleHijackJailbreak",
		Keywords:    []string{"unrestricted", "jailbroken", "dan", "developer", "god", "root", "admin"},
		Regex:       regexp.MustCompile(`(?i)\b(?:you\s+are\s+now|act\s+as|pretend\s+to\s+be)\s+(?:an?\s+)?(?:unrestricted|jailbroken|dan|developer\s+mode|god\s+mode|root\s+user|admin|system\s+administrator)`),
		Weight:      0.90,
		Description: "Persona hijacking or LLM jailbreak simulation directive",
	},
	{
		ID:          "LLM01-003",
		Name:        "DangerousShellExecution",
		Keywords:    []string{"bash", " -c", "\t-c", "curl", "rm ", "rm\t", "chmod", "/etc/passwd", "/bin/sh", "/bin/bash"},
		Regex:       regexp.MustCompile(`(?i)(?:run\s+(?:bash|sh)\s+-c|bash\s+-c|curl\s+[^\n|]{1,512}\|\s*(?:bash|sh)|rm\s+-rf\s+[/~]|chmod\s+777|cat\s+/etc/passwd|nc\s+-e\s+/bin/(?:ba)?sh)`),
		Weight:      0.98,
		Description: "Direct invocation of destructive shell commands or reverse shells",
	},
	{
		ID:          "LLM01-004",
		Name:        "CredentialExfiltration",
		Keywords:    []string{"exfiltrate", "credentials", "keys", "tokens", "passwords", " env", "\tenv", "secrets", ".env"},
		Regex:       regexp.MustCompile(`(?i)\b(?:exfiltrate|send|post|upload)\s+(?:all\s+)?(?:credentials|keys|tokens|passwords|env|secrets|\.env)\s+to\b`),
		Weight:      0.95,
		Description: "Imperative command instructing data/secret exfiltration",
	},
	{
		ID:          "LLM01-005",
		Name:        "SystemDelimiterSmuggling",
		Keywords:    []string{"[system", "[instruction]", "[admin]", "<<sys>>", "<|im_start|>", "<system>"},
		Regex:       regexp.MustCompile(`(?i)(?:\[(?:system|instruction|admin)\]|<<SYS>>|<\|im_start\|>system|\[SYSTEM_OVERRIDE\]|<system>)`),
		Weight:      0.85,
		Description: "Boundary delimiter spoofing or fake system header injection",
	},
	{
		ID:          "LLM01-006",
		Name:        "ImperativeNewDirective",
		Keywords:    []string{"from now", "from\tnow", "from\nnow", "instruction", "directive", "rule:"},
		Regex:       regexp.MustCompile(`(?i)\b(?:from\s+now\s+on\s+you\s+must|new\s+(?:instruction|directive|rule):\s*(?:execute|run|delete|exfiltrate|bypass))\b`),
		Weight:      0.90,
		Description: "New imperative priority override directive",
	},
	{
		ID:          "LLM01-007",
		Name:        "LocalhostWebSocketPivot",
		Keywords:    []string{"ws://", "wss://", "127.", "0.0.0.0", "localhost", "::1", "169.254.169.254", "fd00:ec2", "::ffff:"},
		Regex:       regexp.MustCompile(`(?i)(?:wss?:\/\/[a-z0-9_.\-:\[\]]+|(?:https?|tcp|udp):\/\/(?:127(?:\.\d+)+|0\.0\.0\.0|localhost|\[::1\]|\[::ffff:(?:127(?:\.\d+)+|169\.254\.169\.254)\]|\[fd00:ec2::254\]|169\.254\.169\.254)(?::\d+)?|\b(?:127(?:\.\d+)+|0\.0\.0\.0|localhost|\[::1\]|169\.254\.169\.254):(8080|8088|9090|9191|2375|2376|4243|11434)\b)`),
		Weight:      0.98,
		Description: "WebSocket or localhost loopback pivoting targeting local control plane interfaces (OpenClaw CVE-2026-25253)",
	},
	{
		ID:          "LLM01-008",
		Name:        "ArtificialDelimiterInjection",
		Keywords:    []string{"openclaw", "control_panel", "system_override", "root_exec", "system_", "admin_", "tool_call", "tool_response", "function_call", "call_tool"},
		Regex:       regexp.MustCompile(`(?i)(?:<\/?(?:openclaw_execute|control_panel|system_override|root_exec|openclaw_[a-z0-9_-]+|system_[a-z0-9_-]+|admin_[a-z0-9_-]+|tool_call|tool_response|tool_results|function_call|call_tool|result|observation|thought|antml)(?:\s+[^>]*)?>|\[\/?(?:SYSTEM_OVERRIDE|ROOT_EXEC|CONTROL_PANEL|OPENCLAW_EXECUTE|ADMIN_OVERRIDE|SYSTEM_INSTRUCTION)\]|\{\{\s*\/?(?:control_panel|system_override|root_exec|openclaw_execute)[^}]*\}\}|\{%\s*(?:control_panel|system_override|root_exec|openclaw_execute)[^%]*%\})`),
		Weight:      0.95,
		Description: "Artificial prompt-injection delimiter, tool reflection, or execution envelope smuggling",
	},
}

// DetectionResult encapsulates the output of prompt injection evaluation.
type DetectionResult struct {
	IsInjected    bool
	Confidence    float64
	MatchedRuleIDs []string
	Reason        string
	Details       []string
}

// Detector scans content using static pattern rules and AST normalization.
type Detector struct {
	rules []InjectionRule
}

// NewDetector initializes a prompt injection detector with standard rules.
func NewDetector() *Detector {
	return &Detector{
		rules: defaultInjectionRules,
	}
}

// Scan examines the target content, its normalized form, and any hidden decoded payloads.
func (d *Detector) Scan(content string) *DetectionResult {
	return d.ScanNormalized(content, schema.Normalize(content))
}

// ScanNormalized evaluates already-normalized content to avoid redundant AST/Unicode normalization passes.
func (d *Detector) ScanNormalized(content string, norm *schema.NormalizationResult) *DetectionResult {
	if norm == nil {
		norm = schema.Normalize(content)
	}

	matchedMap := make(map[string]bool)
	var matchedRules []string
	var details []string
	maxWeight := 0.0

	// 1. Check raw and (if distinct) cleaned content against injection rules
	targets := []string{content}
	if norm.Cleaned != content {
		targets = append(targets, norm.Cleaned)
	}
	// Also inspect extracted/decoded payloads (e.g. from Base64 or Unicode Tag characters)
	targets = append(targets, norm.DecodedPayloads...)

	scanChunk := func(chunk string) {
		if chunk == "" {
			return
		}
		lowerChunk := strings.ToLower(chunk)
		for _, rule := range d.rules {
			if matchedMap[rule.ID] {
				continue
			}
			if len(rule.Keywords) > 0 && !containsAnyKeyword(lowerChunk, rule.Keywords) {
				continue
			}
			if rule.Regex.MatchString(chunk) {
				matchedMap[rule.ID] = true
				matchedRules = append(matchedRules, rule.ID)
				details = append(details, rule.Name+": "+rule.Description)
				if rule.Weight > maxWeight {
					maxWeight = rule.Weight
				}
			}
		}
	}

	for _, text := range targets {
		if len(matchedRules) == len(d.rules) {
			break
		}
		if strings.TrimSpace(text) == "" {
			continue
		}
		// For large multi-line inputs (>4KB, e.g. git diffs), stream 2-line windows directly using
		// slice sub-indexing (zero string concatenation allocations!) so multi-line injections are
		// caught without O(N) RE2 NFA stalls under -race.
		if len(text) > 4096 && strings.IndexByte(text, '\n') >= 0 {
			lineStart := 0
			n := len(text)
			for lineStart < n {
				nl1 := strings.IndexByte(text[lineStart:], '\n')
				if nl1 < 0 {
					scanChunk(text[lineStart:])
					break
				}
				nextLineStart := lineStart + nl1 + 1
				windowEnd := n
				if nextLineStart < n {
					if nl2 := strings.IndexByte(text[nextLineStart:], '\n'); nl2 >= 0 {
						windowEnd = nextLineStart + nl2
					}
				} else {
					windowEnd = lineStart + nl1
				}
				scanChunk(text[lineStart:windowEnd])
				lineStart = nextLineStart
			}
		} else {
			scanChunk(text)
		}
	}

	// 2. Check for cloaking evasion anomalies (high count of zero-width or hidden tags)
	if norm.StrippedRunes > 5 && len(norm.DecodedPayloads) > 0 {
		details = append(details, "High-density invisible Unicode combined with embedded payload")
		if maxWeight < 0.85 {
			maxWeight = 0.85
		}
	}

	isInjected := len(matchedRules) > 0 || maxWeight >= 0.85
	reason := ""
	if isInjected {
		reason = "imperative_injection_detected"
	}

	return &DetectionResult{
		IsInjected:    isInjected,
		Confidence:    maxWeight,
		MatchedRuleIDs: matchedRules,
		Reason:        reason,
		Details:       details,
	}
}

func containsAnyKeyword(lowerText string, keywords []string) bool {
	for _, kw := range keywords {
		if strings.Contains(lowerText, kw) {
			return true
		}
	}
	return false
}
