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
	Regex       *regexp.Regexp
	Weight      float64
	Description string
}

// OWASP LLM01 Injection Catalog: High-confidence static detection patterns.
var defaultInjectionRules = []InjectionRule{
	{
		ID:          "LLM01-001",
		Name:        "InstructionOverride",
		Regex:       regexp.MustCompile(`(?i)\b(?:ignore|disregard|forget|override|bypass)\s+(?:all\s+)?(?:previous|prior|above|former|system)\s+(?:instructions|directions|directives|commands|rules|prompts)`),
		Weight:      0.95,
		Description: "Imperative command to disregard previous system instructions",
	},
	{
		ID:          "LLM01-002",
		Name:        "RoleHijackJailbreak",
		Regex:       regexp.MustCompile(`(?i)\b(?:you\s+are\s+now|act\s+as|pretend\s+to\s+be)\s+(?:an?\s+)?(?:unrestricted|jailbroken|dan|developer\s+mode|god\s+mode|root\s+user|admin|system\s+administrator)`),
		Weight:      0.90,
		Description: "Persona hijacking or LLM jailbreak simulation directive",
	},
	{
		ID:          "LLM01-003",
		Name:        "DangerousShellExecution",
		Regex:       regexp.MustCompile(`(?i)(?:run\s+(?:bash|sh)\s+-c|bash\s+-c|curl\s+.*?\|\s*(?:bash|sh)|rm\s+-rf\s+[/~]|chmod\s+777|cat\s+/etc/passwd|nc\s+-e\s+/bin/(?:ba)?sh)`),
		Weight:      0.98,
		Description: "Direct invocation of destructive shell commands or reverse shells",
	},
	{
		ID:          "LLM01-004",
		Name:        "CredentialExfiltration",
		Regex:       regexp.MustCompile(`(?i)\b(?:exfiltrate|send|post|upload)\s+(?:all\s+)?(?:credentials|keys|tokens|passwords|env|secrets|\.env)\s+to\b`),
		Weight:      0.95,
		Description: "Imperative command instructing data/secret exfiltration",
	},
	{
		ID:          "LLM01-005",
		Name:        "SystemDelimiterSmuggling",
		Regex:       regexp.MustCompile(`(?i)(?:\[(?:system|instruction|admin)\]|<<SYS>>|<\|im_start\|>system|\[SYSTEM_OVERRIDE\]|<system>)`),
		Weight:      0.85,
		Description: "Boundary delimiter spoofing or fake system header injection",
	},
	{
		ID:          "LLM01-006",
		Name:        "ImperativeNewDirective",
		Regex:       regexp.MustCompile(`(?i)\b(?:from\s+now\s+on\s+you\s+must|new\s+(?:instruction|directive|rule):\s*(?:execute|run|delete|exfiltrate|bypass))\b`),
		Weight:      0.90,
		Description: "New imperative priority override directive",
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
	norm := schema.Normalize(content)

	matchedMap := make(map[string]bool)
	var matchedRules []string
	var details []string
	maxWeight := 0.0

	// 1. Check raw and cleaned content against injection rules
	targets := []string{content, norm.Cleaned}
	// Also inspect extracted/decoded payloads (e.g. from Base64 or Unicode Tag characters)
	targets = append(targets, norm.DecodedPayloads...)

	for _, text := range targets {
		if strings.TrimSpace(text) == "" {
			continue
		}
		for _, rule := range d.rules {
			if rule.Regex.MatchString(text) {
				if !matchedMap[rule.ID] {
					matchedMap[rule.ID] = true
					matchedRules = append(matchedRules, rule.ID)
					details = append(details, rule.Name+": "+rule.Description)
					if rule.Weight > maxWeight {
						maxWeight = rule.Weight
					}
				}
			}
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
