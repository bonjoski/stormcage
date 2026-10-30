package taint

import (
	"errors"
	"fmt"
	"strings"
	"time"
)

// TaintLevel defines the provenance security classification of context data.
type TaintLevel string

const (
	// TRUST_LOCAL_WORKSPACE represents verified local source code and authorized local configuration.
	TRUST_LOCAL_WORKSPACE TaintLevel = "TRUST_LOCAL_WORKSPACE"
	// TAINT_EXTERNAL_USER represents data originating from PR comments, issue descriptions, or external user chat.
	TAINT_EXTERNAL_USER TaintLevel = "TAINT_EXTERNAL_USER"
	// TAINT_UNTRUSTED_WEB represents web crawls, scraper output, documentation, and external API responses.
	TAINT_UNTRUSTED_WEB TaintLevel = "TAINT_UNTRUSTED_WEB"
)

// PrivilegeLevel defines the tool execution capability of a receiving agent.
type PrivilegeLevel string

const (
	PRIVILEGE_LOW    PrivilegeLevel = "LOW"    // Read-only analysis, indexing, planning
	PRIVILEGE_MEDIUM PrivilegeLevel = "MEDIUM" // Sandboxed code modification, unit test execution
	PRIVILEGE_HIGH   PrivilegeLevel = "HIGH"   // Shell execution, git push, deployment, cloud credentials
)

var (
	ErrInvalidTaintLevel     = errors.New("invalid taint level")
	ErrInvalidPrivilegeLevel = errors.New("invalid privilege level")
	ErrTaintGateViolation    = errors.New("tainted input cannot flow directly to elevated privilege agent without firewall sanitization")
)

// Severity returns an integer rank for taint comparisons: higher number = higher risk.
func (t TaintLevel) Severity() int {
	switch t {
	case TRUST_LOCAL_WORKSPACE:
		return 0
	case TAINT_EXTERNAL_USER:
		return 1
	case TAINT_UNTRUSTED_WEB:
		return 2
	default:
		return 999
	}
}

// IsValid checks whether the TaintLevel is recognized.
func (t TaintLevel) IsValid() bool {
	switch t {
	case TRUST_LOCAL_WORKSPACE, TAINT_EXTERNAL_USER, TAINT_UNTRUSTED_WEB:
		return true
	default:
		return false
	}
}

// ParseTaintLevel parses a string into a validated TaintLevel.
func ParseTaintLevel(s string) (TaintLevel, error) {
	upper := strings.ToUpper(strings.TrimSpace(s))
	switch TaintLevel(upper) {
	case TRUST_LOCAL_WORKSPACE:
		return TRUST_LOCAL_WORKSPACE, nil
	case TAINT_EXTERNAL_USER:
		return TAINT_EXTERNAL_USER, nil
	case TAINT_UNTRUSTED_WEB:
		return TAINT_UNTRUSTED_WEB, nil
	default:
		return "", fmt.Errorf("%w: %q", ErrInvalidTaintLevel, s)
	}
}

// ParsePrivilegeLevel parses a string into a validated PrivilegeLevel.
func ParsePrivilegeLevel(s string) (PrivilegeLevel, error) {
	upper := strings.ToUpper(strings.TrimSpace(s))
	switch PrivilegeLevel(upper) {
	case PRIVILEGE_LOW:
		return PRIVILEGE_LOW, nil
	case PRIVILEGE_MEDIUM:
		return PRIVILEGE_MEDIUM, nil
	case PRIVILEGE_HIGH:
		return PRIVILEGE_HIGH, nil
	default:
		return "", fmt.Errorf("%w: %q", ErrInvalidPrivilegeLevel, s)
	}
}

// TaintedEnvelope encapsulates data with provenance taint tracking and lineage.
type TaintedEnvelope struct {
	Content   string     `json:"content"`
	Taint     TaintLevel `json:"taint"`
	Source    string     `json:"source"`
	Lineage   []string   `json:"lineage"`
	Timestamp time.Time  `json:"timestamp"`
}

// NewTaintedEnvelope constructs a new envelope with validated taint.
func NewTaintedEnvelope(content string, taint TaintLevel, source string, originAgent string) (*TaintedEnvelope, error) {
	if !taint.IsValid() {
		return nil, fmt.Errorf("%w: %s", ErrInvalidTaintLevel, taint)
	}
	lineage := []string{}
	if originAgent != "" {
		lineage = append(lineage, originAgent)
	}
	return &TaintedEnvelope{
		Content:   content,
		Taint:     taint,
		Source:    source,
		Lineage:   lineage,
		Timestamp: time.Now().UTC(),
	}, nil
}

// MergeTaints calculates the propagated taint when multiple inputs are combined.
// Propagation rule: The resulting taint level adopts the highest severity of all inputs.
func MergeTaints(levels ...TaintLevel) TaintLevel {
	if len(levels) == 0 {
		return TRUST_LOCAL_WORKSPACE
	}
	highest := TRUST_LOCAL_WORKSPACE
	for _, lvl := range levels {
		if lvl.Severity() > highest.Severity() {
			highest = lvl
		}
	}
	return highest
}

// Propagate transforms the content while preserving or escalating taint and recording agent lineage.
func (e *TaintedEnvelope) Propagate(newContent string, currentAgent string, additionalTaint ...TaintLevel) *TaintedEnvelope {
	allTaints := append([]TaintLevel{e.Taint}, additionalTaint...)
	propagatedTaint := MergeTaints(allTaints...)

	newLineage := make([]string, len(e.Lineage), len(e.Lineage)+1)
	copy(newLineage, e.Lineage)
	if currentAgent != "" {
		newLineage = append(newLineage, currentAgent)
	}

	return &TaintedEnvelope{
		Content:   newContent,
		Taint:     propagatedTaint,
		Source:    e.Source,
		Lineage:   newLineage,
		Timestamp: time.Now().UTC(),
	}
}

// DirectAccessAllowed returns true if the context can flow directly to the agent without firewall intervention.
// Any untrusted or external data destined for HIGH privilege execution agents MUST be intercepted and sanitized.
func DirectAccessAllowed(t TaintLevel, p PrivilegeLevel) bool {
	switch p {
	case PRIVILEGE_LOW:
		// Low-privilege reasoning/reading agents can read anything directly
		return true
	case PRIVILEGE_MEDIUM:
		// Medium privilege (code editing) requires firewall inspection for untrusted web
		return t != TAINT_UNTRUSTED_WEB
	case PRIVILEGE_HIGH:
		// High privilege (shell execution) requires firewall inspection for any external/untrusted taint
		return t == TRUST_LOCAL_WORKSPACE
	default:
		return false
	}
}
