package taint

import (
	"testing"
)

// TestTaintPropagation verifies taint propagation and escalation when combining context sources.
func TestTaintPropagation(t *testing.T) {
	// Baseline: local source
	localEnv, err := NewTaintedEnvelope("local code snippet", TRUST_LOCAL_WORKSPACE, "/src/main.go", "agent-planner")
	if err != nil {
		t.Fatalf("unexpected error creating envelope: %v", err)
	}
	if localEnv.Taint != TRUST_LOCAL_WORKSPACE {
		t.Errorf("expected TRUST_LOCAL_WORKSPACE, got %s", localEnv.Taint)
	}

	// Propagate with untrusted web content (e.g. documentation fetch)
	webEnv := localEnv.Propagate("summarized docs", "agent-scraper", TAINT_UNTRUSTED_WEB)
	if webEnv.Taint != TAINT_UNTRUSTED_WEB {
		t.Errorf("expected propagated taint TAINT_UNTRUSTED_WEB, got %s", webEnv.Taint)
	}
	if len(webEnv.Lineage) != 2 || webEnv.Lineage[0] != "agent-planner" || webEnv.Lineage[1] != "agent-scraper" {
		t.Errorf("expected lineage [agent-planner, agent-scraper], got %v", webEnv.Lineage)
	}

	// Propagate further down: taint must not degrade to TRUST_LOCAL_WORKSPACE
	downstreamEnv := webEnv.Propagate("refined code suggestion", "agent-coder", TRUST_LOCAL_WORKSPACE)
	if downstreamEnv.Taint != TAINT_UNTRUSTED_WEB {
		t.Errorf("expected taint to remain TAINT_UNTRUSTED_WEB, got %s", downstreamEnv.Taint)
	}
	if len(downstreamEnv.Lineage) != 3 {
		t.Errorf("expected 3 agents in lineage, got %d", len(downstreamEnv.Lineage))
	}

	// Verify MergeTaints truth table
	tests := []struct {
		inputs   []TaintLevel
		expected TaintLevel
	}{
		{[]TaintLevel{TRUST_LOCAL_WORKSPACE, TRUST_LOCAL_WORKSPACE}, TRUST_LOCAL_WORKSPACE},
		{[]TaintLevel{TRUST_LOCAL_WORKSPACE, TAINT_EXTERNAL_USER}, TAINT_EXTERNAL_USER},
		{[]TaintLevel{TAINT_EXTERNAL_USER, TAINT_UNTRUSTED_WEB}, TAINT_UNTRUSTED_WEB},
		{[]TaintLevel{TRUST_LOCAL_WORKSPACE, TAINT_UNTRUSTED_WEB}, TAINT_UNTRUSTED_WEB},
		{[]TaintLevel{TAINT_UNTRUSTED_WEB, TAINT_EXTERNAL_USER, TRUST_LOCAL_WORKSPACE}, TAINT_UNTRUSTED_WEB},
	}

	for i, tc := range tests {
		got := MergeTaints(tc.inputs...)
		if got != tc.expected {
			t.Errorf("case %d: MergeTaints(%v) = %s, expected %s", i, tc.inputs, got, tc.expected)
		}
	}
}

// TestTaintDirectAccess verifies policy gate logic between taint levels and target agent privilege.
func TestTaintDirectAccess(t *testing.T) {
	// LOW privilege can consume anything directly
	if !DirectAccessAllowed(TAINT_UNTRUSTED_WEB, PRIVILEGE_LOW) {
		t.Errorf("expected LOW privilege to allow direct untrusted web access")
	}
	if !DirectAccessAllowed(TAINT_EXTERNAL_USER, PRIVILEGE_LOW) {
		t.Errorf("expected LOW privilege to allow direct external user access")
	}

	// MEDIUM privilege cannot directly consume untrusted web without gate
	if DirectAccessAllowed(TAINT_UNTRUSTED_WEB, PRIVILEGE_MEDIUM) {
		t.Errorf("expected MEDIUM privilege to forbid direct untrusted web access")
	}
	if !DirectAccessAllowed(TAINT_EXTERNAL_USER, PRIVILEGE_MEDIUM) {
		t.Errorf("expected MEDIUM privilege to allow direct external user access")
	}

	// HIGH privilege cannot directly consume any untrusted or external taint
	if DirectAccessAllowed(TAINT_UNTRUSTED_WEB, PRIVILEGE_HIGH) {
		t.Errorf("expected HIGH privilege to forbid direct untrusted web access")
	}
	if DirectAccessAllowed(TAINT_EXTERNAL_USER, PRIVILEGE_HIGH) {
		t.Errorf("expected HIGH privilege to forbid direct external user access")
	}
	if !DirectAccessAllowed(TRUST_LOCAL_WORKSPACE, PRIVILEGE_HIGH) {
		t.Errorf("expected HIGH privilege to allow verified local workspace")
	}
}

// TestParseValidation verifies invalid input handling
func TestParseValidation(t *testing.T) {
	_, err := ParseTaintLevel("INVALID_TAINT")
	if err == nil {
		t.Errorf("expected error for invalid taint level")
	}

	_, err = ParsePrivilegeLevel("SUPERUSER")
	if err == nil {
		t.Errorf("expected error for invalid privilege level")
	}
}
