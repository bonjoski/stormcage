package taint

import (
	"encoding/base64"
	"testing"
)

func TestIsSensitivePath(t *testing.T) {
	sensitive := []string{
		".env",
		"/path/to/.env.production",
		"~/.ssh/id_ed25519",
		"secrets.json",
		"credentials.json",
		"client.key",
		"server.pem",
	}

	for _, p := range sensitive {
		if !IsSensitivePath(p) {
			t.Errorf("expected %q to be marked sensitive, got false", p)
		}
	}

	safe := []string{
		"main.go",
		"README.md",
		"package.json",
		"index.html",
	}

	for _, p := range safe {
		if IsSensitivePath(p) {
			t.Errorf("expected %q to be marked safe, got true", p)
		}
	}
}

func TestTaintLedger_EgressEvaluation(t *testing.T) {
	ledger := NewTaintLedger()
	sessionID := "agent-session-alpha"

	secretData := []byte("AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY")

	// 1. Register taint
	_, err := ledger.RegisterTaint(sessionID, SourceSecretFile, ".env", secretData)
	if err != nil {
		t.Fatalf("RegisterTaint failed: %v", err)
	}

	// 2. Clean payload should be allowed
	cleanPayload := []byte(`{"url": "https://api.github.com/repos", "action": "list"}`)
	allowed, reason := ledger.EvaluateEgress(sessionID, "fetch", cleanPayload)
	if !allowed {
		t.Fatalf("expected clean payload to be allowed, got blocked: %s", reason)
	}

	// 3. Direct plaintext leak should be blocked
	leakedPayload := []byte(`{"data": "leaking key: wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"}`)
	allowed, reason = ledger.EvaluateEgress(sessionID, "fetch", leakedPayload)
	if allowed {
		t.Fatal("expected plaintext exfiltration to be blocked, but was allowed")
	}
	t.Logf("Blocked reason: %s", reason)

	// 4. Base64-encoded leak should be blocked
	b64Leak := base64.StdEncoding.EncodeToString(secretData)
	allowed, reason = ledger.EvaluateEgress(sessionID, "curl", []byte(b64Leak))
	if allowed {
		t.Fatal("expected base64 exfiltration to be blocked, but was allowed")
	}
	t.Logf("Blocked base64 reason: %s", reason)

	// 5. High-entropy random crypto blob should be blocked
	highEntropy := make([]byte, 64)
	for i := range highEntropy {
		highEntropy[i] = byte((i*37 + 19) % 256)
	}
	allowed, reason = ledger.EvaluateEgress(sessionID, "webhook", highEntropy)
	if allowed {
		t.Fatal("expected high-entropy payload to be blocked, but was allowed")
	}
	t.Logf("Blocked entropy reason: %s", reason)

	// 6. Session isolation: different session without taint records should be allowed
	otherSession := "agent-session-beta"
	allowed, _ = ledger.EvaluateEgress(otherSession, "fetch", cleanPayload)
	if !allowed {
		t.Fatal("expected other clean session to be allowed")
	}
}

func TestShannonEntropyCalculation(t *testing.T) {
	// Zero entropy for uniform repeating byte
	zeroEnt := CalculateShannonEntropy([]byte("AAAAAAAAAAAAAAA"))
	if zeroEnt != 0.0 {
		t.Errorf("expected 0.0 entropy for uniform bytes, got %f", zeroEnt)
	}

	// High entropy for mixed alphanumeric + symbols
	highEnt := CalculateShannonEntropy([]byte("gK5tvVccaFInT4Ekwml3m0cLYgveadA+wGCHDIcNfwMYvs9zOabuWD731e47xyRr1K4yFy5HjLI3kxsq3Kwhbg=="))
	if highEnt < 4.2 {
		t.Errorf("expected high entropy (>4.2), got %f", highEnt)
	}
}
