package honeytoken

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCanaryGenerationAndPlanting(t *testing.T) {
	registry := NewCanaryRegistry()
	cred, err := registry.GenerateAWSCanary("prod-canary-01")
	if err != nil {
		t.Fatalf("GenerateAWSCanary failed: %v", err)
	}

	if !strings.HasPrefix(cred.AccessKeyID, "AKIATRIP") {
		t.Errorf("expected AKIATRIP prefix, got %s", cred.AccessKeyID)
	}
	if len(cred.AccessKeyID) != 18 { // "AKIA" + "TRIP" + 10 hex
		t.Logf("Canary key ID generated: %s (length %d)", cred.AccessKeyID, len(cred.AccessKeyID))
	}

	tmpDir := t.TempDir()
	awsConfigPath := filepath.Join(tmpDir, ".aws", "credentials")
	if err := PlantAWSConfig(awsConfigPath, cred); err != nil {
		t.Fatalf("PlantAWSConfig failed: %v", err)
	}

	content, err := os.ReadFile(awsConfigPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(content), cred.AccessKeyID) {
		t.Error("PlantAWSConfig did not embed canary access key")
	}

	webConfigPath := filepath.Join(tmpDir, "web.config")
	if err := PlantWebConfig(webConfigPath, cred); err != nil {
		t.Fatalf("PlantWebConfig failed: %v", err)
	}

	webContent, err := os.ReadFile(webConfigPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(webContent), cred.AccessKeyID) {
		t.Error("PlantWebConfig did not embed canary access key")
	}
}

func TestTripwireGate_CanaryAccess(t *testing.T) {
	revocationCalled := false
	mockRevoke := func(ctx context.Context, alert TripwireAlert) error {
		revocationCalled = true
		return nil
	}

	registry := NewCanaryRegistry()
	cred, _ := registry.GenerateAWSCanary("honey-01")
	gate := NewTripwireGate(registry, mockRevoke)

	alert, err := gate.InspectInvocation(context.Background(), cred.AccessKeyID, "ListBuckets", "198.51.100.42")
	if err == nil {
		t.Fatal("expected error on canary invocation, but succeeded")
	}

	if alert == nil || alert.TripwireType != "CANARY_CREDENTIAL_ACCESS" {
		t.Errorf("expected CANARY_CREDENTIAL_ACCESS, got %+v", alert)
	}
	if !revocationCalled {
		t.Error("expected revocation callback to be executed")
	}
}

func TestTripwireGate_VelocityBurst(t *testing.T) {
	revocationCalled := false
	mockRevoke := func(ctx context.Context, alert TripwireAlert) error {
		revocationCalled = true
		return nil
	}

	gate := NewTripwireGate(nil, mockRevoke)
	clientIP := "203.0.113.99"

	// First 5 calls pass within velocity limit
	for i := 0; i < 5; i++ {
		_, err := gate.InspectInvocation(context.Background(), "AKIAREALKEY12345678", "GetSecretValue", clientIP)
		if err != nil {
			t.Fatalf("call %d within velocity limit unexpectedly tripped: %v", i+1, err)
		}
	}

	// 6th call exceeds burst threshold (>5/sec) and must trip the circuit breaker
	alert, err := gate.InspectInvocation(context.Background(), "AKIAREALKEY12345678", "GetSecretValue", clientIP)
	if err == nil {
		t.Fatal("expected 6th rapid call to trip velocity breaker, but succeeded")
	}

	if alert == nil || alert.TripwireType != "VELOCITY_BURST" {
		t.Errorf("expected VELOCITY_BURST alert, got %+v", alert)
	}
	if !revocationCalled {
		t.Error("expected revocation callback on velocity burst")
	}
}
