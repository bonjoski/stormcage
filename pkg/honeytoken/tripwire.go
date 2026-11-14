package honeytoken

import (
	"context"
	"fmt"
	"sync"
	"time"
)

// TripwireAlert records a triggered honeytoken breach.
type TripwireAlert struct {
	CanaryID    string    `json:"canary_id"`
	AccessKeyID string    `json:"access_key_id"`
	Action      string    `json:"action"` // e.g. "GetSecretValue", "ListBuckets"
	ClientIP    string    `json:"client_ip"`
	Timestamp   time.Time `json:"timestamp"`
	TripwireType string   `json:"tripwire_type"` // "CANARY_CREDENTIAL_ACCESS" or "VELOCITY_BURST"
	Revoked     bool      `json:"revoked"`
}

// VelocityTracker tracks API invocation rates per client/key.
type VelocityTracker struct {
	mu           sync.Mutex
	requestTimes map[string][]time.Time
	maxBurst     int
	window       time.Duration
}

// NewVelocityTracker initializes a velocity rate limiter.
func NewVelocityTracker(maxBurst int, window time.Duration) *VelocityTracker {
	if maxBurst <= 0 {
		maxBurst = 5 // Max 5 secret queries per window
	}
	if window <= 0 {
		window = 1 * time.Second
	}
	return &VelocityTracker{
		requestTimes: make(map[string][]time.Time),
		maxBurst:     maxBurst,
		window:       window,
	}
}

// Record checks whether an actor has exceeded burst velocity thresholds.
func (v *VelocityTracker) Record(actor string) bool {
	v.mu.Lock()
	defer v.mu.Unlock()

	now := time.Now()
	cutoff := now.Add(-v.window)

	times := v.requestTimes[actor]
	validTimes := make([]time.Time, 0, len(times)+1)

	for _, t := range times {
		if t.After(cutoff) {
			validTimes = append(validTimes, t)
		}
	}

	validTimes = append(validTimes, now)
	v.requestTimes[actor] = validTimes

	return len(validTimes) > v.maxBurst
}

// TripwireGate evaluates API access and trips automated defenses.
type TripwireGate struct {
	registry     *CanaryRegistry
	velocity     *VelocityTracker
	revocationFn func(ctx context.Context, alert TripwireAlert) error
}

// NewTripwireGate initializes the gate.
func NewTripwireGate(registry *CanaryRegistry, revocationFn func(ctx context.Context, alert TripwireAlert) error) *TripwireGate {
	if registry == nil {
		registry = NewCanaryRegistry()
	}
	return &TripwireGate{
		registry:     registry,
		velocity:     NewVelocityTracker(5, 1*time.Second),
		revocationFn: revocationFn,
	}
}

// InspectInvocation evaluates an inbound cloud API request.
func (g *TripwireGate) InspectInvocation(ctx context.Context, keyID, action, clientIP string) (*TripwireAlert, error) {
	now := time.Now()

	// 1. Check if the key is a honeytoken
	if isCanary, cred := g.registry.IsCanaryKey(keyID); isCanary {
		alert := TripwireAlert{
			CanaryID:     cred.CanaryID,
			AccessKeyID:  keyID,
			Action:       action,
			ClientIP:     clientIP,
			Timestamp:    now,
			TripwireType: "CANARY_CREDENTIAL_ACCESS",
			Revoked:      true,
		}
		if g.revocationFn != nil {
			_ = g.revocationFn(ctx, alert)
		}
		return &alert, fmt.Errorf("CANARY_TRIPWIRE_TRIGGERED: honeytoken %s accessed from %s", keyID, clientIP)
	}

	// 2. Velocity Tripwire: check if machine-speed enumeration is occurring (AntiFox GetSecretValue spray)
	if action == "GetSecretValue" || action == "ListSecrets" {
		if burstExceeded := g.velocity.Record(clientIP); burstExceeded {
			alert := TripwireAlert{
				CanaryID:     "velocity-tripwire",
				AccessKeyID:  keyID,
				Action:       action,
				ClientIP:     clientIP,
				Timestamp:    now,
				TripwireType: "VELOCITY_BURST",
				Revoked:      true,
			}
			if g.revocationFn != nil {
				_ = g.revocationFn(ctx, alert)
			}
			return &alert, fmt.Errorf("VELOCITY_TRIPWIRE_TRIGGERED: %s exceeded secret access rate from %s", action, clientIP)
		}
	}

	return nil, nil
}
