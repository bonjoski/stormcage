package honeytoken

import (
	"context"
	"fmt"
	"sync"
	"testing"
)

func TestAdversarial_ConcurrentHoneytokenChecks(t *testing.T) {
	registry := NewCanaryRegistry()
	for i := 0; i < 10; i++ {
		_, _ = registry.GenerateAWSCanary(fmt.Sprintf("canary-%d", i))
	}

	gate := NewTripwireGate(registry, nil)

	// Run concurrent checks across 8 worker goroutines
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()
			for j := 0; j < 50; j++ {
				key := fmt.Sprintf("AKIA%d%d", workerID, j)
				_, _ = gate.InspectInvocation(context.Background(), key, "DescribeInstances", fmt.Sprintf("192.0.2.%d", workerID))
			}
		}(i)
	}

	wg.Wait()
}

func TestAdversarial_SprayVelocityTrip(t *testing.T) {
	trips := 0
	var mu sync.Mutex

	mockRevoke := func(ctx context.Context, alert TripwireAlert) error {
		mu.Lock()
		trips++
		mu.Unlock()
		return nil
	}

	gate := NewTripwireGate(nil, mockRevoke)
	attackerIP := "198.51.100.123"

	// Simulate AntiFox automated spray: 30 calls in rapid succession
	for i := 0; i < 30; i++ {
		_, _ = gate.InspectInvocation(context.Background(), "AKIAARBITRARYKEY123", "GetSecretValue", attackerIP)
	}

	if trips == 0 {
		t.Error("expected velocity circuit breaker to trip during automated secret spray")
	}
}
