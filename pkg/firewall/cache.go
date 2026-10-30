package firewall

import (
	"crypto/sha256"
	"encoding/hex"
	"sync"
)

// VerdictCache provides a concurrency-safe, bounded memory cache for firewall verdicts.
type VerdictCache struct {
	mu      sync.RWMutex
	entries map[string]*Verdict
	maxSize int
}

// NewVerdictCache creates a new cache with an upper bound limit.
func NewVerdictCache(maxSize int) *VerdictCache {
	if maxSize <= 0 {
		maxSize = 10000
	}
	return &VerdictCache{
		entries: make(map[string]*Verdict, maxSize),
		maxSize: maxSize,
	}
}

// HashKey computes SHA-256 over taint, privilege, intent, and content.
func HashKey(taint string, privilege string, intent string, content string) string {
	hasher := sha256.New()
	hasher.Write([]byte(taint))
	hasher.Write([]byte{':'})
	hasher.Write([]byte(privilege))
	hasher.Write([]byte{':'})
	hasher.Write([]byte(intent))
	hasher.Write([]byte{':'})
	hasher.Write([]byte(content))
	return hex.EncodeToString(hasher.Sum(nil))
}

// Get retrieves a cached Verdict if present.
func (c *VerdictCache) Get(key string) (*Verdict, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	val, ok := c.entries[key]
	if !ok {
		return nil, false
	}
	// Return a shallow copy with Cached flag set
	cp := *val
	cp.Cached = true
	return &cp, true
}

// Set stores a Verdict in the cache.
func (c *VerdictCache) Set(key string, v *Verdict) {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Simple eviction if exceeding max size
	if len(c.entries) >= c.maxSize {
		// Clear half the cache
		count := 0
		for k := range c.entries {
			delete(c.entries, k)
			count++
			if count >= c.maxSize/2 {
				break
			}
		}
	}
	c.entries[key] = v
}
