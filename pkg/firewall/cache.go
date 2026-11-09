package firewall

import (
	"crypto/sha256"
	"encoding/binary"
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
	initCap := 64
	if maxSize < initCap {
		initCap = maxSize
	}
	return &VerdictCache{
		entries: make(map[string]*Verdict, initCap),
		maxSize: maxSize,
	}
}

// HashKey computes a collision-free length-prefixed SHA-256 over taint, privilege, intent, and content.
func HashKey(taint string, privilege string, intent string, content string) string {
	hasher := sha256.New()
	var lenBuf [8]byte
	writeField := func(s string) {
		binary.BigEndian.PutUint64(lenBuf[:], uint64(len(s)))
		hasher.Write(lenBuf[:])
		hasher.Write([]byte(s))
	}
	writeField(taint)
	writeField(privilege)
	writeField(intent)
	writeField(content)
	return hex.EncodeToString(hasher.Sum(nil))
}

func cloneVerdict(v *Verdict, cached bool) *Verdict {
	if v == nil {
		return nil
	}
	cp := *v
	cp.Cached = cached
	if len(v.MatchedRules) > 0 {
		cp.MatchedRules = make([]string, len(v.MatchedRules))
		copy(cp.MatchedRules, v.MatchedRules)
	}
	if len(v.Details) > 0 {
		cp.Details = make([]string, len(v.Details))
		copy(cp.Details, v.Details)
	}
	return &cp
}

// Get retrieves a deep-copied cached Verdict if present.
func (c *VerdictCache) Get(key string) (*Verdict, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	val, ok := c.entries[key]
	if !ok {
		return nil, false
	}
	return cloneVerdict(val, true), true
}

// Set stores a deep-copied Verdict in the cache with bounded O(1) incremental eviction.
func (c *VerdictCache) Set(key string, v *Verdict) {
	if v == nil {
		return
	}
	stored := cloneVerdict(v, false)

	c.mu.Lock()
	defer c.mu.Unlock()

	if _, exists := c.entries[key]; !exists && len(c.entries) >= c.maxSize {
		evictTarget := 64
		if c.maxSize/8 < evictTarget {
			evictTarget = c.maxSize / 8
		}
		if evictTarget < 1 {
			evictTarget = 1
		}
		count := 0
		for k := range c.entries {
			delete(c.entries, k)
			count++
			if count >= evictTarget {
				break
			}
		}
	}
	c.entries[key] = stored
}
