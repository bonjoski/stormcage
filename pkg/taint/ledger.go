package taint

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"net/url"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// TaintSource identifies the origin category of tainted information.
type TaintSource string

const (
	SourceSecretFile TaintSource = "SECRET_FILE"
	SourcePrivateKey TaintSource = "PRIVATE_KEY"
	SourceEnvVar     TaintSource = "ENV_VAR"
)

const (
	ShingleSize             = 8
	EntropyThreshold        = 5.2
	MinLengthForEntropyTest = 24
)

// TaintRecord tracks sensitive data slices and derived shingles in memory.
type TaintRecord struct {
	ID          string      `json:"id"`
	Source      TaintSource `json:"source"`
	Path        string      `json:"path"`
	Fingerprint [32]byte    `json:"fingerprint"`
	Shingles    [][]byte    `json:"shingles"`
	CreatedAt   time.Time   `json:"created_at"`
}

// TaintLedger maintains thread-safe, session-partitioned dynamic taint graphs.
type TaintLedger struct {
	mu       sync.RWMutex
	sessions map[string][]*TaintRecord
}

// NewTaintLedger creates an active taint ledger instance.
func NewTaintLedger() *TaintLedger {
	return &TaintLedger{
		sessions: make(map[string][]*TaintRecord),
	}
}

// SensitivePatterns defines filename and extension patterns that trigger automatic tainting.
var SensitivePatterns = []string{
	".env",
	"*.env",
	".env.*",
	"*.pem",
	"*.key",
	"*.pkcs12",
	"*.pfx",
	"*id_rsa*",
	"*id_ed25519*",
	"*id_ecdsa*",
	"credentials.json",
	"secret*",
	"*token*",
	"*passwd*",
	"shadow",
}

// IsSensitivePath checks if a requested filesystem path matches known secret patterns.
func IsSensitivePath(path string) bool {
	cleanPath := strings.ToLower(filepath.Clean(path))
	baseName := strings.ToLower(filepath.Base(cleanPath))

	for _, pattern := range SensitivePatterns {
		matched, err := filepath.Match(pattern, baseName)
		if err == nil && matched {
			return true
		}
		if strings.Contains(baseName, strings.Trim(pattern, "*")) {
			return true
		}
	}
	return false
}

// CalculateShannonEntropy computes information entropy for a byte slice (in bits per byte).
func CalculateShannonEntropy(data []byte) float64 {
	if len(data) == 0 {
		return 0.0
	}

	freq := make(map[byte]float64)
	for _, b := range data {
		freq[b]++
	}

	length := float64(len(data))
	var entropy float64
	for _, count := range freq {
		p := count / length
		if p > 0 {
			entropy -= p * math.Log2(p)
		}
	}
	return entropy
}

// generateShingles slices data into rolling 8-byte shingles.
func generateShingles(data []byte) [][]byte {
	if len(data) < ShingleSize {
		return [][]byte{bytes.Clone(data)}
	}

	// Maximum 128 shingles per record to prevent memory bloat
	step := 1
	if len(data) > ShingleSize*128 {
		step = len(data) / (ShingleSize * 128)
		if step < 1 {
			step = 1
		}
	}

	var shingles [][]byte
	for i := 0; i <= len(data)-ShingleSize; i += step {
		shingles = append(shingles, bytes.Clone(data[i:i+ShingleSize]))
	}
	return shingles
}

// RegisterTaint tags and indexes a sensitive data buffer for a session.
func (l *TaintLedger) RegisterTaint(sessionID string, source TaintSource, path string, data []byte) (*TaintRecord, error) {
	if len(data) == 0 {
		return nil, errors.New("taint: cannot register empty buffer")
	}

	fingerprint := sha256.Sum256(data)
	shingles := generateShingles(data)

	record := &TaintRecord{
		ID:          fmt.Sprintf("taint-%x", fingerprint[:6]),
		Source:      source,
		Path:        path,
		Fingerprint: fingerprint,
		Shingles:    shingles,
		CreatedAt:   time.Now().UTC(),
	}

	l.mu.Lock()
	defer l.mu.Unlock()

	l.sessions[sessionID] = append(l.sessions[sessionID], record)
	return record, nil
}

// normalizePayload attempts to unwrap common obfuscation codecs (Base64, Hex, URL-encoding).
func normalizePayload(payload []byte) [][]byte {
	variants := [][]byte{payload}

	// 1. URL unquote
	unquoted, err := url.QueryUnescape(string(payload))
	if err == nil && unquoted != string(payload) {
		variants = append(variants, []byte(unquoted))
	}

	// 2. Base64 decode attempt
	b64Dec, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(payload)))
	if err == nil && len(b64Dec) > 0 {
		variants = append(variants, b64Dec)
	}
	b64URLDec, err := base64.RawURLEncoding.DecodeString(strings.TrimSpace(string(payload)))
	if err == nil && len(b64URLDec) > 0 {
		variants = append(variants, b64URLDec)
	}

	// 3. Hex decode attempt
	hexDec, err := hex.DecodeString(strings.TrimSpace(string(payload)))
	if err == nil && len(hexDec) > 0 {
		variants = append(variants, hexDec)
	}

	return variants
}

// EgressTools lists tool names classified as external network or exfiltration pathways.
var EgressTools = map[string]bool{
	"fetch":        true,
	"curl":         true,
	"http_request": true,
	"webhook":      true,
	"send_message": true,
	"post":         true,
	"git_push":     true,
	"dns_query":    true,
}

// IsEgressTool checks if the executed tool transmits data outside the local sandbox.
func IsEgressTool(toolName string) bool {
	normalized := strings.ToLower(strings.TrimSpace(toolName))
	return EgressTools[normalized]
}

// EvaluateEgress scans an outgoing payload for tainted shingles or suspicious entropy.
func (l *TaintLedger) EvaluateEgress(sessionID string, toolName string, payload []byte) (bool, string) {
	if !IsEgressTool(toolName) {
		return true, "" // Local execution is allowed
	}

	l.mu.RLock()
	records := l.sessions[sessionID]
	l.mu.RUnlock()

	if len(records) == 0 {
		return true, "" // No sensitive files read in this session
	}

	variants := normalizePayload(payload)

	for _, variant := range variants {
		// 1. Shingle match across all tainted records
		for _, rec := range records {
			for _, shingle := range rec.Shingles {
				if len(shingle) > 0 && bytes.Contains(variant, shingle) {
					return false, fmt.Sprintf("taint violation: payload contains data leaked from %s (%s)", rec.Path, rec.ID)
				}
			}
		}

		// 2. High-entropy block check
		if len(variant) >= MinLengthForEntropyTest {
			entropy := CalculateShannonEntropy(variant)
			if entropy > EntropyThreshold {
				return false, fmt.Sprintf("taint violation: high-entropy exfiltration block (H=%.2f > %.2f)", entropy, EntropyThreshold)
			}
		}
	}

	return true, ""
}

// ClearSession purges taint records for a completed subagent worktree session.
func (l *TaintLedger) ClearSession(sessionID string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.sessions, sessionID)
}
