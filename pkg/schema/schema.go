package schema

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strings"
	"time"

	"github.com/bonjoski/stormcage/pkg/taint"
)

var (
	ErrInvalidAgentID    = errors.New("invalid agent_id format: must be 1-64 alphanumeric, dash, dot, or underscore chars")
	ErrContentEmpty      = errors.New("content cannot be empty")
	ErrContentTooLarge   = errors.New("content exceeds maximum allowed size (1MB)")
	ErrInvalidTaint      = errors.New("taint field missing or invalid")
	ErrSchemaUnknownKey  = errors.New("unknown fields not permitted by strict schema")
)

const (
	MaxContentLength = 1024 * 1024 // 1 MB
	AgentIDPattern   = `^[a-zA-Z0-9_\-\.]{1,64}$`
)

var agentIDRegex = regexp.MustCompile(AgentIDPattern)

// MemoryRecord represents a strictly typed cross-agent memory write or context exchange envelope.
type MemoryRecord struct {
	AgentID     string            `json:"agent_id"`
	TargetAgent string            `json:"target_agent,omitempty"`
	Taint       taint.TaintLevel  `json:"taint"`
	Content     string            `json:"content"`
	TaskIntent  string            `json:"task_intent,omitempty"`
	Metadata    map[string]string `json:"metadata,omitempty"`
	Signature   string            `json:"signature,omitempty"`
	Timestamp   string            `json:"timestamp,omitempty"`
}

// Validate verifies that the MemoryRecord satisfies strict structural schema constraints.
func (r *MemoryRecord) Validate() error {
	if !agentIDRegex.MatchString(r.AgentID) {
		return fmt.Errorf("%w: %q", ErrInvalidAgentID, r.AgentID)
	}

	if r.TargetAgent != "" && !agentIDRegex.MatchString(r.TargetAgent) {
		return fmt.Errorf("%w for target_agent: %q", ErrInvalidAgentID, r.TargetAgent)
	}

	if !r.Taint.IsValid() {
		return fmt.Errorf("%w: %q", ErrInvalidTaint, r.Taint)
	}

	trimmedContent := strings.TrimSpace(r.Content)
	if len(trimmedContent) == 0 {
		return ErrContentEmpty
	}

	if len(r.Content) > MaxContentLength {
		return fmt.Errorf("%w: length=%d max=%d", ErrContentTooLarge, len(r.Content), MaxContentLength)
	}

	return nil
}

// ParseStrictJSON parses a JSON payload ensuring no unknown fields are permitted.
func ParseStrictJSON(data []byte) (*MemoryRecord, error) {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()

	var record MemoryRecord
	if err := decoder.Decode(&record); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrSchemaUnknownKey, err)
	}

	if record.Timestamp == "" {
		record.Timestamp = time.Now().UTC().Format(time.RFC3339)
	}

	if err := record.Validate(); err != nil {
		return nil, err
	}

	// Reject trailing JSON tokens or multiple concatenated JSON objects
	var extra interface{}
	if err := decoder.Decode(&extra); err != io.EOF {
		return nil, fmt.Errorf("%w: trailing data after JSON object", ErrSchemaUnknownKey)
	}

	return &record, nil
}

// ComputeSignature computes a length-prefixed HMAC-SHA256 over the provenance-critical fields of MemoryRecord.
func (r *MemoryRecord) ComputeSignature(secret []byte) string {
	mac := hmac.New(sha256.New, secret)
	writeField := func(s string) {
		var lenBuf [8]byte
		binary.BigEndian.PutUint64(lenBuf[:], uint64(len(s)))
		mac.Write(lenBuf[:])
		mac.Write([]byte(s))
	}
	writeField(r.AgentID)
	writeField(r.TargetAgent)
	writeField(string(r.Taint))
	writeField(r.TaskIntent)
	writeField(r.Content)
	return hex.EncodeToString(mac.Sum(nil))
}

// Sign populates r.Signature using the provided HMAC secret.
func (r *MemoryRecord) Sign(secret []byte) {
	r.Signature = r.ComputeSignature(secret)
}

// VerifySignature checks r.Signature in constant time against the provided HMAC secret.
func (r *MemoryRecord) VerifySignature(secret []byte) bool {
	if len(secret) == 0 || r.Signature == "" {
		return false
	}
	sigBytes, err := hex.DecodeString(r.Signature)
	if err != nil {
		return false
	}
	expectedHex := r.ComputeSignature(secret)
	expectedBytes, err := hex.DecodeString(expectedHex)
	if err != nil {
		return false
	}
	return hmac.Equal(sigBytes, expectedBytes)
}

// ToJSON marshals the MemoryRecord into canonical JSON.
func (r *MemoryRecord) ToJSON() ([]byte, error) {
	return json.MarshalIndent(r, "", "  ")
}
