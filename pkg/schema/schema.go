package schema

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
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

	return &record, nil
}

// ToJSON marshals the MemoryRecord into canonical JSON.
func (r *MemoryRecord) ToJSON() ([]byte, error) {
	return json.MarshalIndent(r, "", "  ")
}
