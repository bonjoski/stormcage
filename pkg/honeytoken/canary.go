package honeytoken

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

// CanaryType represents the credential flavor of the canary.
type CanaryType string

const (
	TypeAWS       CanaryType = "AWS"
	TypeGitHub    CanaryType = "GITHUB"
	TypeOpenAI    CanaryType = "OPENAI"
	TypeGeneric   CanaryType = "GENERIC"
)

// CanaryCredential models a high-fidelity honeytoken planted to detect automated intrusions (AntiFox).
type CanaryCredential struct {
	CanaryID    string     `json:"canary_id"`
	Type        CanaryType `json:"type"`
	AccessKeyID string     `json:"access_key_id"`
	SecretKey   string     `json:"secret_key"`
	FilePath    string     `json:"file_path,omitempty"`
	CreatedAt   int64      `json:"created_at"`
}

// CanaryRegistry maintains in-memory tracking of active tripwires.
type CanaryRegistry struct {
	mu      sync.RWMutex
	canaries map[string]*CanaryCredential // AccessKeyID -> Canary
}

// NewCanaryRegistry initializes a registry.
func NewCanaryRegistry() *CanaryRegistry {
	return &CanaryRegistry{
		canaries: make(map[string]*CanaryCredential),
	}
}

// GenerateAWSCanary produces a realistic AWS credential pair with identifiable canary signatures.
func (r *CanaryRegistry) GenerateAWSCanary(canaryID string) (*CanaryCredential, error) {
	randomBytes := make([]byte, 8)
	if _, err := rand.Read(randomBytes); err != nil {
		return nil, fmt.Errorf("failed generating canary entropy: %w", err)
	}

	// AKIA prefix + CANARY tag + random suffix (20 characters total, standard AWS IAM key length)
	hexSuffix := strings.ToUpper(hex.EncodeToString(randomBytes))[:10]
	accessKeyID := fmt.Sprintf("AKIA%s%s", "TRIP", hexSuffix)

	secretBytes := make([]byte, 20)
	if _, err := rand.Read(secretBytes); err != nil {
		return nil, fmt.Errorf("failed generating secret key: %w", err)
	}
	secretKey := hex.EncodeToString(secretBytes)

	cred := &CanaryCredential{
		CanaryID:    canaryID,
		Type:        TypeAWS,
		AccessKeyID: accessKeyID,
		SecretKey:   secretKey,
	}

	r.mu.Lock()
	r.canaries[accessKeyID] = cred
	r.mu.Unlock()

	return cred, nil
}

// IsCanaryKey checks if an access key matches an active honeytoken.
func (r *CanaryRegistry) IsCanaryKey(key string) (bool, *CanaryCredential) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	cred, exists := r.canaries[key]
	if exists {
		return true, cred
	}
	// Heuristic: Check if key contains canary tripwire signature
	if strings.HasPrefix(key, "AKIATRIP") {
		return true, &CanaryCredential{
			AccessKeyID: key,
			Type:        TypeAWS,
			CanaryID:    "heuristic-signature-match",
		}
	}
	return false, nil
}

// PlantAWSConfig creates a decoy AWS configuration/credentials file.
func PlantAWSConfig(targetPath string, cred *CanaryCredential) error {
	cleanPath := filepath.Clean(targetPath)
	dir := filepath.Dir(cleanPath)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("failed creating canary directory: %w", err)
	}

	content := fmt.Sprintf(`[default]
aws_access_key_id = %s
aws_secret_access_key = %s
region = us-east-1
`, cred.AccessKeyID, cred.SecretKey)

	cred.FilePath = cleanPath
	return os.WriteFile(cleanPath, []byte(content), 0600)
}

// PlantWebConfig creates a decoy web.config with embedded honeytokens.
func PlantWebConfig(targetPath string, cred *CanaryCredential) error {
	cleanPath := filepath.Clean(targetPath)
	dir := filepath.Dir(cleanPath)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("failed creating canary directory: %w", err)
	}

	content := fmt.Sprintf(`<?xml version="1.0" encoding="utf-8"?>
<configuration>
  <appSettings>
    <add key="AWS_ACCESS_KEY_ID" value="%s" />
    <add key="AWS_SECRET_ACCESS_KEY" value="%s" />
    <add key="AWS_REGION" value="us-east-1" />
  </appSettings>
</configuration>
`, cred.AccessKeyID, cred.SecretKey)

	cred.FilePath = cleanPath
	return os.WriteFile(cleanPath, []byte(content), 0600)
}
