package firewall

import (
	"time"

	"github.com/bonjoski/stormcage/pkg/schema"
	"github.com/bonjoski/stormcage/pkg/taint"
)

// Decision describes the enforcement action chosen by the firewall.
type Decision string

const (
	DecisionAllowed     Decision = "allowed"
	DecisionSanitized   Decision = "sanitized"
	DecisionQuarantined Decision = "quarantined"
)

// Verdict summarizes the firewall security evaluation of a memory record.
type Verdict struct {
	Status         Decision         `json:"status"`
	Reason         string           `json:"reason,omitempty"`
	Taint          taint.TaintLevel `json:"taint"`
	CleanedContent string           `json:"cleaned_content,omitempty"`
	RiskScore      float64          `json:"risk_score"`
	MatchedRules   []string         `json:"matched_rules,omitempty"`
	Details        []string         `json:"details,omitempty"`
	LatencyMs      float64          `json:"latency_ms"`
	Cached         bool             `json:"cached"`
}

// Firewall coordinates multi-tier static, semantic, and structural inspection.
type Firewall struct {
	detector  *Detector
	cache     *VerdictCache
	sanitizer *PreFlightSanitizer
}

// NewFirewall initializes a new Firewall instance.
func NewFirewall() *Firewall {
	return &Firewall{
		detector:  NewDetector(),
		cache:     NewVerdictCache(10000),
		sanitizer: NewPreFlightSanitizer(),
	}
}

// Gate evaluates a memory record and enforces context sanitization or quarantine.
func (f *Firewall) Gate(record *schema.MemoryRecord, targetPrivilege taint.PrivilegeLevel) *Verdict {
	start := time.Now()

	// 1. Cache lookup
	cacheKey := HashKey(string(record.Taint), string(targetPrivilege), record.TaskIntent, record.Content)
	if cachedVerdict, hit := f.cache.Get(cacheKey); hit {
		cachedVerdict.LatencyMs = float64(time.Since(start).Microseconds()) / 1000.0
		return cachedVerdict
	}

	// 2. Normalization & AST extraction
	norm := schema.Normalize(record.Content)

	// 3. Tier 0: Fast static injection scan across raw, cleaned, and decoded payloads
	det := f.detector.Scan(record.Content)
	if det.IsInjected {
		v := &Verdict{
			Status:       DecisionQuarantined,
			Reason:       det.Reason,
			Taint:        record.Taint,
			RiskScore:    det.Confidence,
			MatchedRules: det.MatchedRuleIDs,
			Details:      det.Details,
			LatencyMs:    float64(time.Since(start).Microseconds()) / 1000.0,
			Cached:       false,
		}
		f.cache.Set(cacheKey, v)
		return v
	}

	// 4. Tier 1: Intent drift and imperative density analysis for untrusted/external context
	if record.Taint != taint.TRUST_LOCAL_WORKSPACE {
		drift := AnalyzeIntentDrift(record.TaskIntent, norm.Cleaned)
		if drift.DriftDetected {
			reason := "imperative_injection_detected"
			if drift.Reason != "" {
				reason = drift.Reason
			}
			v := &Verdict{
				Status:       DecisionQuarantined,
				Reason:       reason,
				Taint:        record.Taint,
				RiskScore:    0.88,
				MatchedRules: []string{"TIER1-INTENT-DRIFT"},
				Details:      []string{"Semantic intent drift or elevated imperative command density detected"},
				LatencyMs:    float64(time.Since(start).Microseconds()) / 1000.0,
				Cached:       false,
			}
			f.cache.Set(cacheKey, v)
			return v
		}
	}

	// 5. Structural & Cloaking sanitization
	if norm.StrippedRunes > 0 || len(norm.MarkersFound) > 0 || len(norm.DecodedPayloads) > 0 {
		cleaned := f.sanitizer.Neutralize(norm.Cleaned)
		v := &Verdict{
			Status:         DecisionSanitized,
			Reason:         "markdown_cloaking_neutralized",
			Taint:          record.Taint,
			CleanedContent: cleaned,
			RiskScore:      0.25,
			Details:        norm.MarkersFound,
			LatencyMs:      float64(time.Since(start).Microseconds()) / 1000.0,
			Cached:         false,
		}
		f.cache.Set(cacheKey, v)
		return v
	}

	// 6. Direct access policy check for elevated privilege agents
	if targetPrivilege == taint.PRIVILEGE_HIGH && record.Taint != taint.TRUST_LOCAL_WORKSPACE {
		cleaned := f.sanitizer.Neutralize(norm.Cleaned)
		v := &Verdict{
			Status:         DecisionSanitized,
			Reason:         "sanitized_for_elevated_privilege",
			Taint:          record.Taint,
			CleanedContent: cleaned,
			RiskScore:      0.10,
			LatencyMs:      float64(time.Since(start).Microseconds()) / 1000.0,
			Cached:         false,
		}
		f.cache.Set(cacheKey, v)
		return v
	}

	// Clean, authorized context
	v := &Verdict{
		Status:         DecisionAllowed,
		Reason:         "clean",
		Taint:          record.Taint,
		CleanedContent: record.Content,
		RiskScore:      0.0,
		LatencyMs:      float64(time.Since(start).Microseconds()) / 1000.0,
		Cached:         false,
	}
	f.cache.Set(cacheKey, v)
	return v
}
