package firewall

import (
	"math"
	"regexp"
	"strings"
)

var wordBoundaryRegex = regexp.MustCompile(`[a-zA-Z0-9_\-]+`)

// Common imperative command verbs associated with rogue action hijacking.
var imperativeKeywords = map[string]float64{
	"ignore":     1.5,
	"disregard":  1.5,
	"override":   1.5,
	"forget":     1.2,
	"execute":    1.8,
	"run":        1.6,
	"curl":       2.0,
	"wget":       2.0,
	"bash":       2.2,
	"sh":         2.0,
	"rm":         2.5,
	"delete":     1.8,
	"drop":       2.0,
	"chmod":      2.2,
	"export":     1.8,
	"exfiltrate": 2.5,
	"leak":       2.0,
	"send":       1.2,
	"bypass":     1.8,
	"eval":       2.2,
	"cat":        1.5,
}

// IntentDriftScore holds the computed drift metrics between declared intent and context payload.
type IntentDriftScore struct {
	DriftDetected   bool
	Similarity      float64
	ImperativeScore float64
	Reason          string
}

// TermVector represents normalized term frequencies.
type TermVector map[string]float64

// buildVector constructs a normalized term frequency vector from text.
func buildVector(text string) TermVector {
	tokens := wordBoundaryRegex.FindAllString(strings.ToLower(text), -1)
	if len(tokens) == 0 {
		return TermVector{}
	}

	counts := make(map[string]int)
	for _, tok := range tokens {
		if len(tok) >= 2 {
			counts[tok]++
		}
	}

	vec := make(TermVector)
	var sumSquares float64
	for tok, c := range counts {
		val := float64(c)
		vec[tok] = val
		sumSquares += val * val
	}

	norm := math.Sqrt(sumSquares)
	if norm > 0 {
		for tok := range vec {
			vec[tok] /= norm
		}
	}

	return vec
}

// CosineSimilarity computes the cosine similarity between two term vectors.
func CosineSimilarity(v1, v2 TermVector) float64 {
	if len(v1) == 0 || len(v2) == 0 {
		return 0.0
	}

	var dotProduct float64
	for tok, val1 := range v1 {
		if val2, exists := v2[tok]; exists {
			dotProduct += val1 * val2
		}
	}

	return dotProduct
}

// AnalyzeIntentDrift evaluates whether untrusted content departs significantly from task intent
// and pivots into imperative command hijacking.
func AnalyzeIntentDrift(taskIntent, content string) *IntentDriftScore {
	tokens := wordBoundaryRegex.FindAllString(strings.ToLower(content), -1)
	if len(tokens) == 0 {
		return &IntentDriftScore{
			DriftDetected: false,
			Similarity:    1.0,
		}
	}

	// Calculate imperative verb weight
	var imperativeSum float64
	imperativeHits := 0
	for _, tok := range tokens {
		if weight, found := imperativeKeywords[tok]; found {
			imperativeSum += weight
			imperativeHits++
		}
	}

	totalTokens := float64(len(tokens))
	imperativeDensity := (imperativeSum / totalTokens) * 10.0

	// If no explicit task intent was provided, evaluate baseline imperative anomalies
	if strings.TrimSpace(taskIntent) == "" {
		drift := imperativeDensity > 4.5 && imperativeHits >= 3
		reason := ""
		if drift {
			reason = "high_imperative_anomaly"
		}
		return &IntentDriftScore{
			DriftDetected:   drift,
			Similarity:      1.0,
			ImperativeScore: imperativeDensity,
			Reason:          reason,
		}
	}

	// Compare TaskIntent with incoming Content
	vIntent := buildVector(taskIntent)
	vContent := buildVector(content)
	similarity := CosineSimilarity(vIntent, vContent)

	// Drift condition: Context drastically deviates from declared intent (low similarity)
	// AND introduces dense imperative command triggers
	driftDetected := (similarity < 0.10 && imperativeHits >= 2 && imperativeDensity > 2.0) ||
		(imperativeDensity > 5.0 && imperativeHits >= 3)

	reason := ""
	if driftDetected {
		reason = "intent_drift_detected"
	}

	return &IntentDriftScore{
		DriftDetected:   driftDetected,
		Similarity:      similarity,
		ImperativeScore: imperativeDensity,
		Reason:          reason,
	}
}
