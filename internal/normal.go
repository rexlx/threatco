package internal

import (
	"strconv"
	"strings"
	"sync"
)

const (
	ThreatLevelUnknown  = 0
	ThreatLevelSafe     = 1
	ThreatLevelLow      = 2
	ThreatLevelMedium   = 3
	ThreatLevelHigh     = 4
	ThreatLevelCritical = 5
)

const (
	WeightDefault         = 1.0
	WeightMandiant        = 1.2
	WeightVirusTotal      = 0.8
	WeightCloudflare      = 1.0
	WeightMISP            = 1.0
	WeightCrowdstrike     = 1.1
	WeightURLScan         = 0.9
	WeightDeepfry         = 0.5
	WeightDomainToolsIris = 1.0
)

// NormalizerFunc defines the signature for logic that converts a vendor-specific
// raw score into a standardized 0-100 confidence score.
type NormalizerFunc func(rawScore int) int

var (
	// registry holds the normalization strategy for each vendor.
	// We use a mutex to ensure this is thread-safe if you register vendors at runtime.
	registry = make(map[string]NormalizerFunc)
	thisMu   sync.RWMutex
)

// init registers the default strategies for your known vendors.
func init() {
	// RiskScore is 0-100
	RegisterNormalizer("cloudflare", NormalizeStandardScale)
	RegisterNormalizer("mandiant", NormalizeStandardScale)
	RegisterNormalizer("crowdstrike", NormalizeStandardScale)
	RegisterNormalizer("misp", NormalizeStandardScale)
	RegisterNormalizer("urlscan", NormalizeStandardScale)
	RegisterNormalizer("domaintoolsiris", NormalizeStandardScale)

	// virustotal: Malicious count mapping
	RegisterNormalizer("virustotal", func(maliciousCount int) int {
		switch {
		case maliciousCount == 0:
			return 0 // Safe
		case maliciousCount < 3:
			return 30 // Low (1-2 hits often FP)
		case maliciousCount < 10:
			return 75 // High
		default:
			return 100 // Critical (Consensus)
		}
	})

	// Example: A vendor where 1 is Critical and 10 is Safe (Inverted Small Scale)
	RegisterNormalizer("rank_vendor", func(score int) int {
		if score <= 1 {
			return 100 // Critical
		}
		if score >= 10 {
			return 0 // Safe
		}
		// Linear interpolation for in-between
		return 100 - (score * 10)
	})

	// Example: A vendor using a 1-10 scale
	RegisterNormalizer("small_scale_vendor", func(score int) int {
		return score * 10 // Convert 5 -> 50, 10 -> 100
	})
}

// GetThreatLevelID is your main entry point.
// It accepts the vendor name and the raw number you extracted.
func GetThreatLevelID(vendor string, rawScore int, weight float64) int {
	thisMu.RLock()
	normalizer, exists := registry[strings.ToLower(vendor)]
	thisMu.RUnlock()

	// 1. Normalize the raw number to a standard 0-100 scale
	var standardScore int
	if exists {
		standardScore = normalizer(rawScore)
	} else {
		// Default fallback: Assume the number is already 0-100
		standardScore = NormalizeStandardScale(rawScore)
	}
	// Apply weight
	weightedScore := int(float64(standardScore) * weight)
	finalScore := NormalizeStandardScale(weightedScore)

	// 2. Map the standard 0-100 score to your specific ThreatLevelID buckets
	return MapScoreToID(finalScore)
}

// RegisterNormalizer allows you to add or overwrite vendor logic at runtime/startup.
func RegisterNormalizer(vendor string, fn NormalizerFunc) {
	thisMu.Lock()
	defer thisMu.Unlock()
	registry[strings.ToLower(vendor)] = fn
}

// --- Reusable Strategies ---

// NormalizeStandardScale clamps a number to 0-100.
// Use this for vendors that already adhere to this percentage standard.
func NormalizeStandardScale(score int) int {
	if score < 0 {
		return 0
	}
	if score > 100 {
		return 100
	}
	return score
}

// --- Internal Mapping Logic ---

// mapScoreToID converts the standardized 0-100 score into your DB ID.
func MapScoreToID(score int) int {
	switch {
	case score == 0:
		return ThreatLevelSafe
	case score < 20:
		return ThreatLevelLow
	case score < 50:
		return ThreatLevelMedium
	case score < 80:
		return ThreatLevelHigh
	default:
		return ThreatLevelCritical
	}
}

func ScoreMispThreat(idStr string) int {
	id, _ := strconv.Atoi(idStr)
	switch id {
	case 1: // High
		return 90 // Maps to Critical/High
	case 2: // Medium
		return 50 // Maps to Medium
	case 3: // Low
		return 20 // Maps to Low
	case 4: // Undefined
		return 0 // Maps to Unknown/Safe
	default:
		return 0
	}
}

/*
vendorName := "Mandiant"
rawScore := 85 // You extracted this from the response

threatID := internal.GetThreatLevelID(vendorName, rawScore)

event.ThreatLevelID = threatID
*/
