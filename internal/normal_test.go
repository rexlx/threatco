package internal

import (
	"testing"
)

func TestNormalizeStandardScale(t *testing.T) {
	tests := []struct {
		input int
		want  int
	}{
		{-10, 0},
		{0, 0},
		{50, 50},
		{100, 100},
		{150, 100},
	}

	for _, tt := range tests {
		got := NormalizeStandardScale(tt.input)
		if got != tt.want {
			t.Errorf("NormalizeStandardScale(%d) = %d, want %d", tt.input, got, tt.want)
		}
	}
}

func TestMapScoreToID(t *testing.T) {
	tests := []struct {
		score int
		want  int
	}{
		{0, ThreatLevelSafe},
		{10, ThreatLevelLow},
		{19, ThreatLevelLow},
		{20, ThreatLevelMedium},
		{49, ThreatLevelMedium},
		{50, ThreatLevelHigh},
		{79, ThreatLevelHigh},
		{80, ThreatLevelCritical},
		{100, ThreatLevelCritical},
	}

	for _, tt := range tests {
		got := MapScoreToID(tt.score)
		if got != tt.want {
			t.Errorf("MapScoreToID(%d) = %d, want %d", tt.score, got, tt.want)
		}
	}
}

func TestScoreMispThreat(t *testing.T) {
	tests := []struct {
		input string
		want  int
	}{
		{"1", 90},
		{"2", 50},
		{"3", 20},
		{"4", 0},
		{"99", 0},
		{"invalid", 0},
	}

	for _, tt := range tests {
		got := ScoreMispThreat(tt.input)
		if got != tt.want {
			t.Errorf("ScoreMispThreat(%s) = %d, want %d", tt.input, got, tt.want)
		}
	}
}

func TestGetThreatLevelID(t *testing.T) {
	tests := []struct {
		vendor   string
		rawScore int
		weight   float64
		want     int
	}{
		{"cloudflare", 0, 1.0, ThreatLevelSafe},
		{"cloudflare", 50, 1.0, ThreatLevelHigh},
		{"cloudflare", 100, 1.0, ThreatLevelCritical},
		{"virustotal", 0, 1.0, ThreatLevelSafe},
		{"virustotal", 1, 1.0, ThreatLevelMedium},    // 1 hit -> 30 score -> Medium
		{"virustotal", 5, 1.0, ThreatLevelHigh},      // 5 hits -> 75 score -> High
		{"virustotal", 15, 1.0, ThreatLevelCritical}, // 15 hits -> 100 score -> Critical
		{"unknown_vendor", 0, 1.0, ThreatLevelSafe},
		{"unknown_vendor", 60, 1.0, ThreatLevelHigh},
	}

	for _, tt := range tests {
		got := GetThreatLevelID(tt.vendor, tt.rawScore, tt.weight)
		if got != tt.want {
			t.Errorf("GetThreatLevelID(%s, %d, %f) = %d, want %d", tt.vendor, tt.rawScore, tt.weight, got, tt.want)
		}
	}
}

func TestRegisterNormalizer(t *testing.T) {
	customVendor := "my_custom_vendor"
	RegisterNormalizer(customVendor, func(score int) int {
		return score * 2
	})

	got := GetThreatLevelID(customVendor, 25, 1.0)
	// 25 * 2 = 50 -> High
	if got != ThreatLevelHigh {
		t.Errorf("GetThreatLevelID with custom normalizer got %d, want %d", got, ThreatLevelHigh)
	}
}

func TestCalculateThreatWeight(t *testing.T) {
	tests := []struct {
		item VulnerabilityItem
		want float64
	}{
		{
			item: VulnerabilityItem{Source: "CISA", Description: "No CVSS info"},
			want: VulnWeightKEV,
		},
		{
			item: VulnerabilityItem{Source: "CISA", Description: "Contains CVSS3: 9.8 critical"},
			want: VulnWeightKEV + 20.0,
		},
		{
			item: VulnerabilityItem{Source: "Red Hat", Description: "Contains CVSS3: 2.1 low"},
			want: VulnWeightRedHat - 15.0,
		},
		{
			item: VulnerabilityItem{Source: "Canonical", Description: "Contains CVSS3: 5.4 medium"},
			want: VulnWeightCanonical - 5.0,
		},
		{
			item: VulnerabilityItem{Source: "Unknown", Description: "Default info"},
			want: 20.0,
		},
	}

	for _, tt := range tests {
		got := CalculateThreatWeight(tt.item)
		if got != tt.want {
			t.Errorf("CalculateThreatWeight(%+v) = %f, want %f", tt.item, got, tt.want)
		}
	}
}
