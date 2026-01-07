package internal

import (
	"bytes"
	"testing"
)

func TestGetMispCategory(t *testing.T) {
	tests := []struct {
		inputType string
		want      string
	}{
		{"md5", "Payload delivery"},
		{"ip-src", "Network activity"},
		{"email-subject", "Payload delivery"},
		{"iban", "Financial fraud"},
		{"unknown-type", "Other"},
		{"url", "Network activity"},
	}

	for _, tt := range tests {
		got := GetMispCategory(tt.inputType)
		if got != tt.want {
			t.Errorf("GetMispCategory(%s) = %s; want %s", tt.inputType, got, tt.want)
		}
	}
}

func TestMergeJSONData(t *testing.T) {
	tests := []struct {
		name     string
		existing []byte
		new      []byte
		want     string // checking logical structure/content
	}{
		{
			name:     "Merge Two Objects",
			existing: []byte(`{"a":1}`),
			new:      []byte(`{"b":2}`),
			// Expected: [{"a":1},{"b":2}]
		},
		{
			name:     "Merge Array and Object",
			existing: []byte(`[{"a":1}]`),
			new:      []byte(`{"b":2}`),
			// Expected: [{"a":1},{"b":2}]
		},
		{
			name:     "Merge Object and Array",
			existing: []byte(`{"a":1}`),
			new:      []byte(`[{"b":2}]`),
			// Expected: [{"a":1},{"b":2}]
		},
		{
			name:     "Merge New Data into Empty Existing",
			existing: []byte{},
			new:      []byte(`{"a":1}`),
			// Expected: [{"a":1}]
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := MergeJSONData(tt.existing, tt.new)
			if err != nil {
				t.Fatalf("MergeJSONData failed: %v", err)
			}
			// Simple check to ensure brackets exist (actual order might vary, but for this simpler merger it should be append)
			if !bytes.Contains(got, tt.new[1:len(tt.new)-1]) {
				t.Errorf("Merged data missing new content. Got: %s", got)
			}
			if len(tt.existing) > 0 && !bytes.Contains(got, tt.existing[1:len(tt.existing)-1]) {
				t.Errorf("Merged data missing existing content. Got: %s", got)
			}
		})
	}
}
