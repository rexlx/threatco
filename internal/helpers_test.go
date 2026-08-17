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

func TestSign(t *testing.T) {
	sig := Sign("user1", "secretkey", "123456", "/v1/test")
	if sig == "" {
		t.Error("expected non-empty HMAC signature")
	}
	sig2 := Sign("user1", "secretkey", "123456", "/v1/test")
	if sig != sig2 {
		t.Error("Sign should be deterministic")
	}
}

func TestURLBuilders(t *testing.T) {
	req := ProxyRequest{
		Route: "iris",
		Type:  "domain",
		Value: "example.com",
	}

	url1 := WhoIsURLBuilder("https://api.domaintools.com", "uname", "key", "123", req)
	if !bytes.Contains([]byte(url1), []byte("domain=example.com")) {
		t.Errorf("WhoIsURLBuilder failed: %s", url1)
	}

	url2 := IrisProfileURLBuilder("https://api.domaintools.com", "uname", "key", "123", req)
	if !bytes.Contains([]byte(url2), []byte("/v1/iris/example.com")) {
		t.Errorf("IrisProfileURLBuilder failed: %s", url2)
	}
}

func TestTruncateString(t *testing.T) {
	s := "hello world"
	if got := truncateString(s, 5); got != "hello" {
		t.Errorf("expected 'hello', got '%s'", got)
	}
	if got := truncateString(s, 20); got != "hello world" {
		t.Errorf("expected 'hello world', got '%s'", got)
	}
}

func TestCleanUserServices(t *testing.T) {
	s := setupTestServer()
	s.Details.SupportedServices = []ServiceType{
		{Kind: "misp"},
		{Kind: "virustotal"},
	}

	user := &User{
		Email: "user@test.com",
		Services: []ServiceType{
			{Kind: "misp"},
			{Kind: "unsupported_kind"},
			{Kind: "virustotal"},
		},
	}

	s.CleanUserServices(user)

	if len(user.Services) != 2 {
		t.Errorf("expected 2 services after cleanup, got %d", len(user.Services))
	}
	for _, svc := range user.Services {
		if svc.Kind == "unsupported_kind" {
			t.Error("unsupported service should have been removed")
		}
	}
}

func TestExtractThreatLevelID(t *testing.T) {
	// Valid data
	data := []byte(`[{"threat_level_id": 4}]`)
	tid, err := ExtractThreatLevelID(data)
	if err != nil || tid != 4 {
		t.Errorf("expected tid=4, got tid=%d, err=%v", tid, err)
	}

	// Invalid JSON
	_, err = ExtractThreatLevelID([]byte(`invalid json`))
	if err == nil {
		t.Error("expected error for invalid json")
	}

	// Missing field
	_, err = ExtractThreatLevelID([]byte(`[{"other_field": 123}]`))
	if err == nil {
		t.Error("expected error for missing threat_level_id")
	}
}

func TestGetDBHost(t *testing.T) {
	t.Setenv("DB_HOST", "db.internal")
	host := GetDBHost()
	if host != "db.internal" {
		t.Errorf("expected 'db.internal', got '%s'", host)
	}
}

func TestRemoveTimestamp(t *testing.T) {
	input := "prefix_2026.suffix"
	res, err := RemoveTimestamp("_", input)
	if err != nil || res != "prefix.suffix" {
		t.Errorf("expected 'prefix.suffix', got '%s', err=%v", res, err)
	}
}
