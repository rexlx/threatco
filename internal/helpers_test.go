package internal

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
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
		{"vulnerability", "External analysis"},
		{"cve", "External analysis"},
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
	// Valid data array
	data := []byte(`[{"threat_level_id": 4}]`)
	tid, err := ExtractThreatLevelID(data)
	if err != nil || tid != 4 {
		t.Errorf("expected tid=4, got tid=%d, err=%v", tid, err)
	}

	// Valid single JSON object
	singleObj := []byte(`{"threat_level_id": 2, "id": "CVE-2026-1234"}`)
	tidSingle, err := ExtractThreatLevelID(singleObj)
	if err != nil || tidSingle != 2 {
		t.Errorf("expected tid=2, got tid=%d, err=%v", tidSingle, err)
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

func TestAddMispTag(t *testing.T) {
	var receivedTags []string
	createdTags := make(map[string]bool)

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/tags/add" {
			var payload struct {
				Tag struct {
					Name string `json:"name"`
				} `json:"Tag"`
			}
			if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
				t.Errorf("failed to decode tag creation body: %v", err)
			}
			if payload.Tag.Name == "uncreatable_tag" {
				w.Write([]byte(`{"saved": false, "errors": "Failed to create"}`))
			} else {
				createdTags[payload.Tag.Name] = true
				w.Write([]byte(`{"saved": true, "Tag": {"id": "100", "name": "` + payload.Tag.Name + `"}}`))
			}
			return
		}

		if r.URL.Path != "/events/addTag" {
			t.Errorf("unexpected path: %s", r.URL.Path)
			return
		}

		var payload struct {
			Request struct {
				Event struct {
					ID  string `json:"id"`
					Tag string `json:"tag"`
				} `json:"Event"`
			} `json:"request"`
		}
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			t.Errorf("failed to decode request body: %v", err)
		}
		if payload.Request.Event.ID != "1727" {
			t.Errorf("expected event ID '1727', got '%s'", payload.Request.Event.ID)
		}
		receivedTags = append(receivedTags, payload.Request.Event.Tag)

		if payload.Request.Event.Tag == "new_tag" && !createdTags["new_tag"] {
			w.Write([]byte(`{"saved": false, "errors": "Invalid Tag."}`))
		} else if payload.Request.Event.Tag == "uncreatable_tag" {
			w.Write([]byte(`{"saved": false, "errors": "Invalid Tag."}`))
		} else {
			w.Write([]byte(`{"saved": true, "success": "Tag added"}`))
		}
	}))
	defer ts.Close()

	s := setupTestServer()
	if s.Targets == nil {
		s.Targets = make(map[string]*Endpoint)
	}
	s.Targets["misp"] = NewEndpoint(ts.URL, &XAPIKeyAuth{Token: "test-key"}, false, nil, "misp")

	// 1. Test multiple comma-separated tags
	err := s.AddMispTag("1727", "Application:Threatco, tlp:amber")
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	if len(receivedTags) != 2 {
		t.Fatalf("expected 2 tags received, got %d: %v", len(receivedTags), receivedTags)
	}
	if receivedTags[0] != "Application:Threatco" || receivedTags[1] != "tlp:amber" {
		t.Errorf("unexpected tags received: %v", receivedTags)
	}

	// 2. Test auto-creation on Invalid Tag
	receivedTags = nil
	err = s.AddMispTag("1727", "new_tag")
	if err != nil {
		t.Fatalf("expected auto-creation to succeed for new_tag, got error: %v", err)
	}
	if !createdTags["new_tag"] {
		t.Errorf("expected new_tag to be auto-created in MISP")
	}

	// 3. Test failure when tag creation fails
	receivedTags = nil
	err = s.AddMispTag("1727", "uncreatable_tag")
	if err == nil {
		t.Errorf("expected error for uncreatable_tag, got nil")
	}
}
