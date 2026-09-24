package internal

import (
	"bytes"
	"encoding/json"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestContainsMatch(t *testing.T) {
	// Single item with matched: true
	matchEvent, _ := json.Marshal(SummarizedEvent{Matched: true})
	if !containsMatch(matchEvent) {
		t.Error("expected containsMatch to return true for matched event")
	}

	// Single item with matched: false
	noMatchEvent, _ := json.Marshal(SummarizedEvent{Matched: false})
	if containsMatch(noMatchEvent) {
		t.Error("expected containsMatch to return false for non-matched event")
	}

	// Array with one matched event
	arrayEvent, _ := json.Marshal([]SummarizedEvent{{Matched: false}, {Matched: true}})
	if !containsMatch(arrayEvent) {
		t.Error("expected containsMatch to return true for array containing matched event")
	}

	// Empty bytes
	if containsMatch([]byte{}) {
		t.Error("expected containsMatch to return false for empty bytes")
	}
}

func TestPaginateResponses(t *testing.T) {
	items := []ResponseItem{
		{ID: "1"}, {ID: "2"}, {ID: "3"}, {ID: "4"}, {ID: "5"},
	}

	res1 := paginateResponses(items, 0, 2)
	if len(res1) != 2 || res1[0].ID != "1" || res1[1].ID != "2" {
		t.Errorf("expected items 1 and 2, got %+v", res1)
	}

	res2 := paginateResponses(items, 3, 5)
	if len(res2) != 2 || res2[0].ID != "4" || res2[1].ID != "5" {
		t.Errorf("expected items 4 and 5, got %+v", res2)
	}

	res3 := paginateResponses(items, 10, 2)
	if len(res3) != 0 {
		t.Errorf("expected empty slice for out-of-bounds start, got %+v", res3)
	}
}

func TestIsLikelyDomain(t *testing.T) {
	tests := []struct {
		input string
		want  bool
	}{
		{"example.com", true},
		{"sub.domain.co.uk", true},
		{"notadomain", false},
		{"user@domain.com", false},
		{"domain with spaces.com", false},
	}

	for _, tt := range tests {
		got := isLikelyDomain(tt.input)
		if got != tt.want {
			t.Errorf("isLikelyDomain(%s) = %v, want %v", tt.input, got, tt.want)
		}
	}
}

func TestDeriveKey(t *testing.T) {
	password := "myPassword123"
	salt := []byte("randomSalt123456")

	key1 := DeriveKey(password, salt)
	key2 := DeriveKey(password, salt)

	if len(key1) != 32 {
		t.Errorf("expected key length 32, got %d", len(key1))
	}
	if !bytes.Equal(key1, key2) {
		t.Error("DeriveKey should be deterministic for same input")
	}

	key3 := DeriveKey("differentPassword", salt)
	if bytes.Equal(key1, key3) {
		t.Error("DeriveKey should produce different keys for different passwords")
	}
}

func TestNormalizeSeverity(t *testing.T) {
	tests := []struct {
		rawString     string
		scoreFallback string
		want          string
	}{
		{"critical", "", "critical"},
		{"HIGH", "", "high"},
		{"medium", "", "warning"},
		{"low", "", "info"},
		{"", "9.5", "critical"},
		{"", "7.5", "high"},
		{"", "5.0", "warning"},
		{"", "2.0", "info"},
	}

	for _, tt := range tests {
		got := NormalizeSeverity(tt.rawString, tt.scoreFallback)
		if got != tt.want {
			t.Errorf("NormalizeSeverity(%s, %s) = %s, want %s", tt.rawString, tt.scoreFallback, got, tt.want)
		}
	}
}

func TestToolsGenerateUUIDHandler(t *testing.T) {
	s := setupTestServer()
	req := httptest.NewRequest("GET", "/tools/uuid", nil)
	rr := httptest.NewRecorder()

	s.ToolsGenerateUUIDHandler(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", rr.Code)
	}
	if !strings.Contains(rr.Body.String(), "uuid") {
		t.Errorf("expected response to contain 'uuid'")
	}
}

func TestToolsGeneratePasswordHandler(t *testing.T) {
	s := setupTestServer()
	body := strings.NewReader(`{"length":16,"upper":true,"lower":true}`)
	req := httptest.NewRequest("POST", "/tools/password", body)
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	s.ToolsGeneratePasswordHandler(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", rr.Code)
	}
	var res map[string]string
	json.Unmarshal(rr.Body.Bytes(), &res)
	if len(res["password"]) != 16 {
		t.Errorf("expected password length 16, got %d", len(res["password"]))
	}
}

func TestToolsChecksumHandler(t *testing.T) {
	s := setupTestServer()

	var buf bytes.Buffer
	writer := multipart.NewWriter(&buf)
	part, err := writer.CreateFormFile("file", "test.txt")
	if err != nil {
		t.Fatalf("failed to create form file: %v", err)
	}
	part.Write([]byte("hello world"))
	writer.Close()

	req := httptest.NewRequest("POST", "/tools/checksum", &buf)
	req.Header.Set("Content-Type", writer.FormDataContentType())

	rr := httptest.NewRecorder()
	s.ToolsChecksumHandler(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", rr.Code)
	}
	if len(rr.Body.String()) == 0 {
		t.Error("expected non-empty checksum response")
	}
}

func TestAIReportCache(t *testing.T) {
	s := setupTestServer()

	// 1. Check status for non-existent report
	reqCheck := httptest.NewRequest("GET", "/aireport/check?id=CVE-2026-99999", nil)
	rrCheck := httptest.NewRecorder()
	s.AIReportCheckHandler(rrCheck, reqCheck)

	if rrCheck.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", rrCheck.Code)
	}
	var checkRes map[string]interface{}
	json.Unmarshal(rrCheck.Body.Bytes(), &checkRes)
	if checkRes["exists"] != false {
		t.Errorf("expected exists=false for new CVE, got %v", checkRes["exists"])
	}

	// 2. Save a report manually
	s.saveCachedAIReport("CVE-2026-99999", "<h1>Test Report</h1>")

	// 3. Check status again -> should exist
	rrCheck2 := httptest.NewRecorder()
	s.AIReportCheckHandler(rrCheck2, reqCheck)
	if rrCheck2.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", rrCheck2.Code)
	}
	var checkRes2 map[string]interface{}
	json.Unmarshal(rrCheck2.Body.Bytes(), &checkRes2)
	if checkRes2["exists"] != true {
		t.Errorf("expected exists=true after caching, got %v", checkRes2["exists"])
	}

	// 4. Call AIReportHandler -> should return cached HTML directly
	s.Details.LlmConf.Enabled = true
	reqReport := httptest.NewRequest("GET", "/aireport?id=CVE-2026-99999", nil)
	rrReport := httptest.NewRecorder()
	s.AIReportHandler(rrReport, reqReport)

	if rrReport.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", rrReport.Code)
	}
	if !strings.Contains(rrReport.Body.String(), "<h1>Test Report</h1>") {
		t.Errorf("expected cached report body, got %s", rrReport.Body.String())
	}
}

func TestGenerateCaseAIReportHandler(t *testing.T) {
	s := setupTestServer()
	s.Details.LlmConf.Enabled = true

	// Create a test case in mock DB
	c := Case{
		ID:          "case-ai-test-1",
		Name:        "Case for CVE-2026-8888",
		Description: "Test description for case",
		Status:      "Open",
		IOCs:        []string{"CVE-2026-8888", "1.1.1.1"},
	}
	s.DB.CreateCase(c)

	// Save a cached report for CVE-2026-8888
	s.saveCachedAIReport("CVE-2026-8888", "<html>Case Report</html>")

	// Call GenerateCaseAIReportHandler without force -> should link cached report
	body := strings.NewReader(`{"id":"case-ai-test-1","force":false}`)
	req := httptest.NewRequest("POST", "/cases/aireport", body)
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	s.GenerateCaseAIReportHandler(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", rr.Code)
	}

	var res map[string]interface{}
	json.Unmarshal(rr.Body.Bytes(), &res)
	if res["ai_report"] != "<html>Case Report</html>" {
		t.Errorf("expected ai_report to be '<html>Case Report</html>', got %v", res["ai_report"])
	}

	// Verify case in DB now has AIReport populated
	updatedCase, _ := s.DB.GetCase("case-ai-test-1")
	if updatedCase.AIReport != "<html>Case Report</html>" {
		t.Errorf("expected updatedCase.AIReport to be populated, got '%s'", updatedCase.AIReport)
	}
}
