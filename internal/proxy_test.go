package internal

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestVirusTotalProxyHelper_GTI(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/urls/aHR0cDovL21hbGljaW91cy5leGFtcGxl" {
			resp := map[string]interface{}{
				"data": map[string]interface{}{
					"id":   "aHR0cDovL21hbGljaW91cy5leGFtcGxl",
					"type": "url",
					"attributes": map[string]interface{}{
						"last_analysis_stats": map[string]interface{}{
							"harmless":   0,
							"malicious":  5,
							"suspicious": 1,
							"undetected": 10,
							"timeout":    0,
						},
						"gti_assessment": map[string]interface{}{
							"verdict":  "MALICIOUS",
							"severity": "HIGH",
						},
						"popular_threat_classification": map[string]interface{}{
							"suggested_threat_label": "phishing",
						},
						"threat_actors": []map[string]interface{}{
							{"name": "APT29"},
						},
						"mandiant_associations": []map[string]interface{}{
							{"name": "UNC2452"},
						},
					},
				},
			}
			json.NewEncoder(w).Encode(resp)
			return
		}
		http.NotFound(w, r)
	}))
	defer ts.Close()

	ep := NewEndpoint(ts.URL, &XAPIKeyAuth{Token: "test-key"}, false, nil, "gti")
	resch := make(chan ResponseItem, 1)

	req := ProxyRequest{
		Value:         "http://malicious.example",
		Route:         "urls",
		Type:          "url",
		To:            "gti",
		TransactionID: "tx123",
		Username:      "user@example.com",
	}

	respBytes, err := VirusTotalProxyHelper(resch, ep, req)
	if err != nil {
		t.Fatalf("VirusTotalProxyHelper returned error: %v", err)
	}

	var sum SummarizedEvent
	if err := json.Unmarshal(respBytes, &sum); err != nil {
		t.Fatalf("Failed to unmarshal summary: %v", err)
	}

	if !sum.Matched {
		t.Errorf("Expected sum.Matched to be true")
	}

	if sum.ThreatLevelID < ThreatLevelHigh {
		t.Errorf("Expected ThreatLevelID >= High, got %d", sum.ThreatLevelID)
	}

	select {
	case item := <-resch:
		if item.Vendor != "gti" {
			t.Errorf("Expected item.Vendor to be 'gti', got %s", item.Vendor)
		}
	default:
		t.Errorf("Expected item on response channel")
	}
}

func TestVirusTotalProxyHelper_LegacyVT(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/files/44d88612fea8a8f36de82e1278abb02f" {
			// Standard legacy VT v3 response without any GTI or Mandiant fields
			resp := map[string]interface{}{
				"data": map[string]interface{}{
					"id":   "44d88612fea8a8f36de82e1278abb02f",
					"type": "file",
					"attributes": map[string]interface{}{
						"last_analysis_stats": map[string]interface{}{
							"harmless":   60,
							"malicious":  12,
							"suspicious": 2,
							"undetected": 5,
							"timeout":    0,
						},
						"tags": []string{"eicar", "trojan"},
					},
				},
			}
			json.NewEncoder(w).Encode(resp)
			return
		}
		http.NotFound(w, r)
	}))
	defer ts.Close()

	ep := NewEndpoint(ts.URL, &XAPIKeyAuth{Token: "standard-free-vt-key"}, false, nil, "virustotal")
	resch := make(chan ResponseItem, 1)

	req := ProxyRequest{
		Value:         "44d88612fea8a8f36de82e1278abb02f",
		Route:         "files",
		Type:          "md5",
		To:            "virustotal",
		TransactionID: "tx456",
		Username:      "freeuser@example.com",
	}

	respBytes, err := VirusTotalProxyHelper(resch, ep, req)
	if err != nil {
		t.Fatalf("VirusTotalProxyHelper returned error: %v", err)
	}

	var sum SummarizedEvent
	if err := json.Unmarshal(respBytes, &sum); err != nil {
		t.Fatalf("Failed to unmarshal summary: %v", err)
	}

	if !sum.Matched {
		t.Errorf("Expected sum.Matched to be true for 12 malicious detections")
	}

	expectedInfo := "harmless: 60, malicious: 12, suspicious: 2, undetected: 5, timeout: 0"
	if sum.Info != expectedInfo {
		t.Errorf("Expected sum.Info to be %q, got %q", expectedInfo, sum.Info)
	}

	if sum.Background != "has-background-warning-dark" {
		t.Errorf("Expected background 'has-background-warning-dark', got %q", sum.Background)
	}

	if sum.AttrCount != 2 {
		t.Errorf("Expected AttrCount 2 (for tags), got %d", sum.AttrCount)
	}
}
