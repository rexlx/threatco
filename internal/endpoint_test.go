package internal

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestNewEndpoint(t *testing.T) {
	respCh := make(chan ResponseItem, 1)

	epSecure := NewEndpoint("https://example.com", &BearerAuth{Token: "test"}, false, respCh, "ep1")
	if epSecure.GetURL() != "https://example.com" {
		t.Errorf("expected URL 'https://example.com', got '%s'", epSecure.GetURL())
	}
	if epSecure.GetAuth() == nil {
		t.Error("expected Auth to be set")
	}

	epInsecure := NewEndpoint("https://insecure.example.com", &BearerAuth{Token: "test"}, true, respCh, "ep2")
	if epInsecure.GetURL() != "https://insecure.example.com" {
		t.Errorf("expected URL 'https://insecure.example.com', got '%s'", epInsecure.GetURL())
	}

	epSecure.SetAuth(&KeyAuth{Token: "newkey"})
	if _, ok := epSecure.GetAuth().(*KeyAuth); !ok {
		t.Errorf("expected Auth to be KeyAuth")
	}
}

func TestEndpoint_Do(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer secret-token" {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok response"))
	}))
	defer ts.Close()

	respCh := make(chan ResponseItem, 1)
	ep := NewEndpoint(ts.URL, &BearerAuth{Token: "secret-token"}, false, respCh, "test-ep")

	req, _ := http.NewRequest("GET", ts.URL, nil)
	resp, err := ep.Do("", req)
	if err != nil {
		t.Fatalf("Endpoint.Do failed: %v", err)
	}

	if string(resp) != "ok response" {
		t.Errorf("expected 'ok response', got '%s'", string(resp))
	}
}

func TestEndpoint_Do_RateLimited(t *testing.T) {
	respCh := make(chan ResponseItem, 1)
	ep := NewEndpoint("https://example.com", &BearerAuth{Token: "tok"}, false, respCh, "rate-ep")
	ep.RateLimited = true
	ep.MaxRequests = 1
	ep.InFlight = 1

	req, _ := http.NewRequest("GET", "https://example.com", nil)
	_, err := ep.Do("", req)
	if err != ErrRateLimited {
		t.Errorf("expected ErrRateLimited, got %v", err)
	}
}

func TestEndpoint_ProcessQueue(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("queue response"))
	}))
	defer ts.Close()

	respCh := make(chan ResponseItem, 5)
	ep := NewEndpoint(ts.URL, &BearerAuth{Token: "tok"}, false, respCh, "queue-ep")
	ep.MaxRequests = 5

	req, _ := http.NewRequest("GET", ts.URL, nil)
	ep.Backlog = []*http.Request{req}

	ep.ProcessQueue("req-123")

	select {
	case res := <-respCh:
		if res.ID != "req-123" {
			t.Errorf("expected ID 'req-123', got '%s'", res.ID)
		}
		if string(res.Data) != "queue response" {
			t.Errorf("expected 'queue response', got '%s'", string(res.Data))
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for queue processing")
	}
}

func TestAuthMethods_Apply(t *testing.T) {
	stop := make(chan bool, 1)

	// URLScanAuth
	uAuth := &URLScanAuth{Token: "urlscan-key"}
	uAuth.GetAndStoreToken(stop)
	req, _ := http.NewRequest("GET", "https://api.urlscan.io", nil)
	uAuth.Apply(req)
	if req.Header.Get("api-key") != "urlscan-key" {
		t.Errorf("URLScanAuth failed to set api-key header")
	}

	// PrefetchAuth
	pAuth := &PrefetchAuth{AppName: "myapp", Token: "mytoken"}
	pAuth.Apply(req)
	if req.Header.Get("X-App-Name") != "myapp" || req.Header.Get("Authorization") != "Bearer mytoken" {
		t.Errorf("PrefetchAuth failed to set headers")
	}

	// XAPIKeyAuth
	xAuth := &XAPIKeyAuth{Token: "vt-key"}
	xAuth.GetAndStoreToken(stop)
	xAuth.Apply(req)
	if req.Header.Get("x-apikey") != "vt-key" {
		t.Errorf("XAPIKeyAuth failed to set x-apikey header")
	}

	// VmRayAuth
	vAuth := &VmRayAuth{Token: "vm-token"}
	vAuth.GetAndStoreToken(stop)
	vAuth.Apply(req)
	if req.Header.Get("Authorization") != "api_key vm-token" {
		t.Errorf("VmRayAuth failed to set Authorization header")
	}

	// BearerAuth
	bAuth := &BearerAuth{Token: "bearer-token"}
	bAuth.GetAndStoreToken(stop)
	bAuth.Apply(req)
	if req.Header.Get("Authorization") != "Bearer bearer-token" {
		t.Errorf("BearerAuth failed to set Authorization header")
	}

	// KeyAuth
	kAuth := &KeyAuth{Token: "custom-key"}
	kAuth.GetAndStoreToken(stop)
	kAuth.Apply(req)
	if req.Header.Get("Authorization") != "custom-key" {
		t.Errorf("KeyAuth failed to set Authorization header")
	}

	// BasicAuth
	baAuth := &BasicAuth{Username: "user", Password: "pass"}
	baAuth.GetAndStoreToken(stop)
	if u, p := baAuth.GetInfo(); u != "user" || p != "pass" {
		t.Errorf("BasicAuth GetInfo returned invalid credentials")
	}
	baAuth.Apply(req)
	user, pass, ok := req.BasicAuth()
	if !ok || user != "user" || pass != "pass" {
		t.Errorf("BasicAuth Apply failed to set basic auth")
	}

	// AbuseIPDBAuth
	aAuth := &AbuseIPDBAuth{Token: "abuse-key"}
	aAuth.GetAndStoreToken(stop)
	aAuth.Apply(req)
	if req.Header.Get("Key") != "abuse-key" {
		t.Errorf("AbuseIPDBAuth failed to set Key header")
	}
}
