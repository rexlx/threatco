package internal

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
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
	if ep.InFlight != 0 {
		t.Errorf("expected InFlight to return to 0 after request, got %d", ep.InFlight)
	}
}

func TestEndpoint_Do_RateLimited(t *testing.T) {
	respCh := make(chan ResponseItem, 1)
	ep := NewEndpoint("https://example.com", &BearerAuth{Token: "tok"}, false, respCh, "rate-ep")
	ep.RateLimited = true
	ep.MaxRequests = 1
	ep.RefillRate = 10 * time.Second
	ep.RateMark = time.Now()
	ep.WindowCount = 1

	req, _ := http.NewRequest("GET", "https://example.com", nil)
	_, err := ep.Do("", req)
	if err != ErrRateLimited {
		t.Errorf("expected ErrRateLimited, got %v", err)
	}
}

func TestEndpoint_Do_RateLimitWindowAndRefill(t *testing.T) {
	var hits int32
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
	}))
	defer ts.Close()

	respCh := make(chan ResponseItem, 1)
	ep := NewEndpoint(ts.URL, &BearerAuth{Token: "tok"}, false, respCh, "window-ep")
	ep.RateLimited = true
	ep.MaxRequests = 2
	ep.RefillRate = 80 * time.Millisecond

	// Send 2 sequential requests (should both succeed despite fast completion)
	for i := 0; i < 2; i++ {
		req, _ := http.NewRequest("GET", ts.URL, nil)
		if _, err := ep.Do("", req); err != nil {
			t.Fatalf("request %d failed unexpectedly: %v", i+1, err)
		}
	}

	// 3rd request inside the same window must be rate limited
	req3, _ := http.NewRequest("GET", ts.URL, nil)
	if _, err := ep.Do("", req3); err != ErrRateLimited {
		t.Fatalf("expected ErrRateLimited on 3rd request, got %v", err)
	}

	if ep.InFlight != 0 {
		t.Errorf("expected InFlight to be 0, got %d", ep.InFlight)
	}

	// Wait for RefillRate window to expire
	time.Sleep(100 * time.Millisecond)

	// 4th request should succeed after refill
	req4, _ := http.NewRequest("GET", ts.URL, nil)
	if _, err := ep.Do("", req4); err != nil {
		t.Fatalf("expected request after refill to succeed, got %v", err)
	}

	if got := atomic.LoadInt32(&hits); got != 3 {
		t.Errorf("expected server to receive 3 requests total, got %d", got)
	}
}

func TestEndpoint_Do_ConcurrentBurst(t *testing.T) {
	var hits int32
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		time.Sleep(15 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
	}))
	defer ts.Close()

	respCh := make(chan ResponseItem, 1)
	ep := NewEndpoint(ts.URL, &BearerAuth{Token: "tok"}, false, respCh, "burst-ep")
	ep.RateLimited = true
	ep.MaxRequests = 3
	ep.RefillRate = 5 * time.Second

	const totalGoroutines = 10
	var wg sync.WaitGroup
	var allowed, limited int32

	for i := 0; i < totalGoroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			req, _ := http.NewRequest("GET", ts.URL, nil)
			_, err := ep.Do("", req)
			if err == nil {
				atomic.AddInt32(&allowed, 1)
			} else if err == ErrRateLimited {
				atomic.AddInt32(&limited, 1)
			} else {
				t.Errorf("unexpected error: %v", err)
			}
		}()
	}
	wg.Wait()

	if allowed != 3 {
		t.Errorf("expected exactly 3 allowed requests, got %d", allowed)
	}
	if limited != 7 {
		t.Errorf("expected exactly 7 rate-limited requests, got %d", limited)
	}
	if ep.InFlight != 0 {
		t.Errorf("expected InFlight to be 0 after burst, got %d", ep.InFlight)
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

	tests := []struct {
		name  string
		auth  AuthMethod
		check func(t *testing.T, req *http.Request)
	}{
		{
			name: "URLScanAuth",
			auth: &URLScanAuth{Token: "urlscan-key"},
			check: func(t *testing.T, req *http.Request) {
				if req.Header.Get("api-key") != "urlscan-key" {
					t.Errorf("expected api-key 'urlscan-key', got '%s'", req.Header.Get("api-key"))
				}
			},
		},
		{
			name: "URLScanAuth_DefaultToken",
			auth: &URLScanAuth{},
			check: func(t *testing.T, req *http.Request) {
				if req.Header.Get("api-key") != "threatco" {
					t.Errorf("expected default api-key 'threatco', got '%s'", req.Header.Get("api-key"))
				}
			},
		},
		{
			name: "PrefetchAuth",
			auth: &PrefetchAuth{AppName: "myapp", Token: "mytoken"},
			check: func(t *testing.T, req *http.Request) {
				if req.Header.Get("X-App-Name") != "myapp" {
					t.Errorf("expected X-App-Name 'myapp', got '%s'", req.Header.Get("X-App-Name"))
				}
				if req.Header.Get("Authorization") != "Bearer mytoken" {
					t.Errorf("expected Authorization 'Bearer mytoken', got '%s'", req.Header.Get("Authorization"))
				}
			},
		},
		{
			name: "XAPIKeyAuth",
			auth: &XAPIKeyAuth{Token: "vt-key"},
			check: func(t *testing.T, req *http.Request) {
				if req.Header.Get("x-apikey") != "vt-key" {
					t.Errorf("expected x-apikey 'vt-key', got '%s'", req.Header.Get("x-apikey"))
				}
			},
		},
		{
			name: "VmRayAuth",
			auth: &VmRayAuth{Token: "vm-token"},
			check: func(t *testing.T, req *http.Request) {
				if req.Header.Get("Authorization") != "api_key vm-token" {
					t.Errorf("expected Authorization 'api_key vm-token', got '%s'", req.Header.Get("Authorization"))
				}
			},
		},
		{
			name: "BearerAuth",
			auth: &BearerAuth{Token: "bearer-token"},
			check: func(t *testing.T, req *http.Request) {
				if req.Header.Get("Authorization") != "Bearer bearer-token" {
					t.Errorf("expected Authorization 'Bearer bearer-token', got '%s'", req.Header.Get("Authorization"))
				}
			},
		},
		{
			name: "KeyAuth",
			auth: &KeyAuth{Token: "custom-key"},
			check: func(t *testing.T, req *http.Request) {
				if req.Header.Get("Authorization") != "custom-key" {
					t.Errorf("expected Authorization 'custom-key', got '%s'", req.Header.Get("Authorization"))
				}
			},
		},
		{
			name: "BasicAuth",
			auth: &BasicAuth{Username: "user", Password: "pass"},
			check: func(t *testing.T, req *http.Request) {
				user, pass, ok := req.BasicAuth()
				if !ok || user != "user" || pass != "pass" {
					t.Errorf("BasicAuth Apply failed: got user=%q, pass=%q, ok=%v", user, pass, ok)
				}
			},
		},
		{
			name: "AbuseIPDBAuth",
			auth: &AbuseIPDBAuth{Token: "abuse-key"},
			check: func(t *testing.T, req *http.Request) {
				if req.Header.Get("Key") != "abuse-key" {
					t.Errorf("expected Key 'abuse-key', got '%s'", req.Header.Get("Key"))
				}
			},
		},
		{
			name: "OTXAuth",
			auth: &OTXAuth{Token: "otx-key"},
			check: func(t *testing.T, req *http.Request) {
				if req.Header.Get("X-OTX-API-KEY") != "otx-key" {
					t.Errorf("expected X-OTX-API-KEY 'otx-key', got '%s'", req.Header.Get("X-OTX-API-KEY"))
				}
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// Skip PrefetchAuth's background goroutine here; tested separately below
			if _, isPrefetch := tc.auth.(*PrefetchAuth); !isPrefetch {
				tc.auth.GetAndStoreToken(stop)
			}
			req, _ := http.NewRequest("GET", "https://api.example.com", nil)
			tc.auth.Apply(req)
			tc.check(t, req)
		})
	}

	baAuth := &BasicAuth{Username: "user", Password: "pass"}
	if u, p := baAuth.GetInfo(); u != "user" || p != "pass" {
		t.Errorf("BasicAuth GetInfo returned invalid credentials: %s, %s", u, p)
	}
}

func TestPrefetchAuth_GetAndStoreToken(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"access_token": "refreshed-oauth-token",
			"expires_in":   3600,
			"token_type":   "Bearer",
		})
	}))
	defer ts.Close()

	pAuth := &PrefetchAuth{
		AppName: "myapp",
		URL:     ts.URL,
		Key:     "client-id",
		Secret:  "client-secret",
		Expires: 10,
	}

	stop := make(chan bool)
	done := make(chan struct{})
	go func() {
		pAuth.GetAndStoreToken(stop)
		close(done)
	}()

	// Poll briefly until token is populated, then shut down the goroutine
	deadline := time.Now().Add(1 * time.Second)
	for time.Now().Before(deadline) {
		if pAuth.Token == "refreshed-oauth-token" {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	close(stop)
	<-done

	if pAuth.Token != "refreshed-oauth-token" {
		t.Errorf("expected token 'refreshed-oauth-token', got '%s'", pAuth.Token)
	}
}
