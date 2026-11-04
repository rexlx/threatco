package internal

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestGetVisitor(t *testing.T) {
	limiter1 := getVisitor("127.0.0.1")
	if limiter1 == nil {
		t.Fatal("expected limiter1 to be non-nil")
	}

	limiter2 := getVisitor("127.0.0.1")
	if limiter1 != limiter2 {
		t.Errorf("expected same limiter for same IP")
	}

	limiter3 := getVisitor("10.0.0.1")
	if limiter1 == limiter3 {
		t.Errorf("expected different limiters for different IPs")
	}
}

func TestServer_CORSMiddleware(t *testing.T) {
	s := setupTestServer()
	s.Details.CorsOrigins = []string{"https://app.threat.co", "http://localhost:3000"}

	nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
	})

	corsHandler := s.CORSMiddleware(nextHandler)

	// Allowed origin
	req := httptest.NewRequest("GET", "/api/test", nil)
	req.Header.Set("Origin", "https://app.threat.co")
	rr := httptest.NewRecorder()
	corsHandler.ServeHTTP(rr, req)

	if rr.Header().Get("Access-Control-Allow-Origin") != "https://app.threat.co" {
		t.Errorf("expected origin header to be 'https://app.threat.co', got '%s'", rr.Header().Get("Access-Control-Allow-Origin"))
	}

	// Disallowed origin
	reqBad := httptest.NewRequest("GET", "/api/test", nil)
	reqBad.Header.Set("Origin", "https://evil.com")
	rrBad := httptest.NewRecorder()
	corsHandler.ServeHTTP(rrBad, reqBad)

	if rrBad.Header().Get("Access-Control-Allow-Origin") != "null" {
		t.Errorf("expected origin header to be 'null' for unauthorized origin")
	}

	// Preflight OPTIONS request
	reqOptions := httptest.NewRequest("OPTIONS", "/api/test", nil)
	reqOptions.Header.Set("Origin", "https://app.threat.co")
	rrOptions := httptest.NewRecorder()
	corsHandler.ServeHTTP(rrOptions, reqOptions)

	if rrOptions.Code != http.StatusNoContent {
		t.Errorf("expected status 204 for OPTIONS request, got %d", rrOptions.Code)
	}
}

func TestServer_ValidateSessionToken(t *testing.T) {
	s := setupTestServer()
	mockDb := s.DB.(*MockDB)

	// Add user with encrypted key
	rawKey := "user-api-key-123"
	encKey, _ := s.Encrypt(rawKey)
	u := User{
		Email: "testuser@threat.co",
		Key:   encKey,
	}
	mockDb.users = append(mockDb.users, u)

	handler := s.Session.LoadAndSave(s.ValidateSessionToken(func(w http.ResponseWriter, r *http.Request) {
		email := r.Context().Value("email")
		if email != "testuser@threat.co" {
			http.Error(w, "Wrong user", http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("authenticated"))
	}))

	// Valid Authorization header test
	req := httptest.NewRequest("GET", "/protected", nil)
	req.Header.Set("Authorization", "testuser@threat.co:user-api-key-123")
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d (body: %s)", rr.Code, rr.Body.String())
	}

	// Invalid header format
	reqBad := httptest.NewRequest("GET", "/protected", nil)
	reqBad.Header.Set("Authorization", "invalid_header_format")
	rrBad := httptest.NewRecorder()

	handler.ServeHTTP(rrBad, reqBad)

	if rrBad.Code != http.StatusSeeOther {
		t.Errorf("expected status 303 redirect for invalid token format, got %d", rrBad.Code)
	}
}

func TestServer_ProtectedFileServer(t *testing.T) {
	tempDir := t.TempDir()
	os.WriteFile(filepath.Join(tempDir, "test.txt"), []byte("Protected File Content"), 0644)

	s := setupTestServer()
	mockDb := s.DB.(*MockDB)
	rawKey := "user-api-key-456"
	encKey, _ := s.Encrypt(rawKey)
	mockDb.users = append(mockDb.users, User{
		Email: "fileuser@threat.co",
		Key:   encKey,
	})

	fs := http.Dir(tempDir)
	protectedFS := s.Session.LoadAndSave(s.ProtectedFileServer(fs))

	req := httptest.NewRequest("GET", "/test.txt", nil)
	req.Header.Set("Authorization", "fileuser@threat.co:user-api-key-456")
	rr := httptest.NewRecorder()

	protectedFS.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", rr.Code)
	}
}

func TestServer_RateLimit(t *testing.T) {
	s := setupTestServer()
	nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
	})
	rateLimitedHandler := s.RateLimit(nextHandler)

	// Single request should succeed
	req := httptest.NewRequest("GET", "/api/data", nil)
	req.RemoteAddr = "192.0.2.1:12345"
	rr := httptest.NewRecorder()
	rateLimitedHandler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected status 200 on initial request, got %d", rr.Code)
	}

	// Burst beyond rate limiter capacity
	var hitLimit bool
	for i := 0; i < 50; i++ {
		reqBurst := httptest.NewRequest("GET", "/api/data", nil)
		reqBurst.RemoteAddr = "192.0.2.1:12345"
		rrBurst := httptest.NewRecorder()
		rateLimitedHandler.ServeHTTP(rrBurst, reqBurst)
		if rrBurst.Code == http.StatusTooManyRequests {
			hitLimit = true
			break
		}
	}

	if !hitLimit {
		t.Error("expected rate limit to trigger HTTP 429 Too Many Requests after burst")
	}
}

func TestServer_ValidateSessionToken_SessionCookie(t *testing.T) {
	s := setupTestServer()
	mockDb := s.DB.(*MockDB)

	validToken := Token{
		Token:     "session-token-valid",
		Email:     "sessionuser@threat.co",
		ExpiresAt: time.Now().Add(1 * time.Hour),
	}
	expiredToken := Token{
		Token:     "session-token-expired",
		Email:     "sessionuser@threat.co",
		ExpiresAt: time.Now().Add(-1 * time.Hour),
	}
	mockDb.SaveToken(validToken)
	mockDb.SaveToken(expiredToken)

	nextCalled := false
	handler := s.ValidateSessionToken(func(w http.ResponseWriter, r *http.Request) {
		nextCalled = true
		email := r.Context().Value("email")
		if email != "sessionuser@threat.co" {
			http.Error(w, "incorrect email in context", http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("authenticated via cookie"))
	})

	// 1. Valid session token in session context
	wrappedValid := s.Session.LoadAndSave(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.Session.Put(r.Context(), "token", "session-token-valid")
		handler.ServeHTTP(w, r)
	}))

	reqValid := httptest.NewRequest("GET", "/protected", nil)
	rrValid := httptest.NewRecorder()
	wrappedValid.ServeHTTP(rrValid, reqValid)

	if rrValid.Code != http.StatusOK {
		t.Errorf("expected status 200 for valid session token, got %d: %s", rrValid.Code, rrValid.Body.String())
	}
	if !nextCalled {
		t.Error("expected next handler to be called for valid session token")
	}
	if rrValid.Header().Get("Content-Security-Policy") == "" {
		t.Error("expected CSP header to be set")
	}

	// 2. Expired session token in session context
	wrappedExpired := s.Session.LoadAndSave(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.Session.Put(r.Context(), "token", "session-token-expired")
		handler.ServeHTTP(w, r)
	}))

	reqExpired := httptest.NewRequest("GET", "/protected", nil)
	rrExpired := httptest.NewRecorder()
	wrappedExpired.ServeHTTP(rrExpired, reqExpired)

	if rrExpired.Code != http.StatusUnauthorized {
		t.Errorf("expected status 401 for expired session token, got %d", rrExpired.Code)
	}

	// 3. Header fallback with wrong key
	rawKey := "correct-api-key"
	encKey, _ := s.Encrypt(rawKey)
	mockDb.users = append(mockDb.users, User{
		Email: "wrongkeyuser@threat.co",
		Key:   encKey,
	})

	wrappedHeader := s.Session.LoadAndSave(http.HandlerFunc(handler))
	reqWrongKey := httptest.NewRequest("GET", "/protected", nil)
	reqWrongKey.Header.Set("Authorization", "wrongkeyuser@threat.co:wrong-key")
	rrWrongKey := httptest.NewRecorder()
	wrappedHeader.ServeHTTP(rrWrongKey, reqWrongKey)

	if rrWrongKey.Code != http.StatusUnauthorized {
		t.Errorf("expected status 401 for wrong API key in header, got %d", rrWrongKey.Code)
	}
}
