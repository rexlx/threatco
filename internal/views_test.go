package internal

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestServer_LoginViewHandler(t *testing.T) {
	s := setupTestServer()
	req := httptest.NewRequest("GET", "/login", nil)
	rr := httptest.NewRecorder()

	s.LoginViewHandler(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", rr.Code)
	}
	if len(rr.Body.String()) == 0 {
		t.Error("expected non-empty response body")
	}
}

func TestServer_LogViewHandler(t *testing.T) {
	s := setupTestServer()
	req := httptest.NewRequest("GET", "/logs", nil)
	rr := httptest.NewRecorder()

	s.LogViewHandler(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", rr.Code)
	}
}

func TestServer_AllUsersViewHandler(t *testing.T) {
	s := setupTestServer()
	db := s.DB.(*MockDB)

	adminUser := User{
		Email: "admin@threat.co",
		Admin: true,
	}
	normalUser := User{
		Email: "user@threat.co",
		Admin: false,
	}
	db.users = []User{adminUser, normalUser}

	req := httptest.NewRequest("GET", "/users?q=admin", nil)
	ctx := context.WithValue(req.Context(), "email", "admin@threat.co")
	req = req.WithContext(ctx)

	rr := httptest.NewRecorder()
	s.AllUsersViewHandler(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", rr.Code)
	}
	if !strings.Contains(rr.Body.String(), "admin@threat.co") {
		t.Errorf("expected response to contain 'admin@threat.co'")
	}
}

func TestBuildPaginationControls(t *testing.T) {
	s := setupTestServer()

	// Single page -> no controls
	html1 := s.buildPaginationControls(1, 1, "")
	if html1 != "" {
		t.Errorf("expected empty string for single page pagination, got '%s'", html1)
	}

	// Multiple pages
	html2 := s.buildPaginationControls(2, 10, "searchterm")
	if !strings.Contains(html2, "page=1") || !strings.Contains(html2, "q=searchterm") {
		t.Errorf("expected pagination controls to include page numbers and search query, got '%s'", html2)
	}
}
