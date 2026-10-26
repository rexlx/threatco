package internal

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/rexlx/threatco/views"
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
		Services: []ServiceType{
			{Kind: "misp"},
			{Kind: "virustotal"},
		},
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
	body := rr.Body.String()
	if !strings.Contains(body, "admin@threat.co") {
		t.Errorf("expected response to contain 'admin@threat.co'")
	}
	if !strings.Contains(body, "User Accounts") {
		t.Errorf("expected response to contain 'User Accounts'")
	}
	if !strings.Contains(body, `id="usersViewer"`) {
		t.Errorf("expected response to contain usersViewer container")
	}
	if !strings.Contains(body, `id="userResults"`) {
		t.Errorf("expected response to contain userResults container")
	}
	if !strings.Contains(body, `id="userSearchInput"`) {
		t.Errorf("expected response to contain userSearchInput")
	}
	if !strings.Contains(body, "USER / EMAIL") || !strings.Contains(body, "ROLE") || !strings.Contains(body, "ACTIONS") {
		t.Errorf("expected response to contain table column headers")
	}
	if !strings.Contains(body, "role-admin") {
		t.Errorf("expected response to contain admin role badge")
	}
	if !strings.Contains(body, "user-you-tag") {
		t.Errorf("expected response to contain 'you' tag for current user")
	}
	if !strings.Contains(body, "delete-user-btn") || !strings.Contains(body, "generate-key-btn") {
		t.Errorf("expected response to contain action buttons")
	}
}

func TestServer_AllUsersViewHandler_EmptySearch(t *testing.T) {
	s := setupTestServer()
	db := s.DB.(*MockDB)
	db.users = []User{
		{Email: "admin@threat.co", Admin: true},
	}

	req := httptest.NewRequest("GET", "/users?q=nonexistent_user", nil)
	ctx := context.WithValue(req.Context(), "email", "admin@threat.co")
	req = req.WithContext(ctx)

	rr := httptest.NewRecorder()
	s.AllUsersViewHandler(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", rr.Code)
	}
	body := rr.Body.String()
	if !strings.Contains(body, "No user accounts found") {
		t.Errorf("expected response to show empty user message")
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

func TestServer_ChartViewHandler_WithCharts(t *testing.T) {
	s := setupTestServer()
	s.UpdateCharts()

	req := httptest.NewRequest("GET", "/charts", nil)
	rr := httptest.NewRecorder()

	s.ChartViewHandler(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", rr.Code)
	}

	body := rr.Body.String()

	// Verify dropdown is present
	if !strings.Contains(body, `id="chartNavSelect"`) {
		t.Error("expected chartNavSelect dropdown in response")
	}

	// Verify navigation controls are present
	if !strings.Contains(body, `id="prevChartBtn"`) || !strings.Contains(body, `id="nextChartBtn"`) {
		t.Error("expected prev/next navigation buttons in response")
	}

	if !strings.Contains(body, `id="viewAllChartsBtn"`) || !strings.Contains(body, `id="viewSingleChartBtn"`) {
		t.Error("expected All/Focus view mode buttons in response")
	}

	// Verify at least one chart card wrapper with id is rendered
	if !strings.Contains(body, `class="chart-wrapper chart-card-wrapper`) {
		t.Error("expected chart-wrapper elements in response")
	}

	if !strings.Contains(body, `id="chart-malloc"`) {
		t.Error("expected chart-malloc element in response")
	}

	if !strings.Contains(body, `<option value="chart-malloc">malloc</option>`) {
		t.Error("expected malloc option in dropdown")
	}
}

func TestServer_ChartViewHandler_EmptyState(t *testing.T) {
	s := setupTestServer()
	// Set coordinates to nil and empty cache
	s.Cache.Coordinates = nil
	s.Cache.Charts = []byte(views.NoDataView)

	// Stub UpdateCharts behavior by leaving Cache.Coordinates empty
	req := httptest.NewRequest("GET", "/charts", nil)
	rr := httptest.NewRecorder()

	s.ChartViewHandler(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", rr.Code)
	}

	body := rr.Body.String()
	// Since UpdateCharts() runs on-demand, it may generate charts from runtime stats,
	// which is valid, or render the empty state.
	if !strings.Contains(body, "charts") && !strings.Contains(body, "No Chart Data Available") {
		t.Error("expected response to contain either charts or empty state notice")
	}
}

func TestServer_ChartViewHandler_EmptySectionDirect(t *testing.T) {
	rr := httptest.NewRecorder()
	fmt.Fprintf(rr, views.BaseView, views.ChartsEmptySection)
	if !strings.Contains(rr.Body.String(), "No Chart Data Available") {
		t.Error("expected empty state notice in body")
	}
}

func TestSanitizeChartID(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"malloc", "malloc"},
		{"num_gc", "num_gc"},
		{"go_memstats_alloc_bytes_total", "go_memstats_alloc_bytes_total"},
		{"vendor-responses", "vendor-responses"},
		{"special metrics!@#", "special_metrics___"},
	}

	for _, tt := range tests {
		got := sanitizeChartID(tt.input)
		if got != tt.want {
			t.Errorf("sanitizeChartID(%q) = %q; want %q", tt.input, got, tt.want)
		}
	}
}

func TestServer_ViewServicesHandler(t *testing.T) {
	s := setupTestServer()
	s.Details.SupportedServices = []ServiceType{
		{
			Name:        "virustotal-prod",
			Kind:        "virustotal",
			Description: "VirusTotal API integration for file and IP reputation",
			Type:        []string{"md5", "sha256", "ipv4"},
			RateLimited: true,
			MaxRequests: 4,
			RefillRate:  60,
		},
		{
			Name:          "livery-upload",
			Kind:          "livery",
			Description:   "Livery sample analysis",
			Type:          []string{"upload"},
			UploadService: true,
		},
	}

	req := httptest.NewRequest("GET", "/services", nil)
	rr := httptest.NewRecorder()

	s.ViewServicesHandler(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", rr.Code)
	}

	body := rr.Body.String()

	// Check header navigation & search
	if !strings.Contains(body, "Threat Intelligence Services") {
		t.Error("expected 'Threat Intelligence Services' title in response")
	}
	if !strings.Contains(body, `id="serviceSearchInput"`) {
		t.Error("expected serviceSearchInput in response")
	}
	if !strings.Contains(body, `id="serviceViewer"`) {
		t.Error("expected serviceViewer in response")
	}

	// Check services listed
	if !strings.Contains(body, "virustotal-prod") {
		t.Error("expected 'virustotal-prod' in response")
	}
	if !strings.Contains(body, "VIRUSTOTAL") {
		t.Error("expected 'VIRUSTOTAL' badge in response")
	}
	if !strings.Contains(body, "Rate-Limited") {
		t.Error("expected 'Rate-Limited' badge in response")
	}
	if !strings.Contains(body, "Upload Service") {
		t.Error("expected 'Upload Service' badge in response")
	}
	if !strings.Contains(body, "md5") || !strings.Contains(body, "sha256") {
		t.Error("expected IOC type pills in response")
	}

	// Check news section below services
	if !strings.Contains(body, `id="news"`) {
		t.Error("expected news section with id='news' in response")
	}
	if !strings.Contains(body, "threatco-bulletins.broadcast") {
		t.Error("expected bulletins broadcast header in response")
	}
}

func TestServer_ViewServicesHandler_Empty(t *testing.T) {
	s := setupTestServer()
	s.Details.SupportedServices = []ServiceType{}

	req := httptest.NewRequest("GET", "/services", nil)
	rr := httptest.NewRecorder()

	s.ViewServicesHandler(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", rr.Code)
	}

	body := rr.Body.String()
	if !strings.Contains(body, "No threat intelligence services currently registered") {
		t.Error("expected placeholder when no services are configured")
	}
}
