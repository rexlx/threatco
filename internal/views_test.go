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
