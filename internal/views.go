package internal

import (
	"bytes"
	"fmt"
	"html"
	"net/http"
	"sort"
	"strconv"
	"strings"

	"github.com/rexlx/threatco/views"
)

func (s *Server) LoginViewHandler(w http.ResponseWriter, r *http.Request) {
	// need to format with details.fqdn
	fmt.Fprint(w, views.LoginView)
}

func (s *Server) LogViewHandler(w http.ResponseWriter, r *http.Request) {
	fmt.Fprint(w, views.LogView)
}

func (s *Server) AllUsersViewHandler(w http.ResponseWriter, r *http.Request) {
	email := r.Context().Value("email").(string)
	user, err := s.DB.GetUserByEmail(email)
	if err != nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	rawUsers, err := s.DB.GetAllUsers()
	if err != nil {
		s.Log.Println("AllUsersViewHandler", err)
	}

	totalRawUsers := len(rawUsers)
	_users := rawUsers

	// 1. Filter users based on search query 'q'
	searchQuery := strings.TrimSpace(r.URL.Query().Get("q"))
	if searchQuery != "" {
		filtered := []User{}
		lowerQuery := strings.ToLower(searchQuery)
		for _, u := range _users {
			if strings.Contains(strings.ToLower(u.Email), lowerQuery) {
				filtered = append(filtered, u)
			}
		}
		_users = filtered
	}

	// 2. Pagination settings (Recalculated based on filtered results)
	const usersPerPage = 15
	totalUsers := len(_users)
	totalPages := (totalUsers + usersPerPage - 1) / usersPerPage
	if totalPages == 0 {
		totalPages = 1
	}

	// Get page from query parameter
	pageStr := r.URL.Query().Get("page")
	page := 1
	if pageStr != "" {
		if p, err := strconv.Atoi(pageStr); err == nil && p > 0 && p <= totalPages {
			page = p
		}
	}

	// Calculate start and end indices with safety checks
	startIdx := (page - 1) * usersPerPage
	if startIdx >= totalUsers {
		startIdx = 0
	}
	endIdx := startIdx + usersPerPage
	if endIdx > totalUsers {
		endIdx = totalUsers
	}

	// Get paginated users
	paginatedUsers := _users[startIdx:endIdx]

	var users string
	if len(paginatedUsers) == 0 {
		users = `<tr><td colspan="6" class="terminal-placeholder">No user accounts found.</td></tr>`
	} else {
		for _, u := range paginatedUsers {
			var deleteButton, newKeyButton string
			if user.Admin || u.Email == email {
				deleteButton = fmt.Sprintf(`<button class="button is-small terminal-action-btn terminal-btn-danger delete-user-btn" data-email="%s" title="Delete user account">Delete</button>`, html.EscapeString(u.Email))
				newKeyButton = fmt.Sprintf(`<button class="button is-small terminal-action-btn generate-key-btn" data-email="%s" title="Generate new API key">New Key</button>`, html.EscapeString(u.Email))
			} else {
				deleteButton = fmt.Sprintf(`<button class="button is-small terminal-action-btn terminal-btn-danger delete-user-btn" data-email="%s" disabled title="Delete user account">Delete</button>`, html.EscapeString(u.Email))
				newKeyButton = fmt.Sprintf(`<button class="button is-small terminal-action-btn generate-key-btn" data-email="%s" disabled title="Generate new API key">New Key</button>`, html.EscapeString(u.Email))
			}

			emailHTML := fmt.Sprintf(`<span class="user-email-text">%s</span>`, html.EscapeString(u.Email))
			if u.Email == email {
				emailHTML += ` <span class="user-you-tag">you</span>`
			}

			roleBadge := `<span class="role-badge role-user">USER</span>`
			if u.Admin {
				roleBadge = `<span class="role-badge role-admin">ADMIN</span>`
			}

			var servicesHTML string
			if len(u.Services) == 0 {
				servicesHTML = `<span class="user-no-services">—</span>`
			} else {
				var sb strings.Builder
				sb.WriteString(`<div class="user-services-list">`)
				for _, svc := range u.Services {
					sb.WriteString(fmt.Sprintf(`<span class="service-meta-pill">%s</span>`, html.EscapeString(svc.Kind)))
				}
				sb.WriteString(`</div>`)
				servicesHTML = sb.String()
			}

			createdStr := u.Created.Format("2006-01-02 15:04")
			if u.Created.IsZero() {
				createdStr = "—"
			}

			updatedStr := u.Updated.Format("2006-01-02 15:04")
			if u.Updated.IsZero() {
				updatedStr = "—"
			}

			users += fmt.Sprintf(views.UserTableBody, emailHTML, roleBadge, servicesHTML, createdStr, updatedStr, deleteButton, newKeyButton)
		}
	}

	// 3. Build pagination controls with search query preservation
	paginationHTML := s.buildPaginationControls(page, totalPages, searchQuery)

	countBadge := fmt.Sprintf("%d users", totalUsers)
	clearBtn := ""
	statusText := ""
	if totalUsers == 0 {
		statusText = "No registered accounts found"
	} else {
		statusText = fmt.Sprintf("Showing %d–%d of %d accounts", startIdx+1, endIdx, totalUsers)
	}

	if searchQuery != "" {
		countBadge = fmt.Sprintf("%d / %d users", totalUsers, totalRawUsers)
		clearBtn = `<div class="control"><a href="/users" class="button is-small is-dark" title="Clear filter">Clear</a></div>`
		statusText += fmt.Sprintf(" (filtered by %q)", searchQuery)
	}

	// Inject into template: countBadge, searchQuery, clearBtn, users, statusText, paginationHTML
	tempDiv := fmt.Sprintf(views.ViewUsersSection, countBadge, html.EscapeString(searchQuery), clearBtn, users, statusText, paginationHTML)
	fmt.Fprintf(w, views.BaseView, tempDiv)
}

func (s *Server) buildPaginationControls(currentPage, totalPages int, query string) string {
	if totalPages <= 1 {
		return ""
	}

	// Format the query parameter for the URLs
	qParam := ""
	if query != "" {
		qParam = "&q=" + html.EscapeString(query)
	}

	var prevBtn, nextBtn string
	pageItems := ""

	// Previous button
	if currentPage > 1 {
		prevBtn = fmt.Sprintf(views.PaginationPrevious, "", currentPage-1, qParam)
	} else {
		prevBtn = fmt.Sprintf(views.PaginationPrevious, "is-disabled", currentPage, qParam)
	}

	// Page numbers logic...
	const maxPageButtons = 7
	var startPage, endPage int

	if totalPages <= maxPageButtons {
		startPage = 1
		endPage = totalPages
	} else {
		startPage = currentPage - 3
		endPage = currentPage + 3
		if startPage < 1 {
			startPage = 1
			endPage = maxPageButtons
		}
		if endPage > totalPages {
			endPage = totalPages
			startPage = totalPages - maxPageButtons + 1
		}
	}

	if startPage > 1 {
		pageItems += fmt.Sprintf(views.PaginationItem, "", 1, qParam, 1)
		if startPage > 2 {
			pageItems += views.PaginationEllipsis
		}
	}

	for p := startPage; p <= endPage; p++ {
		activeClass := ""
		if p == currentPage {
			activeClass = "is-current"
		}
		pageItems += fmt.Sprintf(views.PaginationItem, activeClass, p, qParam, p)
	}

	if endPage < totalPages {
		if endPage < totalPages-1 {
			pageItems += views.PaginationEllipsis
		}
		pageItems += fmt.Sprintf(views.PaginationItem, "", totalPages, qParam, totalPages)
	}

	// Next button
	if currentPage < totalPages {
		nextBtn = fmt.Sprintf(views.PaginationNext, "", currentPage+1, qParam)
	} else {
		nextBtn = fmt.Sprintf(views.PaginationNext, "is-disabled", currentPage, qParam)
	}

	return fmt.Sprintf(views.PaginationControls, prevBtn, pageItems, nextBtn)
}

func (s *Server) buildPaginationControlsLegacy(currentPage, totalPages int) string {
	if totalPages <= 1 {
		return ""
	}

	var prevBtn, nextBtn string
	pageItems := ""

	// Previous button
	if currentPage > 1 {
		prevBtn = fmt.Sprintf(views.PaginationPrevious, "", currentPage-1)
	} else {
		prevBtn = fmt.Sprintf(views.PaginationPrevious, "is-disabled", currentPage)
	}

	// Page numbers
	const maxPageButtons = 7
	var startPage, endPage int

	if totalPages <= maxPageButtons {
		startPage = 1
		endPage = totalPages
	} else {
		startPage = currentPage - 3
		endPage = currentPage + 3
		if startPage < 1 {
			startPage = 1
			endPage = maxPageButtons
		}
		if endPage > totalPages {
			endPage = totalPages
			startPage = totalPages - maxPageButtons + 1
		}
	}

	// Add ellipsis at start if needed
	if startPage > 1 {
		pageItems += fmt.Sprintf(views.PaginationItem, "", 1, 1)
		if startPage > 2 {
			pageItems += views.PaginationEllipsis
		}
	}

	// Add page numbers
	for p := startPage; p <= endPage; p++ {
		activeClass := ""
		if p == currentPage {
			activeClass = "is-current"
		}
		pageItems += fmt.Sprintf(views.PaginationItem, activeClass, p, p)
	}

	// Add ellipsis at end if needed
	if endPage < totalPages {
		if endPage < totalPages-1 {
			pageItems += views.PaginationEllipsis
		}
		pageItems += fmt.Sprintf(views.PaginationItem, "", totalPages, totalPages)
	}

	// Next button
	if currentPage < totalPages {
		nextBtn = fmt.Sprintf(views.PaginationNext, "", currentPage+1)
	} else {
		nextBtn = fmt.Sprintf(views.PaginationNext, "is-disabled", currentPage)
	}

	return fmt.Sprintf(views.PaginationControls, prevBtn, pageItems, nextBtn)
}

func (S *Server) CreateUserViewHandler(w http.ResponseWriter, r *http.Request) {
	fmt.Fprint(w, views.AddUserView)
}

func (s *Server) AddServicesHandler(w http.ResponseWriter, r *http.Request) {
	fmt.Fprint(w, views.AddServiceView)
}

func (s *Server) ChartViewHandler(w http.ResponseWriter, r *http.Request) {
	s.Memory.RLock()
	hasData := len(s.Cache.Coordinates) > 0 && len(s.Cache.Charts) > 0 && !bytes.Equal(s.Cache.Charts, []byte(views.NoDataView))
	s.Memory.RUnlock()

	if !hasData {
		s.UpdateCharts()
	}

	s.Memory.RLock()
	defer s.Memory.RUnlock()

	if len(s.Cache.Coordinates) == 0 || len(s.Cache.Charts) == 0 || bytes.Equal(s.Cache.Charts, []byte(views.NoDataView)) {
		fmt.Fprintf(w, views.BaseView, views.ChartsEmptySection)
		return
	}

	keys := make([]string, 0, len(s.Cache.Coordinates))
	for k := range s.Cache.Coordinates {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	var options strings.Builder
	for _, k := range keys {
		chartID := sanitizeChartID(k)
		options.WriteString(fmt.Sprintf(`<option value="chart-%s">%s</option>`, chartID, html.EscapeString(k)))
	}

	chartsContent := string(s.Cache.Charts)
	out := fmt.Sprintf(views.ChartsViewSection, len(keys), options.String(), chartsContent)

	fmt.Fprintf(w, views.BaseView, out)
}

func (s *Server) ViewResponsesHandler(w http.ResponseWriter, r *http.Request) {
	fmt.Fprint(w, views.ResponsesListView)
}

func (s *Server) ViewServicesHandler(w http.ResponseWriter, r *http.Request) {
	s.Memory.RLock()
	defer s.Memory.RUnlock()

	services := make([]ServiceType, len(s.Details.SupportedServices))
	copy(services, s.Details.SupportedServices)

	sort.Slice(services, func(i, j int) bool {
		nameI := services[i].Name
		if nameI == "" {
			nameI = services[i].Kind
		}
		nameJ := services[j].Name
		if nameJ == "" {
			nameJ = services[j].Kind
		}
		return strings.ToLower(nameI) < strings.ToLower(nameJ)
	})

	uniqueTypes := make(map[string]bool)
	var rows strings.Builder

	if len(services) == 0 {
		rows.WriteString(`<div class="terminal-placeholder">No threat intelligence services currently registered.</div>`)
	} else {
		for _, svc := range services {
			for _, t := range svc.Type {
				uniqueTypes[strings.ToLower(t)] = true
			}

			displayName := svc.Name
			if displayName == "" {
				displayName = svc.Kind
			}

			desc := svc.Description
			if strings.TrimSpace(desc) == "" {
				desc = fmt.Sprintf("Active %s intelligence integration for artifact lookups and indicator queries.", svc.Kind)
			}

			sortedTypes := make([]string, len(svc.Type))
			copy(sortedTypes, svc.Type)
			sort.Strings(sortedTypes)

			var typeBadges strings.Builder
			for _, t := range sortedTypes {
				typeBadges.WriteString(fmt.Sprintf(`<span class="service-type-pill" data-type="%s" title="Filter by %s">%s</span>`, html.EscapeString(t), html.EscapeString(t), html.EscapeString(t)))
			}

			var metaBadges strings.Builder
			if svc.RateLimited {
				if svc.MaxRequests > 0 && svc.RefillRate > 0 {
					metaBadges.WriteString(fmt.Sprintf(`<span class="service-meta-pill is-rate-limited">Rate-Limited (%d req / %ds)</span>`, svc.MaxRequests, svc.RefillRate))
				} else {
					metaBadges.WriteString(`<span class="service-meta-pill is-rate-limited">Rate-Limited</span>`)
				}
			}
			if svc.UploadService {
				metaBadges.WriteString(`<span class="service-meta-pill is-upload">Upload Service</span>`)
			}
			if svc.Insecure {
				metaBadges.WriteString(`<span class="service-meta-pill is-insecure">Insecure TLS</span>`)
			}
			if svc.AuthType != "" {
				metaBadges.WriteString(fmt.Sprintf(`<span class="service-meta-pill">Auth: %s</span>`, html.EscapeString(svc.AuthType)))
			}

			searchKeywords := strings.ToLower(fmt.Sprintf("%s %s %s %s", displayName, svc.Kind, desc, strings.Join(sortedTypes, " ")))

			rows.WriteString(fmt.Sprintf(`
<div class="service-row-item" data-search="%s">
	<div class="service-row-header">
		<div class="service-identity">
			<span class="service-name">%s</span>
			<span class="service-vendor-badge">%s</span>
			<span class="system-status-pill status-nominal"><span class="status-indicator-dot dot-nominal"></span>ONLINE</span>
			<div class="service-meta-badges">
				%s
			</div>
		</div>
		<div class="service-types-count">%d supported types</div>
	</div>
	<div class="service-description">%s</div>
	<div class="service-capabilities">
		<span class="service-types-label">IOC TYPES:</span>
		<div class="service-type-tags">
			%s
		</div>
	</div>
</div>`,
				html.EscapeString(searchKeywords),
				html.EscapeString(displayName),
				html.EscapeString(strings.ToUpper(svc.Kind)),
				metaBadges.String(),
				len(sortedTypes),
				html.EscapeString(desc),
				typeBadges.String(),
			))
		}
	}

	totalServices := len(services)
	totalTypes := len(uniqueTypes)

	out := fmt.Sprintf(views.ServicesViewSection, totalServices, totalTypes, rows.String(), totalServices, totalServices)
	fmt.Fprintf(w, views.BaseView, out)
}
