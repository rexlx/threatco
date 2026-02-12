package internal

import (
	"fmt"
	"net/http"
	"strconv"

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
	_users, err := s.DB.GetAllUsers()
	if err != nil {
		s.Log.Println("AllUsersViewHandler", err)
	}

	// Pagination settings
	const usersPerPage = 15
	totalUsers := len(_users)
	totalPages := (totalUsers + usersPerPage - 1) / usersPerPage

	// Get page from query parameter
	pageStr := r.URL.Query().Get("page")
	page := 1
	if pageStr != "" {
		if p, err := strconv.Atoi(pageStr); err == nil && p > 0 && p <= totalPages {
			page = p
		}
	}

	// Calculate start and end indices
	startIdx := (page - 1) * usersPerPage
	endIdx := startIdx + usersPerPage
	if endIdx > totalUsers {
		endIdx = totalUsers
	}

	// Get paginated users
	paginatedUsers := _users[startIdx:endIdx]

	var deleteButton, newKeyButton string
	users := ""
	for _, u := range paginatedUsers {
		if user.Admin || u.Email == email {
			deleteButton = fmt.Sprintf(`<button class="button is-danger is-outlined delete-user-btn" data-email="%s">Delete</button>`, u.Email)
			newKeyButton = fmt.Sprintf(`<button class="button is-warning is-outlined generate-key-btn" data-email="%s">New API Key</button>`, u.Email)
		} else {
			deleteButton = fmt.Sprintf(`<button class="button is-danger is-outlined delete-user-btn" data-email="%s" disabled>Delete</button>`, u.Email)
			newKeyButton = fmt.Sprintf(`<button class="button is-warning is-outlined generate-key-btn" data-email="%s" disabled>New API Key</button>`, u.Email)
		}

		svcs := []string{}
		for _, svc := range u.Services {
			svcs = append(svcs, svc.Kind)
		}
		users += fmt.Sprintf(views.UserTableBody, u.Email, u.Admin, svcs, u.Created, u.Updated, deleteButton, newKeyButton)
	}

	// Build pagination controls
	paginationHTML := s.buildPaginationControls(page, totalPages)

	tempDiv := fmt.Sprintf(views.ViewUsersSection, users, paginationHTML)
	fmt.Fprintf(w, views.BaseView, tempDiv)
}

func (s *Server) buildPaginationControls(currentPage, totalPages int) string {
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
	defer s.Memory.RUnlock()

	out := fmt.Sprintf(`
        <div style="display: flex; flex-direction: column; align-items: center; gap: 2rem; width: 100%%; padding: 2rem 0;">
            %s
        </div>`,
		s.Cache.Charts)

	fmt.Fprintf(w, views.BaseView, out)
}
func (s *Server) ViewResponsesHandler(w http.ResponseWriter, r *http.Request) {
	fmt.Fprint(w, views.ResponsesListView)
}

func (s *Server) ViewServicesHandler(w http.ResponseWriter, r *http.Request) {
	s.Memory.RLock()
	defer s.Memory.RUnlock()

	serviceDiv := `<div class="box has-background-black">
<div class="columns is-multiline">`

	for _, service := range s.Details.SupportedServices {
		// Create a unique modal ID for each service
		modalID := fmt.Sprintf("modal-%s", service.Kind)

		serviceDiv += fmt.Sprintf(`
<div class="column is-3"> 
	<div class="card has-background-custom service-card">
		<div class="card-content">
			<p class="title has-text-primary is-4 open-modal" data-modal-id="%s" style="cursor: pointer">%s</p>
			<div class="content">
				<p class="has-text-white">%v</p>
			</div>
		</div>
	</div>

	<div class="modal" id="%s">
		<div class="modal-background"></div>
		<div class="modal-card">
			<header class="modal-card-head has-background-custom">
				<p class="modal-card-title has-text-primary">%s types</p>
				<button class="delete close-modal" aria-label="close"></button>
			</header>
			<section class="modal-card-body has-background-custom">
				<ul>
`, modalID, service.Kind, service.Description, modalID, service.Kind) //

		// Loop through service types
		for _, t := range service.Type {
			serviceDiv += fmt.Sprintf(`<li class="has-text-primary">%s</li>`, t)
		}

		serviceDiv += `</ul></section>
		</div>
	</div>
</div>`
	}

	serviceDiv += `</div></div>`
	tempDiv := fmt.Sprintf(views.ViewSection, serviceDiv)
	fmt.Fprintf(w, views.BaseView, tempDiv)
}
