package internal

import (
	"fmt"
	"net/http"

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
	var deleteButton, newKeyButton string
	users := ""
	for _, u := range _users {
		if user.Admin || u.Email == email {
			deleteButton = fmt.Sprintf(`<button class="button is-danger is-outlined" onclick="deleteUser('%s')">Delete</button>`, u.Email)
			newKeyButton = fmt.Sprintf(`<button class="button is-warning is-outlined" onclick="generateNewKey('%s')">New API Key</button>`, u.Email)
		} else {
			deleteButton = fmt.Sprintf(`<button class="button is-danger is-outlined" onclick="deleteUser('%s')" disabled>Delete</button>`, u.Email)
			newKeyButton = fmt.Sprintf(`<button class="button is-warning is-outlined" onclick="generateNewKey('%s')" disabled>New API Key</button>`, u.Email)
		}

		svcs := []string{}
		for _, svc := range u.Services {
			svcs = append(svcs, svc.Kind)
		}
		users += fmt.Sprintf(views.UserTableBody, u.Email, u.Admin, svcs, u.Created, u.Updated, deleteButton, newKeyButton)
	}
	tempDiv := fmt.Sprintf(views.ViewUsersSection, users)
	fmt.Fprintf(w, views.BaseView, tempDiv)
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
			<p class="title has-text-primary is-4">%s</p>
			<div class="content">
				<p class="has-text-white">%v</p>
			</div>
			<div class="has-text-centered">
				<button class="button open-modal is-primary" data-modal-id="%s">View Details</button>
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
`, service.Kind, service.Description, modalID, modalID, service.Kind)

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
