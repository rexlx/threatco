package main

import (
	"fmt"
	"net/http"

	"github.com/rexlx/threatco/views"
)

func (s *Server) LoginViewHandler(w http.ResponseWriter, r *http.Request) {
	// need to format with details.fqdn
	fmt.Fprint(w, views.LoginView)
}

func (S *Server) CreateUserViewHandler(w http.ResponseWriter, r *http.Request) {
	fmt.Fprint(w, views.AddUserView)
}

func (s *Server) ViewServicesHandler(w http.ResponseWriter, r *http.Request) {
	s.Memory.RLock()
	defer s.Memory.RUnlock()
	serviceDiv := `<div class="box has-background-black">
	<h2 class="title is-2 has-text-primary">Services</h2>
	<div class="columns is-multiline">`
	for _, service := range s.Details.SupportedServices {
		serviceDiv += fmt.Sprintf(`<div class="column is-one-third">
		<div class="box has-background-black">
			<h2 class="title is-2 has-text-primary">%s</h2>
			<ul>`, service.Kind)
		for _, t := range service.Type {
			serviceDiv += fmt.Sprintf(`<li>%s</li>`, t)
		}
		serviceDiv += `</ul></div></div>`
	}
	serviceDiv += `</div></div>`
	fmt.Fprintf(w, views.ViewServicesView, serviceDiv)
}
