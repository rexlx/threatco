package main

import (
	"fmt"
	"net/http"

	"github.com/rexlx/threatco/views"
)

func (s *Server) LoginViewHandler(w http.ResponseWriter, r *http.Request) {
	// need to format with details.fqdn
	fmt.Fprintf(w, views.LoginView)
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
	out := string(s.Cache.Charts)

	fmt.Fprint(w, out)
}

func (s *Server) ViewServicesHandler(w http.ResponseWriter, r *http.Request) {
	s.Memory.RLock()
	defer s.Memory.RUnlock()

	serviceDiv := `<div class="box has-background-black-ter">
    <h2 class="title is-2 has-text-primary">Services</h2>
    <div class="columns is-multiline">`

	for _, service := range s.Details.SupportedServices {
		// Create a unique modal ID for each service
		modalID := fmt.Sprintf("modal-%s", service.Kind)

		serviceDiv += fmt.Sprintf(`<div class="column">
        <div class="card has-background-black-ter" style="height: 200px;"> <!-- Set fixed height -->
            <div class="card-content">
                <p class="title has-text-white is-4">%s</p> <!-- Use title class for consistency -->
                <div class="content">
                    <p class="has-text-white">Description or additional info can go here.</p> <!-- Optional description -->
                </div>
                <div class="has-text-centered">
                    <button class="button open-modal is-primary" data-modal-id="%s">View Details</button> <!-- Button to open modal -->
                </div>
            </div>
        </div>

        <!-- Modal Structure -->
        <div class="modal" id="%s">
            <div class="modal-background"></div>
            <div class="modal-card">
                <header class="modal-card-head has-background-black">
                    <p class="modal-card-title has-text-primary">%s types</p>
                   <button class="delete close-modal" aria-label="close"></button>
                </header>
                <section class="modal-card-body has-background-black"><ul>
                `, service.Kind, modalID, modalID, service.Kind)

		// Loop through service types
		for _, t := range service.Type {
			serviceDiv += fmt.Sprintf(`<li class="has-text-primary">%s</li>`, t) // Ensure t is a string
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

// func (s *Server) ViewServicesHandler(w http.ResponseWriter, r *http.Request) {
// 	s.Memory.RLock()
// 	defer s.Memory.RUnlock()
// 	serviceDiv := `<div class="box has-background-black">
// 	<h2 class="title is-2 has-text-primary">Services</h2>
// 	<div class="columns is-multiline">`
// 	for _, service := range s.Details.SupportedServices {
// 		serviceDiv += fmt.Sprintf(`<div class="column is-one-third">
// 		<div class="box has-background-black">
// 			<h2 class="title is-2 has-text-primary">%s</h2>
// 			<ul>`, service.Kind)
// 		for _, t := range service.Type {
// 			serviceDiv += fmt.Sprintf(`<li>%s</li>`, t)
// 		}
// 		serviceDiv += `</ul></div></div>`
// 	}
// 	serviceDiv += `</div></div>`
// 	fmt.Fprintf(w, views.ViewServicesView,views.BaseView,serviceDiv)
// }
