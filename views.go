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
