package main

import (
	"net/http"
	"strings"
)

func (s *Server) ValidateToken(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		token := r.Header.Get("Authorization")
		parts := strings.Split(token, ":")
		if token == "" || len(parts) != 2 {
			http.Error(w, "Token is missing, malformed, or you are stupid.", http.StatusUnauthorized)
			return
		}
		user, err := s.GetUserByEmail(parts[0])
		if err != nil {
			http.Error(w, "Invalid token", http.StatusUnauthorized)
			return
		}
		if user.Key != parts[1] {
			http.Error(w, "Invalid token", http.StatusUnauthorized)
			return
		}
		next(w, r)
	}
}
