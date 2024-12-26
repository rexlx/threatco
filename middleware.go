package main

import (
	"net/http"
	"strings"
	"time"
)

func (s *Server) ValidateToken(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		token := r.Header.Get("Authorization")
		parts := strings.Split(token, ":")
		if token == "" || len(parts) != 2 {
			http.Error(w, "Token is missing, malformed, or you are stupid.", http.StatusUnauthorized)
			return
		}
		user, err := s.DB.GetUserByEmail(parts[0])
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

func (s *Server) ValidateSessionToken(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// fmt.Println("Validating session token")
		token, err := s.GetTokenFromSession(r)
		if err != nil {
			// fmt.Println("Error getting token from session")
			token := r.Header.Get("Authorization")
			// fmt.Println("Token from header:", token)
			parts := strings.Split(token, ":")
			if token == "" || len(parts) != 2 {
				http.Error(w, "Token is missing, malformed, or you are stupid.", http.StatusUnauthorized)
				return
			}
			user, err := s.DB.GetUserByEmail(parts[0])
			if err != nil {
				http.Error(w, "Invalid token", http.StatusUnauthorized)
				return
			}
			if user.Key != parts[1] {
				http.Error(w, "Invalid token", http.StatusUnauthorized)
				return
			}
			next(w, r)
			return
		}
		tk, err := s.DB.GetTokenByValue(token)
		if err != nil || tk.ExpiresAt.Before(time.Now()) {
			http.Error(w, "Invalid session token", http.StatusUnauthorized)
			return
		}
		next(w, r)
	}
}
