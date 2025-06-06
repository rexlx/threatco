package main

import (
	"fmt"
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
		token, err := s.GetTokenFromSession(r)
		if err != nil {
			// fmt.Println("Error getting token from session")
			token := r.Header.Get("Authorization")
			// fmt.Println("Token from header:", token)
			parts := strings.Split(token, ":")
			if token == "" || len(parts) != 2 {
				fmt.Println("token missing?", token)
				http.Error(w, "Token is missing, malformed, or you are stupid.", http.StatusUnauthorized)
				return
			}
			user, err := s.DB.GetUserByEmail(parts[0])
			if err != nil {
				fmt.Println("Error getting user by email:", err, user, token)
				http.Error(w, "Invalid token", http.StatusUnauthorized)
				return
			}
			if user.Key != parts[1] {
				fmt.Println("User key mismatch:", user.Key, parts[1], token, parts)
				http.Error(w, "Invalid token", http.StatusUnauthorized)
				return
			}
			cspValue := `default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval'; img-src 'self' data:; style-src 'self' 'unsafe-inline';`
			w.Header().Set("Content-Security-Policy", cspValue)
			w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
			next(w, r)
			return
		}
		tk, err := s.DB.GetTokenByValue(token)
		if err != nil || tk.ExpiresAt.Before(time.Now()) {
			http.Error(w, "Invalid session token", http.StatusUnauthorized)
			return
		}
		cspValue := `default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval'; img-src 'self' data:; style-src 'self' 'unsafe-inline';`
		w.Header().Set("Content-Security-Policy", cspValue)
		w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		next(w, r)
	}
}
