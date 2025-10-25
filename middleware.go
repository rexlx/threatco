package main

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"
)

func (s *Server) ProtectedFileServer(root http.FileSystem) http.Handler {
	fileServer := http.FileServer(root)
	return s.ValidateSessionToken(toHandlerFunc(fileServer))
}

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
			token := r.Header.Get("Authorization")
			parts := strings.Split(token, ":")
			if token == "" || len(parts) != 2 {
				http.Error(w, "Token is missing, malformed, or you are stupid.", http.StatusUnauthorized)
				return
			}

			email := parts[0]
			plaintext := parts[1]
			user, err := s.DB.GetUserByEmail(email)
			if err != nil {
				fmt.Println("Error getting user by email:", err, user, token)
				http.Error(w, "Invalid token", http.StatusUnauthorized)
				return
			}
			decrypted, err := s.Decrypt(user.Key)
			if err != nil {
				fmt.Println("Error decrypting token part:", err, plaintext, token)
				http.Error(w, "Invalid token", http.StatusUnauthorized)
				return
			}
			if string(decrypted) != plaintext {
				fmt.Println("User key mismatch:", user.Key, parts[1], token, parts)
				http.Error(w, "Invalid token", http.StatusUnauthorized)
				return
			}

			ctx := context.WithValue(r.Context(), "email", email)
			r = r.WithContext(ctx)

			cspValue := `default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval'; img-src 'self' data:; style-src 'self' 'unsafe-inline';`
			w.Header().Set("Content-Security-Policy", cspValue)
			w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
			next(w, r)
			return
		}

		tk, err := s.DB.GetTokenByValue(token)
		if err != nil || tk.ExpiresAt.Before(time.Now()) {
			fmt.Println("Invalid session token:", token, err, tk)
			http.Error(w, "Invalid session token", http.StatusUnauthorized)
			return
		}

		ctx := context.WithValue(r.Context(), "email", tk.Email) // Assumes tk has an Email field
		r = r.WithContext(ctx)

		cspValue := `default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval'; img-src 'self' data:; style-src 'self' 'unsafe-inline';`
		w.Header().Set("Content-Security-Policy", cspValue)
		w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		next(w, r)
	}
}

func CORSMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "http://192.168.86.120:8081")
		w.Header().Set("Access-Control-Allow-Credentials", "true")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Content-Range, Authorization, x-filename, x-last-chunk, X-filename, X-last-chunk")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")

		// --- Handle Preflight Request ---
		// If the request method is OPTIONS, it's a preflight request.
		// We handle it by writing the headers and a 204 No Content status.
		if r.Method == "OPTIONS" {
			fmt.Println("Handled preflight OPTIONS request")
			w.WriteHeader(http.StatusNoContent)
			return
		}

		// --- Forward Request ---
		// For all other requests, pass them to the next handler in the chain.
		next.ServeHTTP(w, r)
	})
}

func toHandlerFunc(handler http.Handler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		handler.ServeHTTP(w, r)
	}
}
