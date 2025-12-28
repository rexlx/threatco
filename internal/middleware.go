package internal

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

var visitors = make(map[string]*rate.Limiter)
var mu sync.Mutex

func getVisitor(ip string) *rate.Limiter {
	mu.Lock()
	defer mu.Unlock()

	limiter, exists := visitors[ip]
	if !exists {
		// Allow 1 request per second with a burst of 3
		limiter = rate.NewLimiter(1, 3)
		visitors[ip] = limiter
	}

	return limiter
}

func (s *Server) ProtectedFileServer(root http.FileSystem) http.Handler {
	fileServer := http.FileServer(root)
	return s.ValidateSessionToken(toHandlerFunc(fileServer))
}

func (s *Server) RateLimit(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Get IP address (Handle X-Forwarded-For if behind Cloudflare)
		ip := r.Header.Get("CF-Connecting-IP")
		if ip == "" {
			ip, _, _ = net.SplitHostPort(r.RemoteAddr)
		}

		limiter := getVisitor(ip)
		if !limiter.Allow() {
			s.Log.Printf("Rate limit exceeded for IP: %s", ip)
			http.Error(w, "Too Many Requests", http.StatusTooManyRequests)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// func (s *Server) ValidateToken(next http.HandlerFunc) http.HandlerFunc {
// 	return func(w http.ResponseWriter, r *http.Request) {
// 		token := r.Header.Get("Authorization")
// 		parts := strings.Split(token, ":")
// 		if token == "" || len(parts) != 2 {
// 			http.Error(w, "Token is missing, malformed, or you are stupid.", http.StatusUnauthorized)
// 			return
// 		}
// 		user, err := s.DB.GetUserByEmail(parts[0])
// 		if err != nil {
// 			http.Error(w, "Invalid token", http.StatusUnauthorized)
// 			return
// 		}
// 		if user.Key != parts[1] {
// 			http.Error(w, "Invalid token", http.StatusUnauthorized)
// 			return
// 		}
// 		next(w, r)
// 	}
// }

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
			decryptedDBKey, keyUsed, err := s.Decrypt(user.Key)
			if err != nil {
				fmt.Println("Error decrypting key:", err, user.Key)
				http.Error(w, "Invalid token", http.StatusUnauthorized)
				return
			}
			if decryptedDBKey != plaintext {
				fmt.Println("User key mismatch:", user.Key, parts[1], token, parts)
				http.Error(w, "Invalid token", http.StatusUnauthorized)
				return
			}

			if keyUsed != KeyUsedNew {
				newlyEncrypted, _ := s.Encrypt(plaintext)
				user.Key = newlyEncrypted
				go func(u User) {
					fmt.Printf("Lazily migrating API key for user %s", u.Email)
					if err := s.DB.AddUser(u); err != nil {
						fmt.Printf("failed to migrate key for user %s: %v", u.Email, err)
					}
				}(user)
			}

			ctx := context.WithValue(r.Context(), "email", email)
			r = r.WithContext(ctx)
			cspValue := `default-src 'self'; script-src 'self' https://cdnjs.cloudflare.com; img-src 'self' data:; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' https://fonts.gstatic.com;`
			// cspValue := `default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval'; img-src 'self' data:; style-src 'self' 'unsafe-inline';`
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

		ctx := context.WithValue(r.Context(), "email", tk.Email)
		r = r.WithContext(ctx)
		cspValue := `default-src 'self'; script-src 'self' https://cdnjs.cloudflare.com; img-src 'self' data:; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' https://fonts.gstatic.com;`
		// cspValue := `default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval'; img-src 'self' data:; style-src 'self' 'unsafe-inline';`
		w.Header().Set("Content-Security-Policy", cspValue)
		w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		next(w, r)
	}
}

func (s *Server) CORSMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")
		allowed := false
		for _, o := range s.Details.CorsOrigins {
			if o == origin {
				allowed = true
				break
			}
		}
		if allowed {
			w.Header().Set("Access-Control-Allow-Origin", origin)
		} else {
			w.Header().Set("Access-Control-Allow-Origin", "null")
		}
		w.Header().Set("Access-Control-Allow-Credentials", "true")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Content-Range, Authorization, x-filename, x-last-chunk, X-filename, X-last-chunk")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")

		if r.Method == "OPTIONS" {
			fmt.Println("Handled preflight OPTIONS request")
			w.WriteHeader(http.StatusNoContent)
			return
		}

		next.ServeHTTP(w, r)
	})
}

func toHandlerFunc(handler http.Handler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		handler.ServeHTTP(w, r)
	}
}
