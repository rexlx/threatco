package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"
)

// Config holds the connection details
type Config struct {
	BaseURL   string
	AdminUser string
	AdminKey  string
}

// NewUserRequest matches the struct in handlers.go
type NewUserRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
	Admin    string `json:"admin"` // handlers.go expects "on" or "true" string
}

// UserUpdate matches the User struct in user.go (simplified for update)
type UserUpdate struct {
	Email    string `json:"email"`
	Password string `json:"password,omitempty"`
	Admin    bool   `json:"admin"`
	// Note: In the provided handlers.go, updating a user might reset their
	// specific service permissions if not sent back.
}

func main() {
	// 1. Setup Configuration from Env Vars or Flags
	baseURL := os.Getenv("THREATCO_URL")
	if baseURL == "" {
		baseURL = "http://localhost:8081"
	}

	adminUser := os.Getenv("THREATCO_ADMIN_USER")
	adminKey := os.Getenv("THREATCO_ADMIN_KEY")

	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	client := &APIClient{
		Config: Config{
			BaseURL:   baseURL,
			AdminUser: adminUser,
			AdminKey:  adminKey,
		},
		HTTPClient: &http.Client{Timeout: 10 * time.Second},
	}

	// 2. Handle Subcommands
	switch os.Args[1] {
	case "stats":
		handleStats(client)
	case "add-user":
		handleAddUser(client, os.Args[2:])
	case "update-user":
		handleUpdateUser(client, os.Args[2:])
	default:
		fmt.Printf("Unknown command: %s\n", os.Args[1])
		printUsage()
		os.Exit(1)
	}
}

// --- Command Handlers ---

func handleStats(client *APIClient) {
	resp, err := client.Request("GET", "/stats", nil)
	if err != nil {
		die(err)
	}
	// Pretty print the JSON result
	var out bytes.Buffer
	json.Indent(&out, resp, "", "  ")
	fmt.Println(out.String())
}

func handleAddUser(client *APIClient, args []string) {
	cmd := flag.NewFlagSet("add-user", flag.ExitOnError)
	email := cmd.String("email", "", "Email of the new user")
	pass := cmd.String("password", "", "Password for the new user")
	isAdmin := cmd.Bool("admin", false, "Grant admin privileges")

	cmd.Parse(args)

	if *email == "" || *pass == "" {
		fmt.Println("Error: --email and --password are required")
		cmd.Usage()
		os.Exit(1)
	}

	adminStr := "false"
	if *isAdmin {
		adminStr = "true"
	}

	payload := NewUserRequest{
		Email:    *email,
		Password: *pass,
		Admin:    adminStr,
	}

	resp, err := client.Request("POST", "/adduser", payload)
	if err != nil {
		die(err)
	}

	fmt.Println("User created successfully:")
	fmt.Println(string(resp))
}

func handleUpdateUser(client *APIClient, args []string) {
	cmd := flag.NewFlagSet("update-user", flag.ExitOnError)
	email := cmd.String("email", "", "Email of the user to update")
	pass := cmd.String("password", "", "New password (leave empty to keep current)")
	isAdmin := cmd.Bool("admin", false, "Set admin privileges")

	cmd.Parse(args)

	if *email == "" {
		fmt.Println("Error: --email is required to identify the user")
		cmd.Usage()
		os.Exit(1)
	}

	// Prepare payload based on handlers.go expectations
	payload := UserUpdate{
		Email: *email,
		Admin: *isAdmin,
	}
	if *pass != "" {
		payload.Password = *pass
	}

	resp, err := client.Request("POST", "/updateuser", payload)
	if err != nil {
		die(err)
	}

	fmt.Println("User updated successfully:")
	fmt.Println(string(resp))
}

// --- API Client ---

type APIClient struct {
	Config     Config
	HTTPClient *http.Client
}

func (c *APIClient) Request(method, endpoint string, data interface{}) ([]byte, error) {
	var body io.Reader
	if data != nil {
		jsonData, err := json.Marshal(data)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal payload: %w", err)
		}
		body = bytes.NewBuffer(jsonData)
	}

	req, err := http.NewRequest(method, c.Config.BaseURL+endpoint, body)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	// Set Auth Header based on api.md format
	// "Authorization: beep@boop.com:KEY"
	if c.Config.AdminUser == "" || c.Config.AdminKey == "" {
		return nil, fmt.Errorf("admin credentials not set in environment variables")
	}
	authVal := fmt.Sprintf("%s:%s", c.Config.AdminUser, c.Config.AdminKey)
	req.Header.Set("Authorization", authVal)
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("network error: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("API Error (%d): %s", resp.StatusCode, string(respBody))
	}

	return respBody, nil
}

// --- Helpers ---

func printUsage() {
	fmt.Println("Usage: threatco-cli <command> [flags]")
	fmt.Println("\nCommands:")
	fmt.Println("  stats                   Get server statistics")
	fmt.Println("  add-user                Create a new user")
	fmt.Println("     Flags: --email, --password, --admin (optional)")
	fmt.Println("  update-user             Update an existing user")
	fmt.Println("     Flags: --email, --password, --admin")
	fmt.Println("\nEnvironment Variables:")
	fmt.Println("  THREATCO_URL            (default: http://localhost:8081)")
	fmt.Println("  THREATCO_ADMIN_USER     Admin email address")
	fmt.Println("  THREATCO_ADMIN_KEY      Admin API key")
}

func die(err error) {
	fmt.Fprintf(os.Stderr, "Error: %v\n", err)
	os.Exit(1)
}
