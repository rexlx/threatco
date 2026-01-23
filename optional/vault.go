package optional

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
)

// VaultClient holds configuration for interacting with HashiCorp Vault.
type VaultClient struct {
	BaseURL   string
	Namespace string
	Token     string
	Client    *http.Client
}

// VaultLoginResponse represents the expected response from an auth method.
type VaultLoginResponse struct {
	Auth struct {
		ClientToken string `json:"client_token"`
	} `json:"auth"`
}

// VaultKVResponse represents the structure of a Vault KV v2 secret response.
type VaultKVResponse struct {
	Data struct {
		Data map[string]interface{} `json:"data"`
	} `json:"data"`
}

// NewVaultClient initializes a new Vault client.
func NewVaultClient(baseURL, namespace string) *VaultClient {
	return &VaultClient{
		BaseURL:   baseURL,
		Namespace: namespace,
		Client:    &http.Client{},
	}
}

// LoginAppRole exchanges a Role ID and Secret ID for a Vault Token.
func (v *VaultClient) LoginAppRole(ctx context.Context, roleID, secretID string) error {
	url := fmt.Sprintf("%s/v1/auth/approle/login", v.BaseURL)
	payload, _ := json.Marshal(map[string]string{
		"role_id":   roleID,
		"secret_id": secretID,
	})

	req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewBuffer(payload))
	if err != nil {
		return err
	}

	if v.Namespace != "" {
		req.Header.Set("X-Vault-Namespace", v.Namespace)
	}

	resp, err := v.Client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("vault login failed (%d): %s", resp.StatusCode, string(body))
	}

	var loginResp VaultLoginResponse
	if err := json.NewDecoder(resp.Body).Decode(&loginResp); err != nil {
		return err
	}

	v.Token = loginResp.Auth.ClientToken
	return nil
}

// FetchAndSetEnv retrieves secrets from a KV v2 path and sets them as environment variables.
// mount: the KV engine name (e.g., "kv")
// path: the secret name (e.g., "threatco-env")
func (v *VaultClient) FetchAndSetEnv(ctx context.Context, mount, path string) error {
	// Vault KV v2 uses the /data/ path segment
	url := fmt.Sprintf("%s/v1/%s/data/%s", v.BaseURL, mount, path)

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return err
	}

	req.Header.Set("X-Vault-Token", v.Token)
	if v.Namespace != "" {
		req.Header.Set("X-Vault-Namespace", v.Namespace)
	}

	resp, err := v.Client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("failed to fetch secrets (%d): %s", resp.StatusCode, string(body))
	}

	var kvResp VaultKVResponse
	if err := json.NewDecoder(resp.Body).Decode(&kvResp); err != nil {
		return err
	}

	// Iterate through the keys and set them as environment variables
	for key, value := range kvResp.Data.Data {
		envValue := fmt.Sprintf("%v", value)
		os.Setenv(key, envValue)
	}

	return nil
}
