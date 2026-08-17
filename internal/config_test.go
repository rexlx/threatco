package internal

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"testing"
)

func TestFileExists(t *testing.T) {
	tempDir := t.TempDir()
	filePath := filepath.Join(tempDir, "test.txt")

	if FileExists(filePath) {
		t.Errorf("expected false for non-existent file")
	}

	if err := os.WriteFile(filePath, []byte("hello"), 0644); err != nil {
		t.Fatalf("failed to create file: %v", err)
	}

	if !FileExists(filePath) {
		t.Errorf("expected true for existing file")
	}

	if FileExists(tempDir) {
		t.Errorf("expected false for directory path")
	}
}

func TestConfiguration_ApplyEnvOverrides(t *testing.T) {
	cfg := Configuration{
		EncKey:         "my-enc-key",
		PreviousEncKey: "my-old-enc-key",
		DBLocation:     "/tmp/testdb.db",
		Services: []ServiceType{
			{Kind: "misp", Key: "", Secret: ""},
			{Kind: "virustotal", Key: "existing-key", Secret: "existing-secret"},
		},
	}

	t.Setenv("THREATCO_LLM_API_KEY", "env-llm-key")
	t.Setenv("MISP_KEY", "env-misp-key")
	t.Setenv("MISP_SECRET", "env-misp-secret")

	cfg.ApplyEnvOverrides()

	if cfg.LlmConf.ApiKey != "env-llm-key" {
		t.Errorf("expected LlmConf.ApiKey to be 'env-llm-key', got '%s'", cfg.LlmConf.ApiKey)
	}
	if os.Getenv("THREATCO_ENCRYPTION_KEY") != "my-enc-key" {
		t.Errorf("expected THREATCO_ENCRYPTION_KEY env var to be 'my-enc-key'")
	}
	if os.Getenv("THREATCO_OLD_ENCRYPTION_KEY") != "my-old-enc-key" {
		t.Errorf("expected THREATCO_OLD_ENCRYPTION_KEY env var to be 'my-old-enc-key'")
	}
	if os.Getenv("THREATCO_DB_LOCATION") != "/tmp/testdb.db" {
		t.Errorf("expected THREATCO_DB_LOCATION env var to be '/tmp/testdb.db'")
	}
	if cfg.Services[0].Key != "env-misp-key" || cfg.Services[0].Secret != "env-misp-secret" {
		t.Errorf("expected MISP key/secret overrides to apply")
	}
	if cfg.Services[1].Key != "existing-key" {
		t.Errorf("existing service key should not be overwritten")
	}
}

func TestConfiguration_PopulateFromJSONFile(t *testing.T) {
	tempDir := t.TempDir()
	filePath := filepath.Join(tempDir, "config.json")

	// Non-existent file
	cfg := &Configuration{}
	err := cfg.PopulateFromJSONFile(filepath.Join(tempDir, "nonexistent.json"))
	if err == nil {
		t.Errorf("expected error for nonexistent file")
	}

	// Valid JSON
	validCfg := Configuration{
		HTTPPort: "8080",
		FQDN:     "localhost",
	}
	data, _ := json.Marshal(validCfg)
	if err := os.WriteFile(filePath, data, 0644); err != nil {
		t.Fatalf("failed to write test config file: %v", err)
	}

	cfg = &Configuration{}
	if err := cfg.PopulateFromJSONFile(filePath); err != nil {
		t.Fatalf("PopulateFromJSONFile failed: %v", err)
	}
	if cfg.HTTPPort != "8080" || cfg.FQDN != "localhost" {
		t.Errorf("PopulateFromJSONFile loaded incorrect data: %+v", cfg)
	}

	// Invalid JSON
	invalidFilePath := filepath.Join(tempDir, "invalid.json")
	if err := os.WriteFile(invalidFilePath, []byte("{invalid json"), 0644); err != nil {
		t.Fatalf("failed to write invalid config file: %v", err)
	}
	if err := cfg.PopulateFromJSONFile(invalidFilePath); err == nil {
		t.Errorf("expected error for invalid json file")
	}
}

func TestConfiguration_PopulateFromEncryptedFile(t *testing.T) {
	tempDir := t.TempDir()
	filePath := filepath.Join(tempDir, "encrypted.cfg")

	key := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		t.Fatalf("failed to generate random key: %v", err)
	}

	origCfg := Configuration{
		HTTPPort: "8443",
		ServerID: "srv-001",
	}
	plaintext, _ := json.Marshal(origCfg)

	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatalf("aes.NewCipher failed: %v", err)
	}
	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatalf("cipher.NewGCM failed: %v", err)
	}

	nonce := make([]byte, aesGCM.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		t.Fatalf("failed to generate nonce: %v", err)
	}

	ciphertext := aesGCM.Seal(nil, nonce, plaintext, nil)
	content := hex.EncodeToString(nonce) + ":" + hex.EncodeToString(ciphertext)

	if err := os.WriteFile(filePath, []byte(content), 0644); err != nil {
		t.Fatalf("failed to write encrypted config file: %v", err)
	}

	cfg := &Configuration{}
	if err := cfg.PopulateFromEncryptedFile(filePath, key); err != nil {
		t.Fatalf("PopulateFromEncryptedFile failed: %v", err)
	}
	if cfg.HTTPPort != "8443" || cfg.ServerID != "srv-001" {
		t.Errorf("PopulateFromEncryptedFile loaded incorrect data: %+v", cfg)
	}

	// Test non-existent file
	if err := cfg.PopulateFromEncryptedFile(filepath.Join(tempDir, "nofile"), key); err == nil {
		t.Errorf("expected error for non-existent file")
	}

	// Test invalid format
	invalidFile := filepath.Join(tempDir, "badformat.cfg")
	os.WriteFile(invalidFile, []byte("no_colon_here"), 0644)
	if err := cfg.PopulateFromEncryptedFile(invalidFile, key); err == nil {
		t.Errorf("expected error for invalid format")
	}
}

func TestConfiguration_PopulateFromPasscodeFile(t *testing.T) {
	tempDir := t.TempDir()
	filePath := filepath.Join(tempDir, "passcode.cfg")
	passcode := "mysecretpasscode"

	origCfg := Configuration{
		HTTPPort: "9000",
		ServerID: "srv-passcode",
	}
	plaintext, _ := json.Marshal(origCfg)

	salt := make([]byte, 16)
	nonce := make([]byte, 12)
	io.ReadFull(rand.Reader, salt)
	io.ReadFull(rand.Reader, nonce)

	derivedKey := DeriveKey(passcode, salt)
	block, _ := aes.NewCipher(derivedKey)
	gcm, _ := cipher.NewGCM(block)

	ciphertext := gcm.Seal(nil, nonce, plaintext, nil)

	data := append(salt, nonce...)
	data = append(data, ciphertext...)

	if err := os.WriteFile(filePath, data, 0644); err != nil {
		t.Fatalf("failed to write passcode config file: %v", err)
	}

	cfg := &Configuration{}
	if err := cfg.PopulateFromPasscodeFile(filePath, passcode); err != nil {
		t.Fatalf("PopulateFromPasscodeFile failed: %v", err)
	}
	if cfg.HTTPPort != "9000" || cfg.ServerID != "srv-passcode" {
		t.Errorf("PopulateFromPasscodeFile loaded incorrect data: %+v", cfg)
	}

	// Short data test
	shortFile := filepath.Join(tempDir, "short.cfg")
	os.WriteFile(shortFile, []byte("too short"), 0644)
	if err := cfg.PopulateFromPasscodeFile(shortFile, passcode); err == nil {
		t.Errorf("expected error for short file")
	}

	// Wrong passcode test
	if err := cfg.PopulateFromPasscodeFile(filePath, "wrongpasscode"); err == nil {
		t.Errorf("expected error for wrong passcode")
	}
}
