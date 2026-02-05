package internal

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/rexlx/threatco/optional"
)

type Configuration struct {
	Cors                []string         `json:"cors"`
	DatabaseType        string           `json:"database_type"`
	BindAddress         string           `json:"bind_address"`
	ServerID            string           `json:"server_id"`
	FirstUserMode       bool             `json:"first_user_mode"`
	FQDN                string           `json:"fqdn"`
	Services            []ServiceType    `json:"services"`
	HTTPPort            string           `json:"http_port"`
	HTTPsPort           string           `json:"https_port"`
	HTTPToo             bool             `json:"http_too"`
	TLSCert             string           `json:"tls_cert"`
	TLSKey              string           `json:"tls_key"`
	CertAuth            string           `json:"cert_auth"`
	DBLocation          string           `json:"db_location"`
	SessionTokenTTL     int              `json:"session_token_ttl"`
	ResponseCacheExpiry int              `json:"response_cache_expiry"`
	StatCacheTickRate   int              `json:"stat_cache_tick_rate"`
	LlmConf             LlmConfiguration `json:"llm"`
	EncKey              string           `json:"enc_key"`
	PreviousEncKey      string           `json:"previous_enc_key"`
}

type LlmConfiguration optional.LlmConfig

// ApplyEnvOverrides applies environment variable overrides to the configuration.
func (c *Configuration) ApplyEnvOverrides() {
	if c.LlmConf.ApiKey == "" {
		envVar := "THREATCO_LLM_API_KEY"
		apiKey := os.Getenv(envVar)
		if apiKey != "" {
			c.LlmConf.ApiKey = apiKey
		}
	}
	if c.EncKey != "" {
		err := os.Setenv("THREATCO_ENCRYPTION_KEY", c.EncKey)
		if err != nil {
			fmt.Printf("Warning: failed to set environment variable for encryption key: %v\n", err)
		}
		err = os.Setenv("THREATCO_OLD_ENCRYPTION_KEY", c.PreviousEncKey)
		if err != nil {
			fmt.Printf("Warning: failed to set environment variable for previous encryption key: %v\n", err)
		}
	}
	if c.DBLocation != "" {
		err := os.Setenv("THREATCO_DB_LOCATION", c.DBLocation)
		if err != nil {
			fmt.Printf("Warning: failed to set environment variable for DB location: %v\n", err)
		}
	}
	for i := range c.Services {
		if c.Services[i].Key == "" && c.Services[i].Kind != "" {
			envVarName := strings.ToUpper(c.Services[i].Kind) + "_KEY"
			envVarSecret := strings.ToUpper(c.Services[i].Kind) + "_SECRET"
			envVarName = strings.ReplaceAll(envVarName, " ", "_")
			envVarSecret = strings.ReplaceAll(envVarSecret, " ", "_")

			apiKey := os.Getenv(envVarName)
			secret := os.Getenv(envVarSecret)
			if secret != "" {
				c.Services[i].Secret = secret
			}
			if apiKey != "" {
				c.Services[i].Key = apiKey
			}
		}
	}
}

func (c *Configuration) PopulateFromJSONFile(fh string) error {
	if !FileExists(fh) {
		return fmt.Errorf("file does not exist: %s", fh)
	}
	file, err := os.Open(fh)
	if err != nil {
		return fmt.Errorf("could not open file: %v", err)
	}
	defer file.Close()

	d := json.NewDecoder(file)
	if err := d.Decode(c); err != nil {
		return fmt.Errorf("could not decode file: %v", err)
	}

	c.ApplyEnvOverrides()

	return nil
}

func (c *Configuration) PopulateFromEncryptedFile(fh string, key []byte) error {
	if !FileExists(fh) {
		return fmt.Errorf("file does not exist: %s", fh)
	}
	content, err := os.ReadFile(fh)
	if err != nil {
		return fmt.Errorf("could not read file: %v", err)
	}

	// Format is expected to be hex-encoded "nonce:ciphertext"
	parts := strings.Split(string(content), ":")
	if len(parts) != 2 {
		return fmt.Errorf("invalid encrypted file format (expected nonce:ciphertext)")
	}

	nonce, err := hex.DecodeString(parts[0])
	if err != nil {
		return fmt.Errorf("failed to decode nonce: %w", err)
	}
	ciphertext, err := hex.DecodeString(parts[1])
	if err != nil {
		return fmt.Errorf("failed to decode ciphertext: %w", err)
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return fmt.Errorf("failed to create cipher: %w", err)
	}
	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return fmt.Errorf("failed to create GCM: %w", err)
	}

	plaintext, err := aesGCM.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return fmt.Errorf("failed to decrypt config: %w", err)
	}

	if err := json.Unmarshal(plaintext, c); err != nil {
		return fmt.Errorf("failed to unmarshal JSON config: %w", err)
	}

	c.ApplyEnvOverrides()

	return nil
}

func (c *Configuration) PopulateFromPasscodeFile(fh string, passcode string) error {
	if !FileExists(fh) {
		return fmt.Errorf("file does not exist: %s", fh)
	}
	data, err := os.ReadFile(fh)
	if err != nil {
		return fmt.Errorf("could not read file: %v", err)
	}

	// Minimum length: 16 (salt) + 12 (nonce) + ciphertext
	if len(data) < 29 {
		return fmt.Errorf("invalid data: encrypted config too short")
	}

	salt := data[:16]
	nonce := data[16:28]
	ciphertext := data[28:]

	// Derive key using the same logic as ToolsDecryptHandler
	key := DeriveKey(passcode, salt)

	block, err := aes.NewCipher(key)
	if err != nil {
		return fmt.Errorf("cipher error: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return fmt.Errorf("GCM error: %w", err)
	}

	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return fmt.Errorf("decryption failed (wrong passcode?): %w", err)
	}

	if err := json.Unmarshal(plaintext, c); err != nil {
		return fmt.Errorf("failed to unmarshal JSON config: %w", err)
	}

	c.ApplyEnvOverrides()
	return nil
}

func FileExists(fh string) bool {
	info, err := os.Stat(fh)
	if os.IsNotExist(err) {
		return false
	}
	return info.Mode().IsRegular()
}
