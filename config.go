package main

import (
	"encoding/json"
	"fmt"
	"os"
)

type Configuration struct {
	ServerID            string        `json:"server_id"`
	FirstUserMode       bool          `json:"first_user_mode"`
	FQDN                string        `json:"fqdn"`
	Services            []ServiceType `json:"services"`
	HTTPPort            string        `json:"http_port"`
	HTTPsPort           string        `json:"https_port"`
	HTTPToo             bool          `json:"http_too"`
	TLSCert             string        `json:"tls_cert"`
	TLSKey              string        `json:"tls_key"`
	CertAuth            string        `json:"cert_auth"`
	DBLocation          string        `json:"db_location"`
	SessionTokenTTL     int           `json:"session_token_ttl"`
	ResponseCacheExpiry int           `json:"response_cache_expiry"`
	StatCacheTickRate   int           `json:"stat_cache_tick_rate"`
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
	return nil
}

func FileExists(fh string) bool {
	info, err := os.Stat(fh)
	if os.IsNotExist(err) {
		return false
	}
	return info.Mode().IsRegular()
}
