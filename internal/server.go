package internal

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/alexedwards/scs/v2"
	"github.com/google/uuid"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/rexlx/threatco/views"
	"go.etcd.io/bbolt"
)

var (
	DeleteConfig  = flag.Bool("delete", false, "Delete configuration file")
	EncodedConfig = flag.Bool("encoded-config", false, "Is the config encoded?")
	SeedFile      = flag.String("seedfile", "", "Path to seed file for key generation")
	Fqdn          = flag.String("fqdn", "http://localhost", "Fully qualified domain name")
	DbLocation    = flag.String("db", "", "Database location")
	DbMode        = flag.String("dbmode", "postgres", "Database mode")
	KnowledgeBase = flag.String("kb", "/kb", "Knowledge base path")
	WebApp        = flag.String("app", "/webapp", "path to web application")
	ConfigPath    = flag.String("config", "/config.json", "Configuration file")
	StaticPath    = flag.String("static", "/static", "Static file path")
	FirstUserMode = flag.Bool("firstuse", false, "First user mode")
	UseSyslog     = flag.Bool("syslog", false, "Enable syslog")
	SyslogHost    = flag.String("syslog-host", "localhost", "Syslog host")
	SyslogIndex   = flag.String("syslog-index", "threatco", "Syslog index")
	HealthCheck   = flag.Int("health-check", 60, "Health check interval in seconds")
	RestoreDB     = flag.String("restore-db", "", "filepath to sql file if one needs to restore")
	PrepareTable  = flag.String("prepare-table", "", "Table to drop before startup")
)

const (
	Version          = "2025OCT01"
	KeyUsedNew       = "new"
	KeyUsedOld       = "old"
	KeyUsedPlaintext = "plaintext"
)

type Server struct {
	Session        *scs.SessionManager      `json:"-"`
	RespCh         chan ResponseItem        `json:"-"`
	StopCh         chan bool                `json:"-"`
	Cache          *Cache                   `json:"-"`
	DB             Database                 `json:"-"`
	Hub            *Hub                     `json:"-"`
	Gateway        *http.ServeMux           `json:"-"`
	Log            *log.Logger              `json:"-"`
	Memory         *sync.RWMutex            `json:"-"`
	Targets        map[string]*Endpoint     `json:"targets"`
	ProxyOperators map[string]ProxyOperator `json:"-"`
	ID             string                   `json:"id"`
	Details        Details                  `json:"details"`
	Gauges         *prometheus.GaugeVec     `json:"-"`
	ParserDuration *prometheus.HistogramVec `json:"-"`
}

type Details struct {
	LlmConf           LlmConfiguration   `json:"llm_config"`
	CorsOrigins       []string           `json:"cors_origins"`
	PreviousKey       *cipher.AEAD       `json:"-"`
	Key               *cipher.AEAD       `json:"-"`
	FirstUserMode     bool               `json:"first_user_mode"`
	FQDN              string             `json:"fqdn"`
	SupportedServices []ServiceType      `json:"supported_services"`
	Address           string             `json:"address"`
	StartTime         time.Time          `json:"start_time"`
	Stats             map[string]float64 `json:"stats"`
}

type Cache struct {
	Logs              []LogItem               `json:"logs"`
	Charts            []byte                  `json:"charts"`
	Coordinates       map[string][]Coord      `json:"coordinates"`
	ResponseExpiry    time.Duration           `json:"response_expiry"`
	Services          []ServiceType           `json:"services"`
	StatsHistory      []StatItem              `json:"stats_history"`
	Responses         map[string]ResponseItem `json:"responses"`
	VulnerabilityFeed []VulnerabilityItem     `json:"vulnerability_feed"`
}

type VulnerabilityItem struct {
	Title       string    `json:"title"`
	Description string    `json:"description"`
	Source      string    `json:"source"`
	URL         string    `json:"url"`
	Published   time.Time `json:"published"`
	IOCs        []string  `json:"iocs"`
	CWEs        []string  `json:"cwes"`
}

type Coord struct {
	Value float64 `json:"value"`
	Time  int64   `json:"time"`
}
type StatItem struct {
	Time int64              `json:"time"`
	Data map[string]float64 `json:"data"`
}

type ResponseItem struct {
	Email  string    `json:"email"`
	Notify bool      `json:"notify"`
	Log    bool      `json:"log"`
	ID     string    `json:"id"`
	Vendor string    `json:"vendor"`
	Time   time.Time `json:"time"`
	Data   []byte    `json:"data"`
}

type LogItem struct {
	Time  time.Time `json:"time"`
	Data  string    `json:"data"`
	Error bool      `json:"error"`
}

var ErrInvalidFormat = errors.New("invalid encrypted data format (might be plaintext)")

func NewServer(id string, address string, dbType string, dbLocation string, logger *log.Logger) (*Server, *Configuration) {
	c := &Configuration{}
	keyHex := os.Getenv("THREATCO_ENCRYPTION_KEY")
	if keyHex == "" {
		logger.Fatal("THREATCO_ENCRYPTION_KEY environment variable not set")
	}
	keyOldHex := os.Getenv("THREATCO_OLD_ENCRYPTION_KEY")

	var database Database
	targets := make(map[string]*Endpoint)
	operators := make(map[string]ProxyOperator)
	memory := &sync.RWMutex{}

	gateway := http.NewServeMux()
	cache := &Cache{
		Logs:              make([]LogItem, 0),
		Coordinates:       make(map[string][]Coord),
		StatsHistory:      make([]StatItem, 0),
		Responses:         make(map[string]ResponseItem),
		Charts:            []byte(views.NoDataView),
		VulnerabilityFeed: make([]VulnerabilityItem, 0),
	}

	stopCh := make(chan bool)
	resch := make(chan ResponseItem, 200)
	sessionMgr := scs.New()
	sessionMgr.Lifetime = 24 * time.Hour
	sessionMgr.IdleTimeout = 4 * time.Hour
	sessionMgr.Cookie.Persist = true
	sessionMgr.Cookie.Name = "token"
	sessionMgr.Cookie.SameSite = http.SameSiteLaxMode
	sessionMgr.Cookie.HttpOnly = true

	key, err := hex.DecodeString(keyHex)
	if err != nil {
		log.Fatalf("Failed to decode ENCRYPTION_KEY: %v", err)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		log.Fatalf("Failed to create cipher block: %v", err)
	}
	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		log.Fatalf("Failed to create GCM: %v", err)
	}
	svr := &Server{
		Hub:            NewHub(),
		Log:            logger,
		Session:        sessionMgr,
		RespCh:         resch,
		StopCh:         stopCh,
		Cache:          cache,
		Targets:        targets,
		ProxyOperators: operators,
		Memory:         memory,
		Gateway:        gateway,
		ID:             id,
	}
	svr.Details = Details{
		Key:               &aesGCM,
		FQDN:              *Fqdn,
		SupportedServices: SupportedServices,
		Address:           address,
		StartTime:         time.Now(),
		Stats:             make(map[string]float64),
	}
	svr.InitializeFromConfig(c, true)
	if dbLocation == "" {
		dbLocation = os.Getenv("THREATCO_DB_LOCATION")
	}
	switch dbType {
	case "bbolt":
		db, err := bbolt.Open(dbLocation, 0600, nil)
		if err != nil {
			log.Fatalf("bbolt could not open database: %v", err)
		}
		database = &BboltDB{DB: db}
	case "postgres":
		db, err := NewPostgresDB(dbLocation, *PrepareTable)
		if err != nil {
			log.Fatalf("postgres could not open database: %v", err)
		}
		database = db
	default:
		log.Fatalf("unsupported database type: %s", dbType)
	}
	if *RestoreDB != "" {
		fmt.Println("got the restore db flag:", *RestoreDB)
		err := database.Restore(*RestoreDB)
		if err != nil {
			log.Fatalf("could not restore database from %s: %v", *RestoreDB, err)
		}
		fmt.Printf("database restored from %s successfully", *RestoreDB)
	}
	svr.DB = database
	if id == "" {
		id = fmt.Sprintf("%v-%v-%v", time.Now().Unix(), Version, "non-prod")
	}

	if keyOldHex != "" {
		logger.Println("Old encryption key detected, will attempt to support decryption with old key")
		oldKey, err := hex.DecodeString(keyOldHex)
		if err != nil {
			logger.Fatalf("Failed to decode THREATCO_OLD_ENCRYPTION_KEY: %v", err)
		}
		oldBlock, err := aes.NewCipher(oldKey)
		if err != nil {
			logger.Fatalf("Failed to create cipher block for old key: %v", err)
		}
		oldAesGCM, err := cipher.NewGCM(oldBlock)
		if err != nil {
			logger.Fatalf("Failed to create GCM for old key: %v", err)
		}
		svr.Details.PreviousKey = &oldAesGCM
	}
	svr.Gauges = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "vendor_responses",
			Help: "Custom statistics from ThreatCo internal state",
		},
		[]string{"vendor_responses"},
	)
	svr.ParserDuration = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "parser_handler_duration_ms",
			Help:    "Duration of parse handler requests in milliseconds",
			Buckets: []float64{100, 500, 1000, 2000, 5000, 10000},
		},
		[]string{"status"},
	)

	prometheus.MustRegister(svr.ParserDuration)
	prometheus.MustRegister(svr.Gauges)
	svr.ID = id
	svr.ManageCases()
	SetGlobalHub(svr.Hub)
	fmt.Println("Server initialized with ID:", svr.ID)
	svr.ProxyOperators["internal-case"] = ThreatcoInternalCaseSearchBuilder(svr.DB)
	return svr, c
}

func (s *Server) Encrypt(plaintext string) (string, error) {
	aesGCM := *s.Details.Key
	nonce := make([]byte, aesGCM.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", fmt.Errorf("failed to create nonce: %w", err)
	}
	ciphertext := aesGCM.Seal(nil, nonce, []byte(plaintext), nil)
	return fmt.Sprintf("%x:%x", nonce, ciphertext), nil
}

func (s *Server) tryDecrypt(encryptedValue string, key cipher.AEAD) (string, error) {
	parts := strings.Split(encryptedValue, ":")
	if len(parts) != 2 {
		return "", ErrInvalidFormat
	}

	nonce, err := hex.DecodeString(parts[0])
	if err != nil {
		return "", ErrInvalidFormat
	}
	ciphertext, err := hex.DecodeString(parts[1])
	if err != nil {
		return "", ErrInvalidFormat
	}

	plaintextBytes, err := key.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", err
	}

	return string(plaintextBytes), nil
}

func (s *Server) Decrypt(dbValue string) (string, string, error) {
	if s.Details.Key != nil {
		plaintext, err := s.tryDecrypt(dbValue, *s.Details.Key)
		if err == nil {
			return plaintext, KeyUsedNew, nil
		}
	}

	if s.Details.PreviousKey != nil {
		plaintext, errOld := s.tryDecrypt(dbValue, *s.Details.PreviousKey)
		if errOld == nil {
			return plaintext, KeyUsedOld, nil
		}

		if !errors.Is(errOld, ErrInvalidFormat) {
			return "", "", errOld
		}
	}

	return dbValue, KeyUsedPlaintext, nil
}

func (s *Server) LegacyDecrypt(encryptedValue string) (string, error) {
	start := time.Now()
	defer func(t time.Time) {
		fmt.Println("Decrypt took", time.Since(t))
	}(start)
	parts := strings.Split(encryptedValue, ":")
	if len(parts) != 2 {
		return "", fmt.Errorf("invalid encrypted data format")
	}

	nonce, err := hex.DecodeString(parts[0])
	if err != nil {
		return "", fmt.Errorf("failed to decode nonce: %w", err)
	}
	ciphertext, err := hex.DecodeString(parts[1])
	if err != nil {
		return "", fmt.Errorf("failed to decode ciphertext: %w", err)
	}

	aesGCM := *s.Details.Key
	plaintextBytes, err := aesGCM.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", fmt.Errorf("failed to decrypt data: %w", err)
	}

	return string(plaintextBytes), nil
}

func (s *Server) addStat(key string, value float64) {
	s.Memory.Lock()
	defer s.Memory.Unlock()
	s.Details.Stats[key] += value
}

func (s *Server) UpdateCache() {
	s.Memory.Lock()
	defer s.Memory.Unlock()

	s.Details.Stats["cache_updates"]++

	stat := StatItem{
		Time: time.Now().Unix(),
		Data: make(map[string]float64),
	}

	for k, v := range s.Details.Stats {
		stat.Data[k] = v
	}
	s.Cache.StatsHistory = append(s.Cache.StatsHistory, stat)
	if len(s.Cache.StatsHistory) > 1000 {
		s.Cache.StatsHistory = s.Cache.StatsHistory[1:]
	}
}

func (s *Server) CleanUsers() {
	var allErrs []error
	users, err := s.DB.GetAllUsers()
	if err != nil {
		s.Log.Printf("ERROR: could not retrieve users for cleanup: %v", err)
		return
	}
	for _, user := range users {
		s.CleanUserServices(&user)
		err := s.DB.AddUser(user)
		if err != nil {
			allErrs = append(allErrs, fmt.Errorf("failed to update user %s during cleanup: %w", user.Email, err))
			continue
		}
	}
	if len(allErrs) > 0 {
		out := ""
		for _, err := range allErrs {
			out += err.Error() + "; "
		}

		s.Log.Printf("ERROR: encountered errors during user cleanup: %s", out)
	}

}

func (s *Server) LogError(err error) {
	s.Log.Println(err)
	s.Memory.Lock()
	defer s.Memory.Unlock()
	s.Cache.Logs = append(s.Cache.Logs, LogItem{
		Time:  time.Now(),
		Data:  err.Error(),
		Error: true,
	})
}

func (s *Server) LogInfo(info string) {
	s.Log.Println(info)
	s.Memory.Lock()
	defer s.Memory.Unlock()
	s.Cache.Logs = append(s.Cache.Logs, LogItem{
		Time:  time.Now(),
		Data:  info,
		Error: false,
	})
}

func (s *Server) GetLogs() []LogItem {
	newLogs := make([]LogItem, 0)
	s.Memory.RLock()
	defer s.Memory.RUnlock()
	newLogs = append(newLogs, s.Cache.Logs...)
	return newLogs
}

func (s *Server) ProcessTransientResponses() {
	ticker := time.NewTicker(1 * time.Hour)
	defer ticker.Stop()
	for {
		select {
		case resp := <-s.RespCh:
			s.Memory.RLock()
			r, exists := s.Cache.Responses[resp.ID]
			var oldData []byte
			if exists {
				oldData = r.Data
			}
			s.Memory.RUnlock()
			var finalData []byte
			var err error

			if !exists {
				finalData, err = MergeJSONData(nil, resp.Data)
			} else {
				finalData, err = MergeJSONData(oldData, resp.Data)
			}

			if err != nil {
				s.Log.Printf("ERROR: could not merge JSON for ID %s: %v", resp.ID, err)
				continue
			}
			resp.Data = finalData
			if exists {
				resp.Time = r.Time
			}

			s.Memory.Lock()
			s.Cache.Responses[resp.ID] = resp

			s.Details.Stats[resp.Vendor] += float64(len(resp.Data))
			s.Details.Stats["vendor_responses"]++
			s.Memory.Unlock()

			err = s.DB.StoreResponse(false, resp.ID, resp.Data, resp.Vendor)
			if err != nil {
				s.Log.Printf("ERROR: could not store response ID %s: %v", resp.ID, err)
			}
			if resp.Notify {
				err := s.Hub.SendToUser(s.RespCh, resp.Email, Notification{
					Created: resp.Time,
					Info:    fmt.Sprintf("New response from %s with ID %s", resp.Vendor, resp.ID),
					Error:   false,
				})
				if err != nil {
					s.DB.AddNotification(resp.Email, Notification{
						Created: resp.Time,
						Info:    fmt.Sprintf("New response from %s with ID %s", resp.Vendor, resp.ID),
						Error:   false,
					})
				}
			}
			if resp.Log {
				info := fmt.Sprintf("New response from %s with ID %s from %v", resp.Vendor, resp.ID, resp.Email)
				s.LogInfo(info)
			}
		case <-ticker.C:
			go s.DB.CleanResponses(s.Cache.ResponseExpiry)
			go s.CleanupClosedCases()
			s.Memory.Lock()
			for k, v := range s.Cache.Responses {
				if time.Since(v.Time) > s.Cache.ResponseExpiry {
					s.Log.Printf("Removing response %s from cache due to expiry", k)
					delete(s.Cache.Responses, k)
				}
			}
			s.Memory.Unlock()
			go func() {
				if err := s.DB.CleanSearchHistory(60); err != nil {
					s.Log.Printf("ERROR: search history cleanup failed: %v", err)
				}
			}()
		}
	}
}
func (t *Token) CreateToken(userID string, ttl time.Duration) (*Token, error) {
	tk := &Token{
		UserID:    userID,
		ExpiresAt: time.Now().Add(ttl),
	}
	hotSauce := make([]byte, 64)
	_, err := io.ReadFull(rand.Reader, hotSauce)
	if err != nil {
		return nil, err
	}
	tk.Token = uuid.New().String()
	hash := sha256.Sum256([]byte(tk.Token))
	tk.Hash = hash[:]
	return tk, nil
}

func (s *Server) AddTokenToSession(r *http.Request, w http.ResponseWriter, tk *Token) error {
	s.Session.Put(r.Context(), "token", tk.Token)
	return nil
}

func (s *Server) DeleteTokenFromSession(r *http.Request) error {
	s.Session.Remove(r.Context(), "token")
	return nil
}

func (s *Server) GetTokenFromSession(r *http.Request) (string, error) {
	tk, ok := s.Session.Get(r.Context(), "token").(string)
	if !ok {
		return "", errors.New("error getting token from session")
	}
	return tk, nil
}

func (s *Server) AddResponse(vendor, uid string, data []byte) {
	resp := ResponseItem{
		Vendor: vendor,
		ID:     uid,
		Time:   time.Now(),
		Data:   data,
	}
	s.RespCh <- resp
}

func (s *Server) InitializeFromConfig(cfg *Configuration, fromFile bool) {
	if fromFile {
		if *EncodedConfig {
			fmt.Println("Loading encoded configuration...")
			partialKey := os.Getenv("THREATCO_CONFIG_KEY")
			if partialKey == "" {
				log.Fatal("THREATCO_CONFIG_KEY environment variable is required when -encoded-config is set")
			}
			if *SeedFile == "" {
				log.Fatal("-seedfile flag is required when -encoded-config is set")
			}
			f, err := os.Open(*SeedFile)
			if err != nil {
				log.Fatalf("Failed to open seed file: %v", err)
			}
			defer f.Close()
			seedHash, err := CalculateSHA256(f)
			if err != nil {
				log.Fatalf("Failed to hash seed file: %v", err)
			}
			passcode := partialKey + seedHash
			err = cfg.PopulateFromPasscodeFile(*ConfigPath, passcode)
			if err != nil {
				log.Fatalf("Failed to populate from passcode file: %v", err)
			}
		} else {
			err := cfg.PopulateFromJSONFile(*ConfigPath)
			if err != nil {
				log.Fatalf("could not populate from file: %v", err)
			}
		}
		if *DeleteConfig {
			err := DeleteConfigFile(*ConfigPath)
			if err != nil {
				log.Fatalf("could not delete config file: %v", err)
			}
			fmt.Println("config file deleted")
		}
	}
	for _, svc := range cfg.Services {
		u := svc.URL
		parts := strings.Split(svc.AuthType, "|")
		if len(parts) > 1 {
			u = parts[1]
		}
		authName := parts[0]
		switch authName {
		case "key":
			thisAuthType := &XAPIKeyAuth{Token: svc.Key}
			thisEndpoint := NewEndpoint(svc.URL, thisAuthType, svc.Insecure, s.RespCh, svc.Kind)
			thisEndpoint.RateLimited = svc.RateLimited
			thisEndpoint.MaxRequests = svc.MaxRequests
			thisEndpoint.RefillRate = time.Duration(svc.RefillRate) * time.Second
			thisEndpoint.UploadService = svc.UploadService
			s.Memory.Lock()
			s.Targets[svc.Kind] = thisEndpoint
			s.Memory.Unlock()
		case "token":
			thisAuthType := &KeyAuth{Token: svc.Key}
			thisEndpoint := NewEndpoint(svc.URL, thisAuthType, svc.Insecure, s.RespCh, svc.Kind)
			thisEndpoint.RateLimited = svc.RateLimited
			thisEndpoint.MaxRequests = svc.MaxRequests
			thisEndpoint.RefillRate = time.Duration(svc.RefillRate) * time.Second
			thisEndpoint.UploadService = svc.UploadService
			s.Memory.Lock()
			s.Targets[svc.Kind] = thisEndpoint
			s.Memory.Unlock()
		case "basic":
			thisAuthType := &BasicAuth{Username: svc.Secret, Password: svc.Key}
			thisEndpoint := NewEndpoint(svc.URL, thisAuthType, svc.Insecure, s.RespCh, svc.Kind)
			thisEndpoint.RateLimited = svc.RateLimited
			thisEndpoint.MaxRequests = svc.MaxRequests
			thisEndpoint.RefillRate = time.Duration(svc.RefillRate) * time.Second
			thisEndpoint.UploadService = svc.UploadService
			s.Memory.Lock()
			s.Targets[svc.Kind] = thisEndpoint
			s.Memory.Unlock()
		case "fetch":
			thisAuthType := &PrefetchAuth{
				URL:     u,
				Key:     svc.Key,
				Secret:  svc.Secret,
				Expires: svc.Expires,
			}
			thisEndpoint := NewEndpoint(svc.URL, thisAuthType, svc.Insecure, s.RespCh, svc.Kind)
			thisEndpoint.RateLimited = svc.RateLimited
			thisEndpoint.MaxRequests = svc.MaxRequests
			thisEndpoint.RefillRate = time.Duration(svc.RefillRate) * time.Second
			thisEndpoint.UploadService = svc.UploadService
			s.Memory.Lock()
			s.Targets[svc.Kind] = thisEndpoint
			s.Memory.Unlock()
		case "vmray":
			thisAuthType := &VmRayAuth{Token: svc.Key}
			thisEndpoint := NewEndpoint(svc.URL, thisAuthType, svc.Insecure, s.RespCh, svc.Kind)
			thisEndpoint.RateLimited = svc.RateLimited
			thisEndpoint.MaxRequests = svc.MaxRequests
			thisEndpoint.RefillRate = time.Duration(svc.RefillRate) * time.Second
			thisEndpoint.UploadService = svc.UploadService
			s.Memory.Lock()
			s.Targets[svc.Kind] = thisEndpoint
			s.Memory.Unlock()
		case "urlscan":
			thisAuthType := &URLScanAuth{Token: svc.Key}
			thisEndpoint := NewEndpoint(svc.URL, thisAuthType, svc.Insecure, s.RespCh, svc.Kind)
			thisEndpoint.RateLimited = svc.RateLimited
			thisEndpoint.MaxRequests = svc.MaxRequests
			thisEndpoint.RefillRate = time.Duration(svc.RefillRate) * time.Second
			thisEndpoint.UploadService = svc.UploadService
			s.Memory.Lock()
			s.Targets[svc.Kind] = thisEndpoint
			s.Memory.Unlock()
		case "abuseipdb":
			thisAuthType := &AbuseIPDBAuth{Token: svc.Key}
			thisEndpoint := NewEndpoint(svc.URL, thisAuthType, svc.Insecure, s.RespCh, svc.Kind)
			thisEndpoint.RateLimited = svc.RateLimited
			thisEndpoint.MaxRequests = svc.MaxRequests
			thisEndpoint.RefillRate = time.Duration(svc.RefillRate) * time.Second
			thisEndpoint.UploadService = svc.UploadService
			s.Memory.Lock()
			s.Targets[svc.Kind] = thisEndpoint
			s.Memory.Unlock()
		case "otx":
			thisAuthType := &OTXAuth{Token: svc.Key}
			thisEndpoint := NewEndpoint(svc.URL, thisAuthType, svc.Insecure, s.RespCh, svc.Kind)
			thisEndpoint.RateLimited = svc.RateLimited
			thisEndpoint.MaxRequests = svc.MaxRequests
			thisEndpoint.RefillRate = time.Duration(svc.RefillRate) * time.Second
			thisEndpoint.UploadService = svc.UploadService
			s.Memory.Lock()
			s.Targets[svc.Kind] = thisEndpoint
			s.Memory.Unlock()
		default:
			fmt.Printf("unsupported auth type: %s, defaulting to bearer\n", svc.AuthType)
			thisAuthType := &BearerAuth{Token: svc.Key}
			thisEndpoint := NewEndpoint(svc.URL, thisAuthType, svc.Insecure, s.RespCh, svc.Kind)
			thisEndpoint.RateLimited = svc.RateLimited
			thisEndpoint.MaxRequests = svc.MaxRequests
			thisEndpoint.RefillRate = time.Duration(svc.RefillRate) * time.Second
			thisEndpoint.UploadService = svc.UploadService
			s.Memory.Lock()
			s.Targets[svc.Kind] = thisEndpoint
			s.Memory.Unlock()
			fmt.Printf("added service %s with bearer auth", svc.Kind)
		}
	}
	if *FirstUserMode {
		s.Details.FirstUserMode = true
	}
	s.Details.SupportedServices = cfg.Services
	s.Details.FQDN = cfg.FQDN
	if len(cfg.Cors) == 0 {
		s.Details.CorsOrigins = []string{
			cfg.FQDN,
			"http://localhost:8080",
			"http://127.0.0.1:8080",
		}
	} else {
		s.Details.CorsOrigins = cfg.Cors
	}
	s.Details.Address = fmt.Sprintf("%s:%s", cfg.BindAddress, cfg.HTTPPort)
	s.Cache.ResponseExpiry = time.Duration(cfg.ResponseCacheExpiry) * time.Second
	s.Details.FirstUserMode = cfg.FirstUserMode
	s.Details.LlmConf = cfg.LlmConf
	fmt.Println(s.Details.LlmConf)
	s.Session.Lifetime = time.Duration(cfg.SessionTokenTTL) * time.Hour
	for name, service := range s.Targets {
		thisAuth := service.Auth
		go thisAuth.GetAndStoreToken(s.StopCh)
		op, ok := ProxyOperators[name]
		if !ok {
			fmt.Printf("no proxy operator for service %s, skipping", name)
			continue
		}
		s.ProxyOperators[name] = op
	}
	s.Gateway.Handle("/archive", http.HandlerFunc(s.ValidateSessionToken(s.ArchiveResponseHandler)))
	s.Gateway.Handle("/deleteuser", http.HandlerFunc(s.ValidateSessionToken(s.DeleteUserHandler)))
	s.Gateway.Handle("/events/", http.HandlerFunc(s.ValidateSessionToken(s.EventHandler)))
	s.Gateway.Handle("/kb/", http.StripPrefix("/kb/", http.FileServer(http.Dir(*KnowledgeBase))))
	s.Gateway.Handle("/login", s.RateLimit(http.HandlerFunc(s.LoginHandler)))
	s.Gateway.Handle("/pipe", http.HandlerFunc(s.ValidateSessionToken(s.ProxyHandler)))
	s.Gateway.Handle("/raw", http.HandlerFunc(s.ValidateSessionToken(s.RawResponseHandler)))
	s.Gateway.Handle("/ring", http.HandlerFunc(s.ValidateSessionToken(s.SendTestNotificationHandler)))
	s.Gateway.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.Dir(*StaticPath))))
	s.Gateway.Handle("/stats", http.HandlerFunc(s.ValidateSessionToken(s.GetStatsHandler)))
	s.Gateway.Handle("/updateuser", http.HandlerFunc(s.ValidateSessionToken(s.UpdateUserHandler)))
	s.Gateway.Handle("/upload", http.HandlerFunc(s.ValidateSessionToken(s.UploadFileHandler)))
	s.Gateway.Handle("/user", http.HandlerFunc(s.ValidateSessionToken(s.GetUserHandler)))
	s.Gateway.Handle("/users", http.HandlerFunc(s.ValidateSessionToken(s.AllUsersViewHandler)))
	s.Gateway.HandleFunc("/add-service", http.HandlerFunc(s.ValidateSessionToken(s.AddServicesHandler)))
	s.Gateway.HandleFunc("/aireport", s.ValidateSessionToken(s.AIReportHandler))
	s.Gateway.HandleFunc("/addservice", http.HandlerFunc(s.ValidateSessionToken(s.AddServiceHandler)))
	s.Gateway.HandleFunc("/assisteddeath", http.HandlerFunc(s.ValidateSessionToken(s.KillServerDeadHandler)))
	s.Gateway.HandleFunc("/backup", http.HandlerFunc(s.ValidateSessionToken(s.BackupHandler)))
	s.Gateway.HandleFunc("/cases/create", http.HandlerFunc(s.ValidateSessionToken(s.CreateCaseHandler)))
	s.Gateway.HandleFunc("/cases/delete", http.HandlerFunc(s.ValidateSessionToken(s.DeleteCaseHandler)))
	s.Gateway.HandleFunc("/cases/export", http.HandlerFunc(s.ValidateSessionToken(s.ExportCasesCSVHandler)))
	s.Gateway.HandleFunc("/cases/get", http.HandlerFunc(s.ValidateSessionToken(s.GetCaseHandler)))
	s.Gateway.HandleFunc("/cases/list", http.HandlerFunc(s.ValidateSessionToken(s.GetCasesHandler)))
	s.Gateway.HandleFunc("/cases/search", http.HandlerFunc(s.ValidateSessionToken(s.SearchCasesHandler)))
	s.Gateway.HandleFunc("/cases/update", http.HandlerFunc(s.ValidateSessionToken(s.UpdateCaseHandler)))
	s.Gateway.HandleFunc("/charts", s.ChartViewHandler)
	s.Gateway.HandleFunc("/coordinate", http.HandlerFunc(s.ValidateSessionToken(s.GetCoordinateHandler)))
	s.Gateway.HandleFunc("/create-user", http.HandlerFunc(s.ValidateSessionToken(s.CreateUserViewHandler)))
	s.Gateway.HandleFunc("/dashboard/stats", s.ValidateSessionToken(s.GetDashboardStatsHandler))
	s.Gateway.HandleFunc("/deleteresponse", http.HandlerFunc(s.ValidateSessionToken(s.DeleteResponseHandler)))
	s.Gateway.HandleFunc("/exportresponses", http.HandlerFunc(s.ValidateSessionToken(s.ExportResponseCSVHandler)))
	s.Gateway.HandleFunc("/failed-requests", http.HandlerFunc(s.ValidateSessionToken(s.GetFailedRequestsHandler)))
	s.Gateway.HandleFunc("/failed-requests/delete", http.HandlerFunc(s.ValidateSessionToken(s.DeleteFailedRequestHandler)))
	s.Gateway.HandleFunc("/generatekey", http.HandlerFunc(s.ValidateSessionToken(s.GenerateAPIKeyHandler)))
	s.Gateway.HandleFunc("/getlogs", http.HandlerFunc(s.ValidateSessionToken(s.LogsSSRHandler)))
	s.Gateway.HandleFunc("/getresponses", http.HandlerFunc(s.ValidateSessionToken(s.GetResponseCacheHandler2)))
	s.Gateway.HandleFunc("/getusers", http.HandlerFunc(s.ValidateSessionToken(s.GetAllUsersHandler)))
	s.Gateway.HandleFunc("/getservices", http.HandlerFunc(s.ValidateSessionToken(s.GetServicesHandler)))
	s.Gateway.HandleFunc("/getuptime", http.HandlerFunc(s.ValidateSessionToken(s.GetRuntimeHandler)))
	s.Gateway.HandleFunc("/logger", http.HandlerFunc(s.ValidateSessionToken(s.LogHandler)))
	s.Gateway.HandleFunc("/logs", http.HandlerFunc(s.ValidateSessionToken(s.GetLogsHandler)))
	s.Gateway.HandleFunc("/misp-workflow", http.HandlerFunc(s.ValidateSessionToken(s.TriggerMispWorkflowHandler)))
	s.Gateway.HandleFunc("/misp/workflow/batch", http.HandlerFunc(s.ValidateSessionToken(s.TriggerMispBatchWorkflowHandler)))
	s.Gateway.HandleFunc("/notifications", http.HandlerFunc(s.ValidateSessionToken(s.GetNotificationsHandler)))
	s.Gateway.HandleFunc("/notifications/delete", http.HandlerFunc(s.ValidateSessionToken(s.DeleteNotificationHandler)))
	s.Gateway.HandleFunc("/parse", http.HandlerFunc(s.ValidateSessionToken(s.ParserHandler)))
	s.Gateway.HandleFunc("/previous-results", http.HandlerFunc(s.ValidateSessionToken(s.GetPreviousResponsesHandler)))
	s.Gateway.HandleFunc("/rectify", http.HandlerFunc(s.ValidateSessionToken(s.RectifyServicesHandler)))
	s.Gateway.HandleFunc("/responses", http.HandlerFunc(s.ValidateSessionToken(s.ViewResponsesHandler)))
	s.Gateway.HandleFunc("/rextest", http.HandlerFunc(s.ValidateSessionToken(s.RexsTestHandler)))
	s.Gateway.HandleFunc("/services", http.HandlerFunc(s.ValidateSessionToken(s.ViewServicesHandler)))
	s.Gateway.HandleFunc("/tools/checksum", http.HandlerFunc(s.ValidateSessionToken(s.ToolsChecksumHandler)))
	s.Gateway.HandleFunc("/tools/decrypt", http.HandlerFunc(s.ValidateSessionToken(s.ToolsDecryptHandler)))
	s.Gateway.HandleFunc("/tools/npm-check", http.HandlerFunc(s.ValidateSessionToken(s.ToolsNpmCheckHandler)))
	s.Gateway.HandleFunc("/tools/dnslookup", http.HandlerFunc(s.ValidateSessionToken(s.DNSLookupHandler)))
	s.Gateway.HandleFunc("/tools/uuid", http.HandlerFunc(s.ValidateSessionToken(s.ToolsGenerateUUIDHandler)))
	s.Gateway.HandleFunc("/tools/password", http.HandlerFunc(s.ValidateSessionToken(s.ToolsGeneratePasswordHandler)))
	s.Gateway.HandleFunc("/tools/dnslookup2", http.HandlerFunc(s.ValidateSessionToken(s.DNSLookupHandler2)))
	s.Gateway.HandleFunc("/tools/parse-url", http.HandlerFunc(s.ValidateSessionToken(s.ParseURLHandler)))
	s.Gateway.HandleFunc("/tools/encrypt", http.HandlerFunc(s.ValidateSessionToken(s.ToolsEncryptHandler)))
	s.Gateway.HandleFunc("/tools/inspect-archive", http.HandlerFunc(s.ValidateSessionToken(s.ToolsInspectArchiveHandler)))
	s.Gateway.HandleFunc("/tools/parse", http.HandlerFunc(s.ValidateSessionToken(s.ParseFileHandler)))
	s.Gateway.HandleFunc("/tools/ssh-exec", http.HandlerFunc(s.ValidateSessionToken(s.ToolsSSHExecHandler)))
	s.Gateway.HandleFunc("/tools/ssh-gen", http.HandlerFunc(s.ValidateSessionToken(s.ToolsGenerateSSHKeyHandler)))
	s.Gateway.HandleFunc("/tools/ssh-deploy", http.HandlerFunc(s.ValidateSessionToken(s.ToolsSSHDeployHandler)))
	s.Gateway.HandleFunc("/updatekey", http.HandlerFunc(s.ValidateSessionToken(s.NewApiKeyGeneratorHandler)))
	s.Gateway.HandleFunc("/view-logs", http.HandlerFunc(s.ValidateSessionToken(s.LogViewHandler)))
	s.Gateway.HandleFunc("/ws", http.HandlerFunc(s.ValidateSessionToken(s.ServeWs)))
	s.Gateway.HandleFunc("/history", s.GetStatHistoryHandler)
	s.Gateway.HandleFunc("/vulnerabilities/feed", s.ValidateSessionToken(s.GetVulnerabilityFeedHandler))

	appDir := http.Dir(*WebApp)
	s.Gateway.Handle("/app/", http.StripPrefix("/app/", s.ProtectedFileServer(appDir)))
	if s.Details.FirstUserMode {
		s.Gateway.HandleFunc("/adduser", s.FirstUseHandler)
	} else {
		s.Gateway.Handle("/adduser", http.HandlerFunc(s.ValidateSessionToken(s.AddUserHandler)))
	}
	s.Gateway.Handle("/", http.HandlerFunc(s.LoginViewHandler))
	s.Gateway.HandleFunc("/logout", s.LogoutHandler)
	s.Details.Stats["vendor_responses"] = 0
	go s.Hub.Run()
}

func (s *Server) AutomatedThreatScan() {
	start := time.Now()
	defer func() {
		duration := time.Since(start)
		fmt.Println(fmt.Sprintf("AutomatedThreatScan completed in %v", duration))
	}()
	scanWindow := time.Now().Add(-1 * time.Hour)
	responses, err := s.DB.GetResponses(scanWindow)
	if err != nil {
		s.Log.Println("AutomatedThreatScan error getting responses:", err)
		return
	}

	for _, r := range responses {
		tid, err := ExtractThreatLevelID(r.Data)
		if err != nil {
			continue
		}

		if tid >= 4 {
			se, err := ExtractSummarizedEvent(r.Data)
			if err != nil {
				s.Log.Printf("AutomatedThreatScan: failed to extract event: %v", err)
				continue
			}

			botUser := fmt.Sprintf("%v bot", se.SearchedBy)
			responseMarker := fmt.Sprintf("[response_id:%s]", r.ID)

			existingCases, err := s.DB.SearchCases(se.Value, 0)
			caseAlreadyExists := false

			if err == nil {
				for _, ec := range existingCases {
					if ec.ResponseID == r.ID {
						caseAlreadyExists = true
						break
					}
					for _, ioc := range ec.IOCs {
						if ioc == se.Value {
							caseAlreadyExists = true

							responseAlreadyTracked := false
							for _, comment := range ec.Comments {
								if strings.Contains(comment.Text, responseMarker) {
									responseAlreadyTracked = true
									break
								}
							}

							if !responseAlreadyTracked {
								newComment := Comment{
									User:      botUser,
									Text:      fmt.Sprintf("Automated scan detected %v again. Vendor: %s. %s", se.Value, r.Vendor, responseMarker),
									CreatedAt: time.Now(),
								}
								ec.Comments = append(ec.Comments, newComment)

								if err := s.DB.UpdateCase(ec); err != nil {
									s.Log.Printf("AutomatedThreatScan: failed to update case %s: %v", ec.ID, err)
								} else {
									s.Log.Println(fmt.Sprintf("AutomatedThreatScan: Added tracking comment to Case %s", ec.ID))
								}
							}
							break
						}
					}
					if caseAlreadyExists {
						break
					}
				}
			}

			if !caseAlreadyExists {
				newCase := Case{
					ID:          uuid.New().String(),
					Name:        fmt.Sprintf("Auto-Case: Critical Threat (%s)", se.Value),
					Description: fmt.Sprintf("Automated case for %v (%v). Info: %s.", r.ID, se.From, se.Info),
					CreatedBy:   botUser,
					CreatedAt:   time.Now(),
					Status:      "Open",
					IOCs:        []string{se.Value},
					Comments:    []Comment{},
					IsAuto:      true,
					ResponseID:  r.ID,
				}
				if err := s.DB.CreateCase(newCase); err != nil {
					s.Log.Println("Failed to create auto-case:", err)
				}
				go func() {
					out, err := json.Marshal(newCase)
					if err != nil {
						s.Log.Printf("Failed to marshal new case for notification: %v", err)
						return
					}
					s.Log.Println("__case__: AutomatedThreatScan: Created new case:", newCase.ID, string(out))
				}()
			}
		}
	}
}

func (s *Server) CleanupClosedCases() {
	cutoff := time.Now().AddDate(0, 0, -60)
	limit := 100
	offset := 0

	for {
		cases, err := s.DB.GetCases(limit, offset, "")
		if err != nil {
			s.Log.Printf("ERROR: Failed to fetch cases for cleanup: %v", err)
			break
		}

		if len(cases) == 0 {
			break
		}

		for _, c := range cases {
			if c.Status == "Closed" && c.CreatedAt.Before(cutoff) {
				if err := s.DB.DeleteCase(c.ID); err != nil {
					s.Log.Printf("ERROR: Failed to delete closed case %s: %v", c.ID, err)
				} else {
					s.LogInfo(fmt.Sprintf("Cleanup: Deleted closed case %s (%s) older than 60 days", c.ID, c.Name))
				}
			}
		}

		if len(cases) < limit {
			break
		}
		offset += limit
	}
}

func (s *Server) UpdateCharts() {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	s.Memory.Lock()
	defer s.Memory.Unlock()
	malloc := float64(m.Alloc)
	s.Details.Stats["malloc"] = malloc / 1024
	s.Details.Stats["goroutines"] = float64(runtime.NumGoroutine())
	s.Details.Stats["heap"] = float64(m.HeapAlloc) / 1024
	s.Details.Stats["heap_objects"] = float64(m.HeapObjects)
	s.Details.Stats["stack"] = float64(m.StackInuse) / 1024
	s.Details.Stats["alloc"] = float64(m.Alloc) / 1024
	s.Details.Stats["total_alloc"] = float64(m.TotalAlloc) / 1024
	s.Details.Stats["sys"] = float64(m.Sys) / 1024
	s.Details.Stats["num_gc"] = float64(m.NumGC)
	s.Details.Stats["pause_total_ns"] = float64(m.PauseTotalNs) / 1000000
	s.Details.Stats["go_memstats_alloc_bytes_total"] = float64(m.TotalAlloc)
	s.Details.Stats["go_memstats_frees_total"] = float64(m.Frees)
	s.Gauges.WithLabelValues("vendor_responses").Set(s.Details.Stats["vendor_responses"])
	for i, stat := range s.Details.Stats {
		_, ok := s.Cache.Coordinates[i]
		if !ok {
			s.Cache.Coordinates[i] = make([]Coord, 0)
		}
		if len(s.Cache.Coordinates[i]) > 100 {
			s.Cache.Coordinates[i] = s.Cache.Coordinates[i][1:]
		}
		s.Cache.Coordinates[i] = append(s.Cache.Coordinates[i], Coord{Value: stat, Time: time.Now().Unix()})
	}

	var buf bytes.Buffer
	for k, v := range s.Cache.Coordinates {
		chart := createLineChart(k, v)
		snippet := chart.RenderSnippet()
		buf.Write([]byte(snippet.Element))
		buf.Write([]byte(snippet.Script))
	}
	s.Cache.Charts = buf.Bytes()
}

func LogItemsToArticle(logs []LogItem) string {
	out := `<div class="scrollbar"><div class="thumb"></div></div>`
	templ := `<article class="message is-%s"><div class="message-header"><p>%s</p></div><div class="message-body">%v</div></article>`
	for _, log := range logs {
		var color string
		if log.Error {
			color = "danger"
		} else {
			color = "info"
		}
		out += fmt.Sprintf(templ, color, log.Time, log.Data)
	}
	return out
}

func LogItemsToPanel(logs []LogItem) string {
	out := `<div class="scrollbar"><div class="thumb"></div></div>`
	templ := `<article class="panel is-%s"><p class="panel-heading">%s</p><div class="panel-block">%v</div></article>`
	for _, log := range logs {
		var color string
		if log.Error {
			color = "danger"
		} else {
			color = "info"
		}
		out += fmt.Sprintf(`<div style="margin-bottom: 1em;">`+templ+`</div>`, color, log.Time, log.Data)
	}
	return out
}

func (s *Server) FakeLoggingEvent(n int) {
	for i := 0; i < n; i++ {
		s.LogError(fmt.Errorf("this is a fake error %d", i))
	}
}

func CreateFakeResponse() []byte {
	tmp := make(map[string]interface{})
	type fake struct {
		Iter  int    `json:"iter"`
		One   string `json:"one"`
		Two   string `json:"two"`
		ID    string `json:"id"`
		Email string `json:"email"`
	}
	type faek struct {
		One []string `json:"one"`
		Two []string `json:"two"`
	}
	tmp["one"] = fake{One: "one", Two: "two", ID: uuid.New().String(), Email: "okok@ok.com"}
	tmp["two"] = faek{One: []string{"one", "two"}, Two: []string{"three", "four"}}
	for i := 0; i < 100; i++ {
		tmp[uuid.New().String()] = fake{One: "one", Two: "two", ID: uuid.New().String(), Email: "ok@aol.com", Iter: i}
	}
	out, err := json.Marshal(tmp)
	if err != nil {
		return []byte("could not marshal fake response")
	}
	return out
}

func (s *Server) ManageCases() {
	fmt.Println("Running case management routine...")
	query := "SELECT * FROM cases"
	pgDB, ok := s.DB.(*PostgresDB)
	if !ok {
		fmt.Println("DB is not Postgres, cannot run case management")
		return
	}
	rows, err := pgDB.Pool.Query(context.Background(), query)
	if err != nil {
		fmt.Printf("Error querying cases: %v\n", err)
		return
	}
	defer rows.Close()

	for rows.Next() {
		var c Case
		err := rows.Scan(&c.ID, &c.Name, &c.Description, &c.CreatedBy, &c.CreatedAt, &c.Status, &c.IOCs, &c.Comments, &c.IsAuto, &c.ResponseID)
		if err != nil {
			fmt.Printf("Error scanning case row: %v\n", err)
			continue
		}
		if c.Status == "Open" && c.IsAuto && time.Since(c.CreatedAt) > 30*24*time.Hour {
			c.Status = "Closed"
			err := s.DB.UpdateCase(c)
			if err != nil {
				s.Log.Println(fmt.Sprintf("Error updating case %s: %v\n", c.ID, err))
			} else {
				s.Log.Println(fmt.Sprintf("Auto-closed case %s (%s) due to age\n", c.ID, c.Name))
			}
		}
		if c.Status == "Closed" && time.Since(c.CreatedAt) > 60*24*time.Hour {
			err := s.DB.DeleteCase(c.ID)
			if err != nil {
				s.Log.Println(fmt.Sprintf("Error deleting case %s: %v\n", c.ID, err))
			} else {
				s.Log.Println(fmt.Sprintf("Deleted case %s (%s) due to being closed and old\n", c.ID, c.Name))
			}
		}
	}
}

func (s *Server) PollVulnerabilityFeeds() {
	s.LogInfo("Beginning background synchronization task for CISA, Red Hat, and Canonical advisories...")

	var rawItems []VulnerabilityItem
	var mu sync.Mutex
	var wg sync.WaitGroup

	wg.Add(3)

	go func() {
		defer wg.Done()
		cisaItems := s.pollCisaFeedRaw()
		mu.Lock()
		rawItems = append(rawItems, cisaItems...)
		mu.Unlock()
	}()

	go func() {
		defer wg.Done()
		redHatItems := s.pollRedHatFeedRaw()
		mu.Lock()
		rawItems = append(rawItems, redHatItems...)
		mu.Unlock()
	}()

	go func() {
		defer wg.Done()
		canonicalItems := s.pollCanonicalFeedRaw()
		mu.Lock()
		rawItems = append(rawItems, canonicalItems...)
		mu.Unlock()
	}()

	wg.Wait()

	if len(rawItems) == 0 {
		s.LogError(errors.New("warning: synchronization pass finished with empty raw datasets across feeds"))
		return
	}

	s.LogInfo(fmt.Sprintf("Raw collection complete. Dispatching concurrent MISP and OTX lookups for %d target CVEs...", len(rawItems)))

	var enrichedItems []VulnerabilityItem
	var enrichWg sync.WaitGroup
	var enrichMu sync.Mutex

	for _, item := range rawItems {
		enrichWg.Add(1)
		go func(vItem VulnerabilityItem) {
			defer enrichWg.Done()

			cveID := vItem.Title
			if strings.Contains(cveID, ":") {
				cveID = strings.TrimSpace(strings.Split(cveID, ":")[0])
			}

			uniqueIOCs := make(map[string]bool)
			var combinedIOCs []string

			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()

			mispPayload, err := s.FetchMispIOCsByCVE(ctx, cveID)
			if err == nil && len(mispPayload) > 0 {
				mispIOCs := ExtractValuesFromMispResponse(mispPayload)
				for _, ioc := range mispIOCs {
					trimmed := strings.TrimSpace(ioc)
					if trimmed != "" && !uniqueIOCs[trimmed] {
						uniqueIOCs[trimmed] = true
						combinedIOCs = append(combinedIOCs, trimmed)
					}
				}
			}

			otxPayload, err := s.FetchPublicOtxIOCsByCVE(ctx, cveID)
			if err == nil && len(otxPayload) > 0 {
				otxIOCs := s.extractValuesFromOtxResponse(otxPayload)
				for _, ioc := range otxIOCs {
					trimmed := strings.TrimSpace(ioc)
					if trimmed != "" && !uniqueIOCs[trimmed] {
						uniqueIOCs[trimmed] = true
						combinedIOCs = append(combinedIOCs, trimmed)
					}
				}
			}

			if len(combinedIOCs) > 0 {
				vItem.IOCs = combinedIOCs
			} else {
				vItem.IOCs = make([]string, 0)
			}

			enrichMu.Lock()
			enrichedItems = append(enrichedItems, vItem)
			enrichMu.Unlock()
		}(item)
	}

	enrichWg.Wait()

	sort.Slice(enrichedItems, func(i, j int) bool {
		return enrichedItems[i].Published.After(enrichedItems[j].Published)
	})

	s.Memory.Lock()
	s.Cache.VulnerabilityFeed = enrichedItems
	s.Memory.Unlock()

	s.LogInfo(fmt.Sprintf("Vulnerability cache successfully rebuilt. Saved %d verified records.", len(enrichedItems)))
}

// FetchPublicOtxIOCsByCVE executes a keyless public lookup to capture open community pulse indicators tied to a CVE
func (s *Server) FetchPublicOtxIOCsByCVE(ctx context.Context, cveID string) ([]byte, error) {
	client := &http.Client{Timeout: 10 * time.Second}

	// OTX exposes a public route map containing indicator groupings tagged directly by CVE strings
	url := fmt.Sprintf("https://otx.alienvault.com/api/v1/pulses/cve/%s", strings.ToUpper(cveID))

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "ThreatCo/2.0 Cyber Threat Telemetry Sync Component")

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("public otx api returned status code: %d", resp.StatusCode)
	}

	return io.ReadAll(resp.Body)
}

// extractValuesFromOtxResponse traverses OTX community response envelopes to harvest indicator values
func (s *Server) extractValuesFromOtxResponse(otxPayload []byte) []string {
	var indicators []string

	// Target struct matching AlienVault's public pulses schema payload array layout
	var schema struct {
		Results []struct {
			Indicators []struct {
				Indicator string `json:"indicator"`
			} `json:"indicators"`
		} `json:"results"`
	}

	if err := json.Unmarshal(otxPayload, &schema); err != nil {
		return indicators
	}

	for _, result := range schema.Results {
		for _, ind := range result.Indicators {
			if ind.Indicator != "" {
				indicators = append(indicators, ind.Indicator)
			}
		}
	}

	return indicators
}

// pollCisaFeedRaw fetches the latest advisories from the CISA KEV catalog without enrichment
func (s *Server) pollCisaFeedRaw() []VulnerabilityItem {
	var items []VulnerabilityItem

	cisaClient := &http.Client{Timeout: 10 * time.Second}
	resp, err := cisaClient.Get("https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json")
	if err != nil {
		s.LogError(fmt.Errorf("cisa intel feed pull failure: %w", err))
		return items
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		s.LogError(fmt.Errorf("cisa intel feed returned non-200 status: %d", resp.StatusCode))
		return items
	}

	var data struct {
		Vulnerabilities []struct {
			CveID             string   `json:"cveID"`
			VulnerabilityName string   `json:"vulnerabilityName"`
			ShortDescription  string   `json:"shortDescription"`
			DateAdded         string   `json:"dateAdded"`
			CWEs              []string `json:"cwes"` // Map array from upstream feed schema layout
		} `json:"vulnerabilities"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		s.LogError(fmt.Errorf("failed to decode CISA json stream: %w", err))
		return items
	}

	maxCount := len(data.Vulnerabilities)
	if maxCount > 25 {
		maxCount = 25
	}

	for i := 0; i < maxCount; i++ {
		v := data.Vulnerabilities[i]
		pubTime, _ := time.Parse("2006-01-02", v.DateAdded)

		// Defensive parsing check for nil arrays
		cweList := v.CWEs
		if cweList == nil {
			cweList = make([]string, 0)
		}

		items = append(items, VulnerabilityItem{
			Title:       fmt.Sprintf("%s: %s", v.CveID, v.VulnerabilityName),
			Description: v.ShortDescription,
			Source:      "CISA",
			URL:         fmt.Sprintf("https://nvd.nist.gov/vuln/detail/%s", v.CveID),
			Published:   pubTime,
			CWEs:        cweList, // Appended collection tracking metrics
		})
	}

	return items
}

// pollCirclFeedRaw fetches the latest advisories from the CIRCL CVE JSON 5.x feed without enrichment
// pollCirclFeedRaw fetches the latest advisories from the CIRCL CVE JSON 5.x feed without enrichment
func (s *Server) pollCirclFeedRaw() []VulnerabilityItem {
	var items []VulnerabilityItem

	client := &http.Client{Timeout: 15 * time.Second}
	circlURL := "https://vulnerability.circl.lu/api/last"

	req, err := http.NewRequest("GET", circlURL, nil)
	if err != nil {
		s.LogError(fmt.Errorf("failed to create circl api request object: %w", err))
		return items
	}

	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "ThreatCo/2.0 Threat Intel Sync Component")

	resp, err := client.Do(req)
	if err != nil {
		s.LogError(fmt.Errorf("circl vulnerability intel feed pull failure: %w", err))
		return items
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		s.LogError(fmt.Errorf("circl vulnerability feed returned non-200 status: %d", resp.StatusCode))
		return items
	}

	var circlData []struct {
		CveMetadata struct {
			CveID         string `json:"cveId"`
			DatePublished string `json:"datePublished"`
			DateUpdated   string `json:"dateUpdated"`
		} `json:"cveMetadata"`
		Containers struct {
			Cna struct {
				Descriptions []struct {
					Lang  string `json:"lang"`
					Value string `json:"value"`
				} `json:"descriptions"`
			} `json:"cna"`
		} `json:"containers"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&circlData); err != nil {
		s.LogError(fmt.Errorf("failed to decode nested circl json telemetry stream: %w", err))
		return items
	}

	maxCount := len(circlData)
	if maxCount > 25 {
		maxCount = 25
	}

	for i := 0; i < maxCount; i++ {
		entry := circlData[i]
		cveID := entry.CveMetadata.CveID
		if cveID == "" {
			continue
		}

		desc := ""
		if len(entry.Containers.Cna.Descriptions) > 0 {
			for _, d := range entry.Containers.Cna.Descriptions {
				if d.Lang == "en" {
					desc = d.Value
					break
				}
			}
			if desc == "" {
				desc = entry.Containers.Cna.Descriptions[0].Value
			}
		}

		if desc == "" {
			desc = "No summary or structural context provided by advisory source."
		}

		var pubTime time.Time
		pubStr := entry.CveMetadata.DatePublished
		if pubStr == "" {
			pubStr = entry.CveMetadata.DateUpdated
		}

		if pubStr != "" {
			var parseErr error
			// Attempt Layout 1: Strict RFC3339
			pubTime, parseErr = time.Parse(time.RFC3339, pubStr)
			if parseErr != nil {
				// Fallback Layout 2: ISO fractional with millisecond precision frequently used by document APIs
				pubTime, parseErr = time.Parse("2006-01-02T15:04:05.000Z", pubStr)
				if parseErr != nil {
					// Fallback Layout 3: Standard space-separated datetime string
					pubTime, parseErr = time.Parse("2006-01-02 15:04:05", pubStr)
					if parseErr != nil {
						s.LogInfo(fmt.Errorf("[CIRCL Sync Warning] Unable to parse timestamp '%s' for %s: %w", pubStr, cveID, parseErr).Error())
					}
				}
			}
		}

		if pubTime.IsZero() {
			pubTime = time.Now()
		}

		items = append(items, VulnerabilityItem{
			Title:       strings.ToUpper(cveID),
			Description: desc,
			Source:      "NIST/CIRCL",
			URL:         fmt.Sprintf("https://nvd.nist.gov/vuln/detail/%s", strings.ToUpper(cveID)),
			Published:   pubTime,
		})
	}

	return items
}

// pollCisaFeed handles fetching and concurrent MISP enrichment for the CISA KEV feed
func (s *Server) pollCisaFeed() []VulnerabilityItem {
	var items []VulnerabilityItem

	cisaClient := &http.Client{Timeout: 10 * time.Second}
	resp, err := cisaClient.Get("https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json")
	if err != nil {
		fmt.Printf("CISA intel feed pull failure: %v\n", err)
		return items
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		fmt.Printf("CISA intel feed returned non-200 status: %d\n", resp.StatusCode)
		return items
	}

	var data struct {
		Vulnerabilities []struct {
			CveID             string `json:"cveID"`
			VulnerabilityName string `json:"vulnerabilityName"`
			ShortDescription  string `json:"shortDescription"`
			DateAdded         string `json:"dateAdded"`
		} `json:"vulnerabilities"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		fmt.Printf("Failed to decode CISA json stream: %v\n", err)
		return items
	}

	maxCount := len(data.Vulnerabilities)
	if maxCount > 25 {
		maxCount = 25
	}

	var wg sync.WaitGroup
	var mu sync.Mutex

	for i := 0; i < maxCount; i++ {
		wg.Add(1)
		go func(v struct {
			CveID             string `json:"cveID"`
			VulnerabilityName string `json:"vulnerabilityName"`
			ShortDescription  string `json:"shortDescription"`
			DateAdded         string `json:"dateAdded"`
		}) {
			defer wg.Done()

			pubTime, _ := time.Parse("2006-01-02", v.DateAdded)
			fmt.Printf("Processing CISA vulnerability %s, querying matching MISP attributes...\n", v.CveID)

			var extractedIOCs []string
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			mispPayload, err := s.FetchMispIOCsByCVE(ctx, v.CveID)
			cancel()

			if err != nil {
				fmt.Printf("Skipping MISP intelligence enrichment for %s: %v\n", v.CveID, err)
				extractedIOCs = make([]string, 0)
			} else {
				extractedIOCs = ExtractValuesFromMispResponse(mispPayload)
				fmt.Printf("Successfully enriched %s with %d MISP technical indicators\n", v.CveID, len(extractedIOCs))
			}

			item := VulnerabilityItem{
				Title:       fmt.Sprintf("%s: %s", v.CveID, v.VulnerabilityName),
				Description: v.ShortDescription,
				Source:      "CISA",
				URL:         fmt.Sprintf("https://nvd.nist.gov/vuln/detail/%s", v.CveID),
				Published:   pubTime,
				IOCs:        extractedIOCs,
			}

			mu.Lock()
			items = append(items, item)
			mu.Unlock()
		}(data.Vulnerabilities[i])
	}

	wg.Wait()
	return items
}

// pollNistFeed handles fetching open-source alerts using CIRCL's open vulnerability database,
// parsing the dense nested CVE JSON 5.5 metadata tree structure safely into VulnerabilityItems.
func (s *Server) pollNistFeed() []VulnerabilityItem {
	var items []VulnerabilityItem

	client := &http.Client{Timeout: 15 * time.Second}
	circlURL := "https://vulnerability.circl.lu/api/last"

	req, err := http.NewRequest("GET", circlURL, nil)
	if err != nil {
		s.LogError(fmt.Errorf("failed to create circl api request object: %w", err))
		return items
	}

	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "ThreatCo/2.0 Threat Intel Sync Component")

	resp, err := client.Do(req)
	if err != nil {
		s.LogError(fmt.Errorf("circl vulnerability intel feed pull failure: %w", err))
		return items
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		s.LogError(fmt.Errorf("circl vulnerability feed returned non-200 status: %d", resp.StatusCode))
		return items
	}

	// Unmarshal into an anonymous structural layout reflecting the official CVE v5 schema observed in ko.json
	var circlData []struct {
		CveMetadata struct {
			CveID         string `json:"cveId"`
			DatePublished string `json:"datePublished"`
			DateUpdated   string `json:"dateUpdated"`
		} `json:"cveMetadata"`
		Containers struct {
			Cna struct {
				Descriptions []struct {
					Lang  string `json:"lang"`
					Value string `json:"value"`
				} `json:"descriptions"`
			} `json:"cna"`
		} `json:"containers"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&circlData); err != nil {
		s.LogError(fmt.Errorf("failed to decode nested circl json telemetry stream: %w", err))
		return items
	}

	maxCount := len(circlData)
	if maxCount > 25 {
		maxCount = 25
	}

	for i := 0; i < maxCount; i++ {
		entry := circlData[i]

		// Unpack vulnerability identification token string
		cveID := entry.CveMetadata.CveID
		if cveID == "" {
			continue
		}

		// Traverse down into the CNA container layer to pull out the English value description text block
		desc := ""
		if len(entry.Containers.Cna.Descriptions) > 0 {
			// Prefer English or default to first index availability safely
			for _, d := range entry.Containers.Cna.Descriptions {
				if d.Lang == "en" {
					desc = d.Value
					break
				}
			}
			if desc == "" {
				desc = entry.Containers.Cna.Descriptions[0].Value
			}
		}

		if desc == "" {
			desc = "No summary or structural context provided by advisory source."
		}

		// Resolve time values safely
		var pubTime time.Time
		pubStr := entry.CveMetadata.DatePublished
		if pubStr == "" {
			pubStr = entry.CveMetadata.DateUpdated
		}

		if pubStr != "" {
			// Handle standard NVD ISO fractional format strings
			pubTime, _ = time.Parse(time.RFC3339, pubStr)
		}
		if pubTime.IsZero() {
			pubTime = time.Now()
		}

		vItem := VulnerabilityItem{
			Title:       strings.ToUpper(cveID),
			Description: desc,
			Source:      "NIST/CIRCL",
			URL:         fmt.Sprintf("https://nvd.nist.gov/vuln/detail/%s", strings.ToUpper(cveID)),
			Published:   pubTime,
			IOCs:        make([]string, 0),
		}

		items = append(items, vItem)
	}

	return items
}

// pollRedHatFeedRaw fetches the latest advisories from the open Red Hat Security Data API
// pollRedHatFeedRaw fetches the latest advisories from the open Red Hat Security Data API
func (s *Server) pollRedHatFeedRaw() []VulnerabilityItem {
	var items []VulnerabilityItem

	client := &http.Client{Timeout: 15 * time.Second}
	// Removed the multi-severity query parameter to completely avoid 400 Bad Request statuses.
	// We handle pagination cleanly using Red Hat's native flat listing syntax.
	rhURL := "https://access.redhat.com/hydra/rest/securitydata/cve.json?per_page=25"

	req, err := http.NewRequest("GET", rhURL, nil)
	if err != nil {
		s.LogError(fmt.Errorf("failed to create redhat api request object: %w", err))
		return items
	}

	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "ThreatCo/2.0 Threat Intel Sync Component")

	resp, err := client.Do(req)
	if err != nil {
		s.LogError(fmt.Errorf("redhat vulnerability intel feed pull failure: %w", err))
		return items
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		s.LogError(fmt.Errorf("redhat vulnerability feed returned non-200 status: %d", resp.StatusCode))
		return items
	}

	// Schema strictly maps to Red Hat's official lowercased JSON property responses
	var rhData []struct {
		CVE           string `json:"CVE"`
		Severity      string `json:"severity"` // Values arrive as: "low", "moderate", "important", "critical"
		PublicDate    string `json:"public_date"`
		Bugzilla      string `json:"bugzilla"`
		BugzillaState string `json:"bugzilla_description"`
		ResourceURL   string `json:"resource_url"`
		Cvss3Score    string `json:"cvss3_score"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&rhData); err != nil {
		s.LogError(fmt.Errorf("failed to decode flat redhat json data stream: %w", err))
		return items
	}

	for _, entry := range rhData {
		if entry.CVE == "" {
			continue
		}

		// Optional Local Logic Filter:
		// If you only want high-tier items on your frontend dashboard, you can uncomment this:
		if entry.Severity != "critical" && entry.Severity != "important" {
			continue
		}

		// Parse the date string safely (Red Hat strictly utilizes RFC3339 layout formatting)
		var pubTime time.Time
		if entry.PublicDate != "" {
			pubTime, _ = time.Parse(time.RFC3339, entry.PublicDate)
		}
		if pubTime.IsZero() {
			pubTime = time.Now()
		}

		// Construct a uniform description block with explicit uppercase transformation for visual neatness
		severityDisplay := strings.ToUpper(entry.Severity)
		description := fmt.Sprintf("Severity: %s | CVSS3: %s | Core Advisory: %s",
			severityDisplay,
			entry.Cvss3Score,
			entry.BugzillaState,
		)
		if entry.BugzillaState == "" {
			description = fmt.Sprintf("Red Hat validated vulnerability tracked under Bugzilla ID: %s. Severity classification: %s.", entry.Bugzilla, severityDisplay)
		}

		items = append(items, VulnerabilityItem{
			Title:       strings.ToUpper(entry.CVE),
			Description: description,
			Source:      "Red Hat",
			URL:         fmt.Sprintf("https://access.redhat.com/security/cve/%s", strings.ToUpper(entry.CVE)),
			Published:   pubTime,
			IOCs:        make([]string, 0),
		})
	}

	return items
}

func (s *Server) pollCanonicalFeedRaw() []VulnerabilityItem {
	s.LogInfo("[Intel Engine] Gathering security notices from Canonical...")
	var items []VulnerabilityItem

	client := &http.Client{Timeout: 15 * time.Second}
	req, err := http.NewRequest("GET", "https://ubuntu.com/security/notices.json", nil)
	if err != nil {
		s.LogError(fmt.Errorf("failed to create canonical request: %w", err))
		return items
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "ThreatCo/2.0 Threat Intel Sync Component")

	resp, err := client.Do(req)
	if err != nil {
		s.LogError(fmt.Errorf("canonical feed pull failure: %w", err))
		return items
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		s.LogError(fmt.Errorf("canonical feed returned status code: %d", resp.StatusCode))
		return items
	}

	// Correctly mapping the nested object array layout found in out.json
	var data struct {
		Notices []struct {
			ID          string `json:"id"`
			Published   string `json:"published"`
			Summary     string `json:"summary"`
			Description string `json:"description"`
			CVEs        []struct {
				ID string `json:"id"`
			} `json:"cves"`
		} `json:"notices"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		s.LogError(fmt.Errorf("failed to decode canonical json payload: %w", err))
		return items
	}

	maxCount := len(data.Notices)
	if maxCount > 25 {
		maxCount = 25
	}

	for i := 0; i < maxCount; i++ {
		n := data.Notices[i]

		// Safe extraction from the inner CVE object layer
		targetCVE := n.ID
		if len(n.CVEs) > 0 && n.CVEs[0].ID != "" {
			targetCVE = n.CVEs[0].ID
		}

		// Robust time parsing fallback logic for strict stability
		var pubTime time.Time
		if n.Published != "" {
			var parseErr error
			// 1. Try high-precision fractional layout matching out.json
			pubTime, parseErr = time.Parse("2006-01-02T15:04:05.999999", n.Published)
			if parseErr != nil {
				// 2. Fallback to standard RFC3339
				pubTime, parseErr = time.Parse(time.RFC3339, n.Published)
				if parseErr != nil {
					pubTime = time.Now()
				}
			}
		} else {
			pubTime = time.Now()
		}

		items = append(items, VulnerabilityItem{
			Title:       strings.ToUpper(targetCVE),
			Description: fmt.Sprintf("%s: %s", n.Summary, n.Description),
			Source:      "Canonical",
			URL:         fmt.Sprintf("https://ubuntu.com/security/notices/%s", n.ID),
			Published:   pubTime,
			IOCs:        make([]string, 0),
		})
	}

	return items
}
