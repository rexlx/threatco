package internal

import (
	"bytes"
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
	Logs           []LogItem               `json:"logs"`
	Charts         []byte                  `json:"charts"`
	Coordinates    map[string][]Coord      `json:"coordinates"`
	ResponseExpiry time.Duration           `json:"response_expiry"`
	Services       []ServiceType           `json:"services"`
	StatsHistory   []StatItem              `json:"stats_history"`
	Responses      map[string]ResponseItem `json:"responses"`
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

func NewServer(id string, address string, dbType string, dbLocation string, logger *log.Logger) *Server {
	keyHex := os.Getenv("THREATCO_ENCRYPTION_KEY")
	if keyHex == "" {
		logger.Fatal("THREATCO_ENCRYPTION_KEY environment variable not set")
	}
	keyOldHex := os.Getenv("THREATCO_OLD_ENCRYPTION_KEY")
	var database Database
	targets := make(map[string]*Endpoint)
	operators := make(map[string]ProxyOperator)
	memory := &sync.RWMutex{}
	// logger := log.New(log.Writer(), log.Prefix(), log.Flags())
	gateway := http.NewServeMux()
	cache := &Cache{
		Logs:         make([]LogItem, 0),
		Coordinates:  make(map[string][]Coord),
		StatsHistory: make([]StatItem, 0),
		Responses:    make(map[string]ResponseItem),
		Charts:       []byte(views.NoDataView),
	}
	stopCh := make(chan bool)
	resch := make(chan ResponseItem, 200)
	sessionMgr := scs.New()
	sessionMgr.Lifetime = 24 * time.Hour
	sessionMgr.IdleTimeout = 1 * time.Hour
	sessionMgr.Cookie.Persist = true
	sessionMgr.Cookie.Name = "token"
	sessionMgr.Cookie.SameSite = http.SameSiteLaxMode
	// sessionMgr.Cookie.Secure = true
	sessionMgr.Cookie.HttpOnly = true
	if dbLocation == "" {
		dbLocation = os.Getenv("THREATCO_DB_LOCATION")
	}
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
	if id == "" {
		id = fmt.Sprintf("%v-%v-%v", time.Now().Unix(), Version, "non-prod")
	}
	svr := &Server{
		Hub:            NewHub(),
		ProxyOperators: operators,
		StopCh:         stopCh,
		Session:        sessionMgr,
		RespCh:         resch,
		Cache:          cache,
		DB:             database,
		Gateway:        gateway,
		Log:            logger,
		Memory:         memory,
		Targets:        targets,
		ID:             id,
		Details: Details{
			Key:               &aesGCM,
			FQDN:              *Fqdn,
			SupportedServices: SupportedServices,
			Address:           address,
			StartTime:         time.Now(),
			Stats:             make(map[string]float64),
		},
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
		[]string{"status"}, // Define at least one label
	)

	prometheus.MustRegister(svr.ParserDuration)

	// Register it with the default registry
	prometheus.MustRegister(svr.Gauges)
	// svr.Gateway.HandleFunc("/pipe", svr.ProxyHandler
	fmt.Println("Server initialized with ID:", svr.ID)
	return svr
}

func (s *Server) Encrypt(plaintext string) (string, error) {
	// 1. Get the cipher from your server struct
	aesGCM := *s.Details.Key

	// 2. Create a new, unique nonce
	nonce := make([]byte, aesGCM.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", fmt.Errorf("failed to create nonce: %w", err)
	}

	// 3. Encrypt the data
	ciphertext := aesGCM.Seal(nil, nonce, []byte(plaintext), nil)

	// 4. Return as "nonce:ciphertext"
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
			// start := time.Now()
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
			// Preserve the original timestamp if we are merging into an existing record
			if exists {
				resp.Time = r.Time
			}

			// dur := time.Since(start)
			// ms := float64(dur.Microseconds()) / float64(time.Millisecond)
			// _, ok := s.Cache.Coordinates["response_processing_time_ms"]
			// if !ok {
			// 	s.Cache.Coordinates["response_processing_time_ms"] = make([]Coord, 0)
			// }
			// if len(s.Cache.Coordinates["response_processing_time_ms"]) > 250 {
			// 	s.Cache.Coordinates["response_processing_time_ms"] = s.Cache.Coordinates["response_processing_time_ms"][1:]
			// }
			// s.Cache.Coordinates["response_processing_time_ms"] = append(s.Cache.Coordinates["response_processing_time_ms"], Coord{Value: ms, Time: time.Now().Unix()})
			s.Memory.Lock()
			s.Cache.Responses[resp.ID] = resp

			// Update stats
			s.Details.Stats[resp.Vendor] += float64(len(resp.Data))
			s.Details.Stats["vendor_responses"]++
			s.Memory.Unlock()

			err = s.DB.StoreResponse(false, resp.ID, resp.Data, resp.Vendor)
			if err != nil {
				s.Log.Printf("ERROR: could not store response ID %s: %v", resp.ID, err)
			}
			if resp.Notify {
				s.Hub.SendToUser(s.RespCh, resp.Email, Notification{
					Created: resp.Time,
					Info:    fmt.Sprintf("New response from %s with ID %s", resp.Vendor, resp.ID),
					Error:   false,
				})
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
				if err := s.DB.CleanSearchHistory(60); err != nil { //
					s.Log.Printf("ERROR: search history cleanup failed: %v", err) //
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
		err := cfg.PopulateFromJSONFile(*ConfigPath)
		if err != nil {
			s.Log.Fatalf("could not populate from file: %v", err)
		}
		if *DeleteConfig {
			err := DeleteConfigFile(*ConfigPath)
			if err != nil {
				s.Log.Fatalf("could not delete config file: %v", err)
			}
			s.Log.Println("config file deleted")
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
		default:
			s.Log.Printf("unsupported auth type: %s, defaulting to bearer\n", svc.AuthType)
			thisAuthType := &BearerAuth{Token: svc.Key}
			thisEndpoint := NewEndpoint(svc.URL, thisAuthType, svc.Insecure, s.RespCh, svc.Kind)
			thisEndpoint.RateLimited = svc.RateLimited
			thisEndpoint.MaxRequests = svc.MaxRequests
			thisEndpoint.RefillRate = time.Duration(svc.RefillRate) * time.Second
			thisEndpoint.UploadService = svc.UploadService
			s.Memory.Lock()
			s.Targets[svc.Kind] = thisEndpoint
			s.Memory.Unlock()
			s.Log.Printf("added service %s with bearer auth", svc.Kind)

		}
	}
	if *FirstUserMode {
		s.Details.FirstUserMode = true
	}
	s.Details.SupportedServices = cfg.Services
	s.Details.FQDN = cfg.FQDN
	if len(cfg.Cors) == 0 {
		// Fallback: If no origins defined, default to the FQDN and localhost
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
	// s.ID = cfg.ServerID
	s.Details.FirstUserMode = cfg.FirstUserMode
	s.Details.LlmConf = cfg.LlmConf
	fmt.Println(s.Details.LlmConf)
	s.Session.Lifetime = time.Duration(cfg.SessionTokenTTL) * time.Hour
	for name, service := range s.Targets {
		thisAuth := service.Auth
		go thisAuth.GetAndStoreToken(s.StopCh)
		op, ok := ProxyOperators[name]
		if !ok {
			s.Log.Printf("no proxy operator for service %s, skipping", name)
			continue
		}
		s.ProxyOperators[name] = op
	}
	s.ProxyOperators["internal-case"] = ThreatcoInternalCaseSearchBuilder(s.DB)
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
	s.Gateway.HandleFunc("/deleteresponse", http.HandlerFunc(s.ValidateSessionToken(s.DeleteResponseHandler)))
	s.Gateway.HandleFunc("/exportresponses", http.HandlerFunc(s.ValidateSessionToken(s.ExportResponseCSVHandler)))
	s.Gateway.HandleFunc("/generatekey", http.HandlerFunc(s.ValidateSessionToken(s.GenerateAPIKeyHandler)))
	s.Gateway.HandleFunc("/getlogs", http.HandlerFunc(s.ValidateSessionToken(s.LogsSSRHandler)))
	s.Gateway.HandleFunc("/getresponses", http.HandlerFunc(s.ValidateSessionToken(s.GetResponseCacheHandler2)))
	s.Gateway.HandleFunc("/getservices", http.HandlerFunc(s.ValidateSessionToken(s.GetServicesHandler)))
	s.Gateway.HandleFunc("/getuptime", http.HandlerFunc(s.ValidateSessionToken(s.GetRuntimeHandler)))
	s.Gateway.HandleFunc("/logger", http.HandlerFunc(s.ValidateSessionToken(s.LogHandler)))
	s.Gateway.HandleFunc("/logs", http.HandlerFunc(s.ValidateSessionToken(s.GetLogsHandler)))
	s.Gateway.HandleFunc("/misp-workflow", http.HandlerFunc(s.ValidateSessionToken(s.TriggerMispWorkflowHandler)))
	s.Gateway.HandleFunc("/misp/workflow/batch", http.HandlerFunc(s.ValidateSessionToken(s.TriggerMispBatchWorkflowHandler)))
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
	appDir := http.Dir(*WebApp)
	s.Gateway.Handle("/app/", http.StripPrefix("/app/", s.ProtectedFileServer(appDir)))
	if s.Details.FirstUserMode {
		s.Gateway.HandleFunc("/adduser", s.AddUserHandler)
	} else {
		s.Gateway.Handle("/adduser", http.HandlerFunc(s.ValidateSessionToken(s.AddUserHandler)))
	}
	s.Gateway.Handle("/", http.HandlerFunc(s.LoginViewHandler))
	s.Gateway.HandleFunc("/logout", s.LogoutHandler)
	go s.Hub.Run()
}

// internal/server.go

func (s *Server) AutomatedThreatScan() {
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

		// Threshold for critical threats (4 or higher)
		if tid >= 4 {
			se, err := ExtractSummarizedEvent(r.Data)
			if err != nil {
				s.Log.Printf("AutomatedThreatScan: found tid %d but failed to extract event for %s: %v", tid, r.ID, err)
				continue
			}

			// 1. Search for existing cases containing this specific IOC value.
			// We pass a limit of 0 (or a high number) to ensure we find it even in deep history.
			existingCases, err := s.DB.SearchCases(se.Value, 0)
			alreadyExists := false

			if err == nil {
				for _, ec := range existingCases {
					// 2. Check if the case is still "Open" and actually contains the IOC
					if ec.Status == "Open" {
						for _, ioc := range ec.IOCs {
							if ioc == se.Value {
								alreadyExists = true
								break
							}
						}
					}
					if alreadyExists {
						break
					}
				}
			}

			if !alreadyExists {
				caseName := fmt.Sprintf("Auto-Case: Critical Threat Detected (%s)", se.Value)
				newCase := Case{
					ID:          uuid.New().String(),
					Name:        caseName,
					Description: fmt.Sprintf("Automated case for %v. Vendor: %s. IOC: %s. %s", r.ID, r.Vendor, se.Value, se.Info),
					CreatedBy:   "System Automation",
					CreatedAt:   time.Now(),
					Status:      "Open",
					IOCs:        []string{se.Value},
					Comments:    []Comment{},
					IsAuto:      true,
				}

				if err := s.DB.CreateCase(newCase); err != nil {
					s.Log.Println("Failed to create auto-case:", err)
				} else {
					s.LogInfo(fmt.Sprintf("AutomatedThreatScan: Created Case %s for IOC %s", newCase.ID, se.Value))
				}
			} else {
				s.Log.Printf("AutomatedThreatScan: Open case already exists for IOC %s, skipping creation.", se.Value)
			}
		}
	}
}

// internal/server.go

// CleanupClosedCases finds cases with "Closed" status older than 60 days and deletes them.
func (s *Server) CleanupClosedCases() {
	cutoff := time.Now().AddDate(0, 0, -60)
	limit := 100
	offset := 0

	for {
		// Use existing GetCases method to fetch a batch of cases
		cases, err := s.DB.GetCases(limit, offset, "")
		if err != nil {
			s.Log.Printf("ERROR: Failed to fetch cases for cleanup: %v", err)
			break
		}

		if len(cases) == 0 {
			break
		}

		for _, c := range cases {
			// Filter logic: Status must be "Closed" and older than 60 days
			if c.Status == "Closed" && c.CreatedAt.Before(cutoff) {
				// Use existing DeleteCase method
				if err := s.DB.DeleteCase(c.ID); err != nil {
					s.Log.Printf("ERROR: Failed to delete closed case %s: %v", c.ID, err)
				} else {
					s.LogInfo(fmt.Sprintf("Cleanup: Deleted closed case %s (%s) older than 60 days", c.ID, c.Name))
				}
			}
		}

		// Move to the next batch if necessary
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
	out := `<div class="scrollbar">
            <div class="thumb"></div>
        </div>`
	templ := `<article class="message is-%s">
                <div class="message-header">
                    <p>%s</p>
                </div>
                <div class="message-body">
                    %v
                </div>
              </article>`
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
	out := `<div class="scrollbar">
            <div class="thumb"></div>
        </div>`
	templ := `<article class="panel is-%s">
                <p class="panel-heading">
                    %s
                </p>
                <div class="panel-block">
                    %v
                </div>
              </article>`
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

// func (s *Server) PrepareTable(ctx context.Context, tableName string) error {
// 	// Type assert to PostgresDB to access the pgxpool
// 	pgDB, ok := s.DB.(*PostgresDB)
// 	if !ok {
// 		return fmt.Errorf("PrepareTable is only supported for PostgresDB")
// 	}

// 	// Use CASCADE to remove dependent objects like indexes
// 	query := fmt.Sprintf("DROP TABLE IF EXISTS %s CASCADE", tableName)
// 	_, err := pgDB.Pool.Exec(ctx, query)
// 	if err != nil {
// 		return fmt.Errorf("failed to drop table %s: %w", tableName, err)
// 	}

// 	s.LogInfo(fmt.Sprintf("Wiped table '%s' per -prepare-table flag", tableName))
// 	return nil
// }
