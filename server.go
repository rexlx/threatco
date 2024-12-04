package main

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/alexedwards/scs/v2"
	"github.com/google/uuid"
	"go.etcd.io/bbolt"
)

var (
	firstUserMode = flag.Bool("firstuse", false, "First user mode")
	fqdn          = flag.String("fqdn", "http://localhost", "Fully qualified domain name")
	mispUrl       = flag.String("misp-url", "https://192.168.86.91:443", "MISP URL")
	vtKey         = flag.String("vt-key", "", "VirusTotal API key")
	mispKey       = flag.String("misp-key", "", "MISP API key")
	dbLocation    = flag.String("db", "insights.db", "Database location")
	httpsPort     = flag.String("https-port", ":8443", "HTTPS port")
	httpPort      = flag.String("http-port", ":8080", "HTTP port")
	httpToo       = flag.Bool("http", false, "Enable HTTP")
	tlsCert       = flag.String("tls-cert", "cert.pem", "TLS certificate")
	tlsKey        = flag.String("tls-key", "key.pem", "TLS key")
	certAuth      = flag.String("cert-auth", "certauth.pem", "Certificate authority")
	configPath    = flag.String("config", "data/config.json", "Configuration file")
	// userKey    = flag.String("user-key", "N0jwxsJjJ9KU0lyN74eFohM46yvIh5mqIAvqcq/c5Xw=", "User API key")
)

type Server struct {
	Session *scs.SessionManager  `json:"-"`
	RespCh  chan ResponseItem    `json:"-"`
	StopCh  chan bool            `json:"-"`
	Cache   *Cache               `json:"-"`
	DB      *bbolt.DB            `json:"-"`
	Gateway *http.ServeMux       `json:"-"`
	Log     *log.Logger          `json:"-"`
	Memory  *sync.RWMutex        `json:"-"`
	Targets map[string]*Endpoint `json:"targets"`
	ID      string               `json:"id"`
	Details Details              `json:"details"`
}

type Details struct {
	FirstUserMode     bool               `json:"first_user_mode"`
	FQDN              string             `json:"fqdn"`
	SupportedServices []ServiceType      `json:"supported_services"`
	Address           string             `json:"address"`
	StartTime         time.Time          `json:"start_time"`
	Stats             map[string]float64 `json:"stats"`
}

type Cache struct {
	Charts         []byte                  `json:"charts"`
	Coordinates    map[string][]float64    `json:"coordinates"`
	ResponseExpiry time.Duration           `json:"response_expiry"`
	Services       []ServiceType           `json:"services"`
	StatsHistory   []StatItem              `json:"stats_history"`
	Responses      map[string]ResponseItem `json:"responses"`
}
type StatItem struct {
	Time int64              `json:"time"`
	Data map[string]float64 `json:"data"`
}

type ResponseItem struct {
	ID   string    `json:"id"`
	Time time.Time `json:"time"`
	Data []byte    `json:"data"`
}

func NewServer(id string, address string, dbLocation string) *Server {
	db, err := bbolt.Open(dbLocation, 0600, nil)
	if err != nil {
		log.Fatalf("could not open database: %v", err)
	}
	targets := make(map[string]*Endpoint)
	memory := &sync.RWMutex{}
	logger := log.New(log.Writer(), log.Prefix(), log.Flags())
	gateway := http.NewServeMux()
	cache := &Cache{
		Coordinates:  make(map[string][]float64),
		StatsHistory: make([]StatItem, 0),
		Responses:    make(map[string]ResponseItem),
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
	svr := &Server{
		StopCh:  stopCh,
		Session: sessionMgr,
		RespCh:  resch,
		Cache:   cache,
		DB:      db,
		Gateway: gateway,
		Log:     logger,
		Memory:  memory,
		Targets: targets,
		ID:      id,
		Details: Details{
			FQDN:              *fqdn,
			SupportedServices: SupportedServices,
			Address:           address,
			StartTime:         time.Now(),
			Stats:             make(map[string]float64),
		},
	}
	// svr.Gateway.HandleFunc("/pipe", svr.ProxyHandler
	return svr
}

func (s *Server) addStat(key string, value float64) {
	s.Memory.Lock()
	defer s.Memory.Unlock()
	s.Details.Stats[key] += value
}

func (s *Server) updateCache() {
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
	// set the size limit of the cache here by removing the oldest item if
	// the length is greater than whatever you set
	s.Cache.StatsHistory = append(s.Cache.StatsHistory, stat)
}

func (s *Server) ProcessTransientResponses() {
	ticker := time.NewTicker(1 * time.Hour)
	for {
		select {
		case resp := <-s.RespCh:
			s.Memory.Lock()
			s.Cache.Responses[resp.ID] = resp
			s.Memory.Unlock()
		case <-ticker.C:
			s.Log.Println("Processing transient responses: removing old entries")
			s.Memory.Lock()
			for k, v := range s.Cache.Responses {
				if time.Since(v.Time) > s.Cache.ResponseExpiry {
					delete(s.Cache.Responses, k)
				}
			}
			s.Memory.Unlock()
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

func (s *Server) AddResponse(uid string, data []byte) {
	// uid := uuid.New().String()
	resp := ResponseItem{
		ID:   uid,
		Time: time.Now(),
		Data: data,
	}
	s.RespCh <- resp
}

func (s *Server) InitializeFromConfig(cfg *Configuration, fromFile bool) {
	if fromFile {
		err := cfg.PopulateFromJSONFile(*configPath)
		if err != nil {
			s.Log.Fatalf("could not populate from file: %v", err)
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
			thisEndpoint := NewEndpoint(svc.URL, thisAuthType, svc.Insecure, s.RespCh)
			thisEndpoint.MaxRequests = svc.MaxRequests
			thisEndpoint.RefillRate = time.Duration(svc.RefillRate) * time.Second
			s.Memory.Lock()
			s.Targets[svc.Kind] = thisEndpoint
			s.Memory.Unlock()
		case "token":
			thisAuthType := &KeyAuth{Token: svc.Key}
			thisEndpoint := NewEndpoint(svc.URL, thisAuthType, svc.Insecure, s.RespCh)
			thisEndpoint.MaxRequests = svc.MaxRequests
			thisEndpoint.RefillRate = time.Duration(svc.RefillRate) * time.Second
			s.Memory.Lock()
			s.Targets[svc.Kind] = thisEndpoint
			s.Memory.Unlock()
		case "basic":
			thisAuthType := &BasicAuth{Username: svc.Key}
			thisEndpoint := NewEndpoint(svc.URL, thisAuthType, svc.Insecure, s.RespCh)
			thisEndpoint.MaxRequests = svc.MaxRequests
			thisEndpoint.RefillRate = time.Duration(svc.RefillRate) * time.Second
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
			thisEndpoint := NewEndpoint(svc.URL, thisAuthType, svc.Insecure, s.RespCh)
			thisEndpoint.MaxRequests = svc.MaxRequests
			thisEndpoint.RefillRate = time.Duration(svc.RefillRate) * time.Second
			s.Memory.Lock()
			s.Targets[svc.Kind] = thisEndpoint
			s.Memory.Unlock()
		default:
			s.Log.Fatalf("unsupported auth type: %s", svc.AuthType)

		}
	}
	s.Details.SupportedServices = cfg.Services
	s.Details.FQDN = cfg.FQDN
	s.Details.Address = fmt.Sprintf("%s:%s", cfg.BindAddress, cfg.HTTPPort)
	s.Cache.ResponseExpiry = time.Duration(cfg.ResponseCacheExpiry) * time.Second
	s.ID = cfg.ServerID
	s.Details.FirstUserMode = cfg.FirstUserMode
	s.Session.Lifetime = time.Duration(cfg.SessionTokenTTL) * time.Hour
	for _, service := range s.Targets {
		thisAuth := service.Auth
		go thisAuth.GetAndStoreToken(s.StopCh)
		// s.Log.Printf("service %s: +%v\n", serviceName, service)
	}
	s.Gateway.HandleFunc("/stats", s.GetStatHistoryHandler)
	s.Gateway.HandleFunc("/charts", s.ChartViewHandler)
	// s.Gateway.Handle("/charts", http.HandlerFunc(s.ValidateToken(s.ChartViewHandler)))
	s.Gateway.Handle("/pipe", http.HandlerFunc(s.ValidateToken(s.ProxyHandler)))
	s.Gateway.Handle("/user", http.HandlerFunc(s.ValidateToken(s.GetUserHandler)))
	s.Gateway.Handle("/updateuser", http.HandlerFunc(s.ValidateSessionToken(s.UpdateUserHandler)))
	s.Gateway.HandleFunc("/add", http.HandlerFunc(s.ValidateToken(s.AddAttributeHandler)))
	s.Gateway.HandleFunc("/addservice", http.HandlerFunc(s.ValidateToken(s.AddServiceHandler)))
	s.Gateway.Handle("/raw", http.HandlerFunc(s.ValidateToken(s.RawResponseHandler)))
	s.Gateway.HandleFunc("/createuser", http.HandlerFunc(s.ValidateSessionToken(s.CreateUserViewHandler)))
	s.Gateway.Handle("/events/", http.HandlerFunc(s.ValidateSessionToken(s.EventHandler)))
	s.Gateway.HandleFunc("/login", s.LoginHandler)
	s.Gateway.HandleFunc("/splash", s.LoginViewHandler)
	s.Gateway.HandleFunc("/services", http.HandlerFunc(s.ValidateSessionToken(s.ViewServicesHandler)))
	s.Gateway.HandleFunc("/getservices", http.HandlerFunc(s.ValidateSessionToken(s.GetServicesHandler)))
	s.Gateway.HandleFunc("/add-service", http.HandlerFunc(s.ValidateSessionToken(s.AddServicesHandler)))
	s.Gateway.Handle("/static/", http.StripPrefix("/static/", s.FileServer()))
	if s.Details.FirstUserMode {
		s.Gateway.HandleFunc("/adduser", s.AddUserHandler)
	} else {
		s.Gateway.Handle("/adduser", http.HandlerFunc(s.ValidateSessionToken(s.AddUserHandler)))
	}

	s.Log.Printf("initialized from config: %v", cfg)
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
	// s.Details.Stats["poll_time"] = float64(time.Now().Unix())
	// s.Details.Stats["poll_interval"] = float64(t.Seconds())
	// s.Details.Stats["last_gc"] = float64(m.LastGC) / 1000000
	s.Details.Stats["pause_total_ns"] = float64(m.PauseTotalNs) / 1000000
	for i, stat := range s.Details.Stats {
		_, ok := s.Cache.Coordinates[i]
		if !ok {
			s.Cache.Coordinates[i] = make([]float64, 0)
		}
		if len(s.Cache.Coordinates[i]) > 100 {
			s.Cache.Coordinates[i] = s.Cache.Coordinates[i][1:]
		}
		s.Cache.Coordinates[i] = append(s.Cache.Coordinates[i], stat)
	}

	var buf bytes.Buffer
	for k, v := range s.Cache.Coordinates {
		chart := createLineChart(k, v)
		err := chart.Render(&buf)
		if err != nil {
			s.Log.Printf("could not render chart: %v", err)
			continue
		}
	}
	s.Cache.Charts = buf.Bytes()
}
