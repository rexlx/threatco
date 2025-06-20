package main

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
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
	"github.com/rexlx/threatco/views"
	"go.etcd.io/bbolt"
)

var (
	deleteConfig  = flag.Bool("delete", false, "Delete configuration file")
	fqdn          = flag.String("fqdn", "http://localhost", "Fully qualified domain name")
	dbLocation    = flag.String("db", "", "Database location")
	dbMode        = flag.String("dbmode", "postgres", "Database mode")
	knowledgeBase = flag.String("kb", "/kb", "Knowledge base path")
	configPath    = flag.String("config", "/config.json", "Configuration file")
	staticPath    = flag.String("static", "/static", "Static file path")
	firstUserMode = flag.Bool("firstuse", false, "First user mode")
	useSyslog     = flag.Bool("syslog", false, "Enable syslog")
	syslogHost    = flag.String("syslog-host", "localhost", "Syslog host")
	syslogIndex   = flag.String("syslog-index", "threatco", "Syslog index")
	syslogPort    = flag.String("syslog-port", "514", "Syslog port")
)

type Server struct {
	Session *scs.SessionManager  `json:"-"`
	RespCh  chan ResponseItem    `json:"-"`
	StopCh  chan bool            `json:"-"`
	Cache   *Cache               `json:"-"`
	DB      Database             `json:"-"`
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
	Logs           []LogItem               `json:"logs"`
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

func NewServer(id string, address string, dbType string, dbLocation string, logger *log.Logger) *Server {
	var database Database
	targets := make(map[string]*Endpoint)
	memory := &sync.RWMutex{}
	// logger := log.New(log.Writer(), log.Prefix(), log.Flags())
	gateway := http.NewServeMux()
	cache := &Cache{
		Logs:         make([]LogItem, 0),
		Coordinates:  make(map[string][]float64),
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
	switch dbType {
	case "bbolt":
		db, err := bbolt.Open(dbLocation, 0600, nil)
		if err != nil {
			log.Fatalf("bbolt could not open database: %v", err)
		}
		database = &BboltDB{DB: db}
	case "postgres":
		db, err := NewPostgresDB(dbLocation)
		if err != nil {
			log.Fatalf("postgres could not open database: %v", err)
		}
		database = db
	default:
		log.Fatalf("unsupported database type: %s", dbType)
	}
	svr := &Server{
		StopCh:  stopCh,
		Session: sessionMgr,
		RespCh:  resch,
		Cache:   cache,
		DB:      database,
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
	fmt.Println("Server initialized with ID:", svr.ID, svr.Details.Address)
	return svr
}

func GetDBHost() string {
	host := os.Getenv("DB_HOST")
	if host == "" {
		fmt.Println("DB_HOST not set, using localhost")
		host = "localhost"
	}
	return host
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
	for {
		select {
		case resp := <-s.RespCh:
			s.Memory.Lock()
			// TODO: check if the response already exists in the cache, if so append to the existing entry?
			r, ok := s.Cache.Responses[resp.ID]
			if !ok {
				s.Cache.Responses[resp.ID] = resp
			} else {
				r.Time = resp.Time
				r.Data = append(r.Data, resp.Data...)
				s.Cache.Responses[resp.ID] = r
			}
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

func (s *Server) AddResponse(vendor, uid string, data []byte) {
	// uid := uuid.New().String()
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
		err := cfg.PopulateFromJSONFile(*configPath)
		if err != nil {
			s.Log.Fatalf("could not populate from file: %v", err)
		}
		if *deleteConfig {
			err := DeleteConfigFile(*configPath)
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
			thisEndpoint.MaxRequests = svc.MaxRequests
			thisEndpoint.RefillRate = time.Duration(svc.RefillRate) * time.Second
			thisEndpoint.UploadService = svc.UploadService
			s.Memory.Lock()
			s.Targets[svc.Kind] = thisEndpoint
			s.Memory.Unlock()
		case "token":
			thisAuthType := &KeyAuth{Token: svc.Key}
			thisEndpoint := NewEndpoint(svc.URL, thisAuthType, svc.Insecure, s.RespCh, svc.Kind)
			thisEndpoint.MaxRequests = svc.MaxRequests
			thisEndpoint.RefillRate = time.Duration(svc.RefillRate) * time.Second
			thisEndpoint.UploadService = svc.UploadService
			s.Memory.Lock()
			s.Targets[svc.Kind] = thisEndpoint
			s.Memory.Unlock()
		case "basic":
			thisAuthType := &BasicAuth{Username: svc.Secret, Password: svc.Key}
			thisEndpoint := NewEndpoint(svc.URL, thisAuthType, svc.Insecure, s.RespCh, svc.Kind)
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
			thisEndpoint.MaxRequests = svc.MaxRequests
			thisEndpoint.RefillRate = time.Duration(svc.RefillRate) * time.Second
			thisEndpoint.UploadService = svc.UploadService
			s.Memory.Lock()
			s.Targets[svc.Kind] = thisEndpoint
			s.Memory.Unlock()
		case "vmray":
			thisAuthType := &VmRayAuth{Token: svc.Key}
			thisEndpoint := NewEndpoint(svc.URL, thisAuthType, svc.Insecure, s.RespCh, svc.Kind)
			thisEndpoint.MaxRequests = svc.MaxRequests
			thisEndpoint.RefillRate = time.Duration(svc.RefillRate) * time.Second
			thisEndpoint.UploadService = svc.UploadService
			s.Memory.Lock()
			s.Targets[svc.Kind] = thisEndpoint
			s.Memory.Unlock()
		default:
			s.Log.Fatalf("unsupported auth type: %s", svc.AuthType)

		}
	}
	if *firstUserMode {
		s.Details.FirstUserMode = true
	}
	s.Details.SupportedServices = cfg.Services
	s.Details.FQDN = cfg.FQDN
	s.Details.Address = fmt.Sprintf("%s:%s", cfg.BindAddress, cfg.HTTPPort)
	fmt.Println("Server address:", s.Details.Address, cfg.BindAddress, cfg.HTTPPort)
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
	s.Gateway.Handle("/upload", http.HandlerFunc(s.ValidateToken(s.UploadFileHandler)))
	// s.Gateway.Handle("/upload", http.HandlerFunc(s.ValidateToken(s.UploadFileHandler)))
	s.Gateway.Handle("/users", http.HandlerFunc(s.ValidateSessionToken(s.AllUsersViewHandler)))
	s.Gateway.Handle("/updateuser", http.HandlerFunc(s.ValidateSessionToken(s.UpdateUserHandler)))
	s.Gateway.Handle("/deleteuser", http.HandlerFunc(s.ValidateSessionToken(s.DeleteUserHandler)))
	s.Gateway.HandleFunc("/add", http.HandlerFunc(s.ValidateToken(s.AddAttributeHandler)))
	s.Gateway.HandleFunc("/addservice", http.HandlerFunc(s.ValidateToken(s.AddServiceHandler)))
	s.Gateway.Handle("/raw", http.HandlerFunc(s.ValidateToken(s.RawResponseHandler)))
	s.Gateway.HandleFunc("/create-user", http.HandlerFunc(s.ValidateSessionToken(s.CreateUserViewHandler)))
	s.Gateway.Handle("/events/", http.HandlerFunc(s.ValidateSessionToken(s.EventHandler)))
	s.Gateway.HandleFunc("/login", s.LoginHandler)
	// s.Gateway.HandleFunc("/splash", s.LoginViewHandler)
	s.Gateway.HandleFunc("/services", http.HandlerFunc(s.ValidateSessionToken(s.ViewServicesHandler)))
	s.Gateway.HandleFunc("/getservices", http.HandlerFunc(s.ValidateSessionToken(s.GetServicesHandler)))
	s.Gateway.HandleFunc("/add-service", http.HandlerFunc(s.ValidateSessionToken(s.AddServicesHandler)))
	s.Gateway.HandleFunc("/assisteddeath", http.HandlerFunc(s.ValidateSessionToken(s.KillServerDeadHandler)))
	s.Gateway.HandleFunc("/logs", http.HandlerFunc(s.ValidateSessionToken(s.GetLogsHandler)))
	s.Gateway.HandleFunc("/getlogs", http.HandlerFunc(s.ValidateSessionToken(s.LogsSSRHandler)))
	s.Gateway.HandleFunc("/view-logs", http.HandlerFunc(s.ValidateSessionToken(s.LogViewHandler)))
	s.Gateway.HandleFunc("/getresponses", http.HandlerFunc(s.ValidateSessionToken(s.GetResponseCacheHandler)))
	s.Gateway.HandleFunc("/responses", http.HandlerFunc(s.ValidateSessionToken(s.ViewResponsesHandler)))
	s.Gateway.HandleFunc("/parse", http.HandlerFunc(s.ValidateSessionToken(s.ParserHandler)))
	s.Gateway.HandleFunc("/logger", http.HandlerFunc(s.ValidateSessionToken(s.LogHandler)))
	// s.FileServer = http.FileServer(http.Dir(*staticPath))
	s.Gateway.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.Dir(*staticPath))))
	s.Gateway.Handle("/kb/", http.StripPrefix("/kb/", http.FileServer(http.Dir(*knowledgeBase))))
	if s.Details.FirstUserMode {
		s.Gateway.HandleFunc("/adduser", s.AddUserHandler)
	} else {
		s.Gateway.Handle("/adduser", http.HandlerFunc(s.ValidateSessionToken(s.AddUserHandler)))
	}
	s.Gateway.Handle("/", http.HandlerFunc(s.LoginViewHandler))
	s.Gateway.HandleFunc("/logout", s.LogoutHandler)

	// s.AddResponse("fake", CreateFakeResponse())
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

// func (s *Server) BroacastToAPIs(fn string, uh UploadHandler) {

// }

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
