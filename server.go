package main

import (
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"flag"
	"io"
	"log"
	"net/http"
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
	// userKey    = flag.String("user-key", "N0jwxsJjJ9KU0lyN74eFohM46yvIh5mqIAvqcq/c5Xw=", "User API key")
)

type Server struct {
	Session *scs.SessionManager  `json:"-"`
	RespCh  chan ResponseItem    `json:"-"`
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
	FQDN              string             `json:"fqdn"`
	SupportedServices []ServiceType      `json:"supported_services"`
	Address           string             `json:"address"`
	StartTime         time.Time          `json:"start_time"`
	Stats             map[string]float64 `json:"stats"`
}

type Cache struct {
	Services     []ServiceType           `json:"services"`
	StatsHistory []StatItem              `json:"stats_history"`
	Responses    map[string]ResponseItem `json:"responses"`
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
		StatsHistory: make([]StatItem, 0),
		Responses:    make(map[string]ResponseItem),
	}
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
	// svr.Gateway.HandleFunc("/pipe", svr.ProxyHandler)
	svr.Gateway.HandleFunc("/stats", svr.GetStatHistoryHandler)
	svr.Gateway.Handle("/pipe", http.HandlerFunc(svr.ValidateToken(svr.ProxyHandler)))
	svr.Gateway.Handle("/user", http.HandlerFunc(svr.ValidateToken(svr.GetUserHandler)))
	svr.Gateway.Handle("/updateuser", http.HandlerFunc(svr.ValidateSessionToken(svr.UpdateUserHandler)))
	svr.Gateway.HandleFunc("/add", svr.AddAttributeHandler)
	svr.Gateway.HandleFunc("/addservice", svr.AddServiceHandler)
	svr.Gateway.Handle("/raw", http.HandlerFunc(svr.ValidateToken(svr.RawResponseHandler)))
	svr.Gateway.HandleFunc("/createuser", svr.CreateUserViewHandler)
	svr.Gateway.Handle("/events/", http.HandlerFunc(svr.EventHandler))
	svr.Gateway.HandleFunc("/login", svr.LoginHandler)
	svr.Gateway.HandleFunc("/splash", svr.LoginViewHandler)
	svr.Gateway.HandleFunc("/services", http.HandlerFunc(svr.ValidateSessionToken(svr.ViewServicesHandler)))
	svr.Gateway.HandleFunc("/getservices", http.HandlerFunc(svr.ValidateSessionToken(svr.GetServicesHandler)))
	svr.Gateway.HandleFunc("/add-service", http.HandlerFunc(svr.ValidateSessionToken(svr.AddServicesHandler)))
	svr.Gateway.Handle("/static/", http.StripPrefix("/static/", svr.FileServer()))
	if *firstUserMode {
		svr.Gateway.HandleFunc("/adduser", svr.AddUserHandler)
	} else {
		svr.Gateway.Handle("/adduser", http.HandlerFunc(svr.ValidateSessionToken(svr.AddUserHandler)))
	}
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
			s.Memory.Lock()
			for k, v := range s.Cache.Responses {
				if time.Since(v.Time) > 24*time.Hour {
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
