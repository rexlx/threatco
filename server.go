package main

import (
	"flag"
	"log"
	"net/http"
	"sync"
	"time"

	"go.etcd.io/bbolt"
)

var (
	mispUrl    = flag.String("misp-url", "https://192.168.86.91:443", "MISP URL")
	vtKey      = flag.String("vt-key", "", "VirusTotal API key")
	mispKey    = flag.String("misp-key", "", "MISP API key")
	dbLocation = flag.String("db", "insights.db", "Database location")
	// userKey    = flag.String("user-key", "N0jwxsJjJ9KU0lyN74eFohM46yvIh5mqIAvqcq/c5Xw=", "User API key")
)

type Server struct {
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
	svr := &Server{
		RespCh:  resch,
		Cache:   cache,
		DB:      db,
		Gateway: gateway,
		Log:     logger,
		Memory:  memory,
		Targets: targets,
		ID:      id,
		Details: Details{
			SupportedServices: []ServiceType{
				{
					Kind: "misp",
					Type: []string{"md5", "sha1", "sha256", "sha512", "ipv4", "ipv6", "email", "url", "domain", "filepath", "filename"},
				},
			},
			Address:   address,
			StartTime: time.Now(),
			Stats:     make(map[string]float64),
		},
	}
	// svr.Gateway.HandleFunc("/pipe", svr.ProxyHandler)
	svr.Gateway.HandleFunc("/stats", svr.GetStatHistoryHandler)
	svr.Gateway.Handle("/pipe", http.HandlerFunc(svr.ValidateToken(svr.ProxyHandler)))
	svr.Gateway.HandleFunc("/adduser", svr.AddUserHandler)
	svr.Gateway.HandleFunc("/add", svr.AddAttributeHandler)
	svr.Gateway.Handle("/raw", http.HandlerFunc(svr.ValidateToken(svr.RawResponseHandler)))
	svr.Gateway.Handle("/events/", http.HandlerFunc(svr.EventHandler))
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

func (s *Server) AddResponse(uid string, data []byte) {
	// uid := uuid.New().String()
	resp := ResponseItem{
		ID:   uid,
		Time: time.Now(),
		Data: data,
	}
	s.RespCh <- resp
}
