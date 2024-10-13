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
	mispUrl    = flag.String("misp-url", "https://misp:443", "MISP URL")
	mispKey    = flag.String("misp-key", "", "MISP API key")
	dbLocation = flag.String("db", "insights.db", "Database location")
	// userKey    = flag.String("user-key", "N0jwxsJjJ9KU0lyN74eFohM46yvIh5mqIAvqcq/c5Xw=", "User API key")
)

type Server struct {
	DB      *bbolt.DB            `json:"-"`
	Gateway *http.ServeMux       `json:"-"`
	Log     *log.Logger          `json:"-"`
	Memory  *sync.RWMutex        `json:"-"`
	Targets map[string]*Endpoint `json:"targets"`
	ID      string               `json:"id"`
	Details Details              `json:"details"`
}

type Details struct {
	Address   string             `json:"address"`
	StartTime time.Time          `json:"start_time"`
	Stats     map[string]float64 `json:"stats"`
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
	svr := &Server{
		DB:      db,
		Gateway: gateway,
		Log:     logger,
		Memory:  memory,
		Targets: targets,
		ID:      id,
		Details: Details{
			Address:   address,
			StartTime: time.Now(),
			Stats:     make(map[string]float64),
		},
	}
	// svr.Gateway.HandleFunc("/pipe", svr.ProxyHandler)
	svr.Gateway.Handle("/pipe", http.HandlerFunc(svr.ValidateToken(svr.ProxyHandler)))
	svr.Gateway.HandleFunc("/adduser", svr.AddUserHandler)
	svr.Gateway.HandleFunc("/add", svr.AddAttributeHandler)
	return svr
}

func (s *Server) addStat(key string, value float64) {
	s.Memory.Lock()
	defer s.Memory.Unlock()
	s.Details.Stats[key] += value
}
