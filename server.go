package main

import (
	"flag"
	"log"
	"net/http"
	"sync"
	"time"
)

var (
	mispUrl = flag.String("misp-url", "https://misp:443", "MISP URL")
	mispKey = flag.String("misp-key", "gGY5eIkAUOk917UHpU8XuaLbHhpJEkjH2TicUyoB", "MISP API key")
)

type Server struct {
	RequestCh chan *http.Request   `json:"-"`
	Gateway   *http.ServeMux       `json:"-"`
	Log       *log.Logger          `json:"-"`
	Memory    *sync.RWMutex        `json:"-"`
	Targets   map[string]*Endpoint `json:"targets"`
	ID        string               `json:"id"`
	Details   Details              `json:"details"`
}

type Details struct {
	Address   string             `json:"address"`
	StartTime time.Time          `json:"start_time"`
	Stats     map[string]float64 `json:"stats"`
}

func NewServer(id string, address string) *Server {
	reqch := make(chan *http.Request, 100)
	targets := make(map[string]*Endpoint)
	memory := &sync.RWMutex{}
	logger := log.New(log.Writer(), log.Prefix(), log.Flags())
	gateway := http.NewServeMux()
	svr := &Server{
		RequestCh: reqch,
		Gateway:   gateway,
		Log:       logger,
		Memory:    memory,
		Targets:   targets,
		ID:        id,
		Details: Details{
			Address:   address,
			StartTime: time.Now(),
			Stats:     make(map[string]float64),
		},
	}
	svr.Gateway.HandleFunc("/pipe", svr.ProxyHandler)
	return svr
}
