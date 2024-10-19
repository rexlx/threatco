package main

import (
	"bytes"
	"crypto/tls"
	"net/http"
	"sync"
	"time"
)

type AuthMethod interface {
	Apply(req *http.Request)
}

type Endpoint struct {
	Memory      *sync.RWMutex     `json:"-"`
	RespCH      chan ResponseItem `json:"-"`
	RateMark    time.Time         `json:"-"`
	RateLimited bool              `json:"-"`
	InFlight    int               `json:"-"`
	MaxRequests int               `json:"-"`
	RefillRate  time.Duration     `json:"-"`
	Backlog     []*http.Request   `json:"-"`
	Auth        AuthMethod        `json:"-"`
	Path        string            `json:"path"`
	URL         string            `json:"url"`
	Key         string            `json:"key"`
	Gateway     *http.Client      `json:"-"`
}

func NewEndpoint(url string, auth AuthMethod, insecure bool, respch chan ResponseItem) *Endpoint {
	mem := &sync.RWMutex{}
	if insecure {
		client := &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
			},
		}
		return &Endpoint{
			Memory:  mem,
			RespCH:  respch,
			URL:     url,
			Gateway: client,
			Auth:    auth,
		}
	} else {
		client := &http.Client{}
		return &Endpoint{
			Memory:  mem,
			RespCH:  respch,
			URL:     url,
			Gateway: client,
			Auth:    auth,
		}
	}
}

func (e *Endpoint) GetAuth() AuthMethod {
	return e.Auth
}

func (e *Endpoint) SetAuth(a AuthMethod) {
	e.Auth = a
}

func (e *Endpoint) GetURL() string {
	return e.URL
}

func (e *Endpoint) Do(req *http.Request) []byte {
	e.Auth.Apply(req)
	if e.RateLimited {
		// uid := uuid.New().String()
		if e.InFlight >= e.MaxRequests {
			e.Memory.Lock()
			if e.RateMark.IsZero() {
				e.RateMark = time.Now()
			}
			// log.Println("--------------------------------------------Rate limited")
			if time.Since(e.RateMark) > e.RefillRate {
				// log.Println("--------------------------------------------Refilling")
				e.InFlight = 0
				e.RateMark = time.Now()
			}
			e.Backlog = append(e.Backlog, req)
			e.Memory.Unlock()
			// sumOut := SummarizedEvent{
			// 	ID:            "0",
			// 	Background:    "has-background-info",
			// 	Info:          "Request backlogged due to a rate limit",
			// 	ThreatLevelID: "0",
			// 	Link:          "coming soon!",
			// }
			// out, err := json.Marshal(sumOut)
			// if err != nil {
			// 	fmt.Println("ERROR", e, err)
			// 	return []byte(err.Error())
			// }
			// return out
			return []byte{}
		}
		e.InFlight++
		// defer func() {
		// 	// e.InFlight--
		// 	e.ProcessQueue(uid)
		// }()
	}
	resp, err := e.Gateway.Do(req)
	if err != nil {
		return []byte(err.Error())
	}
	defer resp.Body.Close()
	buf := new(bytes.Buffer)
	buf.ReadFrom(resp.Body)
	return buf.Bytes()
}

func (e *Endpoint) ProcessQueue(id string) {
	if len(e.Backlog) == 0 || e.InFlight >= e.MaxRequests {
		return
	}
	e.Memory.Lock()
	req := e.Backlog[0]
	e.Backlog = e.Backlog[1:]
	e.InFlight++
	e.Memory.Unlock()
	go func() {
		res := e.Do(req)
		ri := ResponseItem{
			ID:   id,
			Time: time.Now(),
			Data: res,
		}
		e.RespCH <- ri
	}()
}

type BasicAuth struct {
	// AuthMethod
	Username string
	Password string
}

type BearerAuth struct {
	// AuthMethod
	Token string
}

type KeyAuth struct {
	// AuthMethod
	Token string
}

type XAPIKeyAuth struct {
	Token string `json:"token"`
}

func (x *XAPIKeyAuth) Apply(req *http.Request) {
	req.Header.Set("x-apikey", x.Token)
	req.Header.Set("Accept", "application/json")
}

func (b *BearerAuth) Apply(req *http.Request) {
	req.Header.Set("Authorization", "Bearer "+b.Token)
}

func (k *KeyAuth) Apply(req *http.Request) {
	req.Header.Set("Authorization", k.Token)
}

func (b *BasicAuth) Apply(req *http.Request) {
	req.SetBasicAuth(b.Username, b.Password)
}
