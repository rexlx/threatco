package main

import (
	"bytes"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"
)

type AuthMethod interface {
	Apply(req *http.Request)
	GetAndStoreToken(stop chan bool)
}

type Endpoint struct {
	UploadService bool              `json:"upload_service"`
	Name          string            `json:"name"`
	Memory        *sync.RWMutex     `json:"-"`
	RespCH        chan ResponseItem `json:"-"`
	RateMark      time.Time         `json:"-"`
	RateLimited   bool              `json:"-"`
	InFlight      int               `json:"-"`
	MaxRequests   int               `json:"-"`
	RefillRate    time.Duration     `json:"-"`
	Backlog       []*http.Request   `json:"-"`
	Auth          AuthMethod        `json:"-"`
	Path          string            `json:"path"`
	URL           string            `json:"url"`
	Key           string            `json:"key"`
	Gateway       *http.Client      `json:"-"`
}

func NewEndpoint(url string, auth AuthMethod, insecure bool, respch chan ResponseItem, name string) *Endpoint {
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
		e := CheckConnectivity(e.URL)
		if e != nil {
			fmt.Println("CheckConnectivity -> Endpoint.Do: error doing request", e)
		} else {
			fmt.Println("Endpoint.Do: failed to perorm request but passed connectivity check...")
		}
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

func (b *BasicAuth) GetInfo() (string, string) {
	return b.Username, b.Password
}

type BearerAuth struct {
	// AuthMethod
	Token string
}

type KeyAuth struct {
	// AuthMethod
	Token string
}

type VmRayAuth struct {
	Token string
}

type PrefetchAuth struct {
	AppName string `json:"x_app"`
	URL     string `json:"url"`
	Key     string `json:"key"`
	Secret  string `json:"secret"`
	Token   string `json:"token"`
	Expires int    `json:"expires"`
}

type XAPIKeyAuth struct {
	Token string `json:"token"`
}

func (p *PrefetchAuth) Apply(req *http.Request) {
	if p.AppName == "" {
		fmt.Println("PrefetchAuth.Apply: AppName is not set, using default 'threatco'")
		p.AppName = "threatco"
	}
	req.Header.Set("X-App-Name", p.AppName)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+p.Token)
}

func (p *PrefetchAuth) GetAndStoreToken(stop chan bool) {
	ticker := time.NewTicker(time.Duration(p.Expires-5) * time.Second)
	client := &http.Client{}

	for {
		_auth := p.Key + ":" + p.Secret
		auth := base64.StdEncoding.EncodeToString([]byte(_auth))
		grant := []byte("grant_type=client_credentials")
		req, err := http.NewRequest("POST", p.URL, bytes.NewBuffer(grant))
		if err != nil {
			fmt.Println("PrefetchAuth.GetAndStoreToken: error creating request", err)
			return
		}
		req.Header.Set("Authorization", "Basic "+auth)
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("Accept", "application/json")
		req.Header.Set("X-App-Name", p.AppName)
		resp, err := client.Do(req)
		if err != nil {
			fmt.Println("PrefetchAuth.GetAndStoreToken: error doing request", err)
			continue
		}
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			fmt.Println("PrefetchAuth.GetAndStoreToken: error reading response body", err)
			continue
		}
		resp.Body.Close()
		type mandiantTokenResponse struct {
			Token     string `json:"access_token"`
			Expires   int    `json:"expires_in"`
			TokenType string `json:"token_type"`
		}
		var res mandiantTokenResponse
		if err := json.Unmarshal(body, &res); err != nil {
			fmt.Println("PrefetchAuth.GetAndStoreToken: error unmarshaling response", err)
			continue
		}
		p.Token = res.Token
		fmt.Println("PrefetchAuth.GetAndStoreToken: token updated", len(p.Token), "chars, expires in", res.Expires, "seconds")
		select {
		case <-ticker.C:
			continue
		case <-stop:
			return
		}
	}
}

func (x *XAPIKeyAuth) GetAndStoreToken(stop chan bool) {
	fmt.Println("no need to rotate token")
}

func (x *XAPIKeyAuth) Apply(req *http.Request) {
	req.Header.Set("x-apikey", x.Token)
	req.Header.Set("Accept", "application/json")
}

func (v *VmRayAuth) GetAndStoreToken(stop chan bool) {
	fmt.Println("no need to rotate token")
}

func (v *VmRayAuth) Apply(req *http.Request) {
	key := fmt.Sprintf("api_key %s", v.Token)
	req.Header.Set("Authorization", key)
	req.Header.Set("Accept", "application/json")
}

func (b *BearerAuth) GetAndStoreToken(stop chan bool) {
	fmt.Println("no need to rotate token")
}

func (b *BearerAuth) Apply(req *http.Request) {
	req.Header.Set("Authorization", "Bearer "+b.Token)
}

func (k *KeyAuth) GetAndStoreToken(stop chan bool) {
	fmt.Println("no need to rotate token")
}

func (k *KeyAuth) Apply(req *http.Request) {
	req.Header.Set("Authorization", k.Token)
}

func (b *BasicAuth) GetAndStoreToken(stop chan bool) {
	fmt.Println("no need to rotate token")
}

func (b *BasicAuth) Apply(req *http.Request) {
	req.SetBasicAuth(b.Username, b.Password)
}
