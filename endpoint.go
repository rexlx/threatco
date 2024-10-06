package main

import (
	"bytes"
	"crypto/tls"
	"net/http"
)

type AuthMethod interface {
	Apply(req *http.Request)
}

type Endpoint struct {
	Auth    AuthMethod   `json:"-"`
	Path    string       `json:"path"`
	URL     string       `json:"url"`
	Key     string       `json:"key"`
	Gateway *http.Client `json:"-"`
}

func NewEndpoint(url string, auth AuthMethod, insecure bool) *Endpoint {
	if insecure {
		client := &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
			},
		}
		return &Endpoint{
			URL:     url,
			Gateway: client,
			Auth:    auth,
		}
	} else {
		client := &http.Client{}
		return &Endpoint{
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
	resp, err := e.Gateway.Do(req)
	if err != nil {
		return []byte(err.Error())
	}
	defer resp.Body.Close()
	buf := new(bytes.Buffer)
	buf.ReadFrom(resp.Body)
	return buf.Bytes()
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

func (b *BearerAuth) Apply(req *http.Request) {
	req.Header.Set("Authorization", "Bearer "+b.Token)
}

func (k *KeyAuth) Apply(req *http.Request) {
	req.Header.Set("Authorization", k.Token)
}

func (b *BasicAuth) Apply(req *http.Request) {
	req.SetBasicAuth(b.Username, b.Password)
}
