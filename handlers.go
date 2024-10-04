package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
)

type ProxyRequest struct {
	To    string `json:"to"`
	Route string `json:"route"`
	Type  string `json:"type"`
	Value string `json:"value"`
}

type GenericOut struct {
	Value string `json:"value"`
	Type  string `json:"type"`
}

func (s *Server) ProxyHandler(w http.ResponseWriter, r *http.Request) {
	var req ProxyRequest
	err := json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if req.To == "" {
		http.Error(w, "missing 'to' field", http.StatusBadRequest)
		return
	}
	var output GenericOut
	output.Type = req.Type
	output.Value = req.Value
	out, err := json.Marshal(output)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	ep, ok := s.Targets[req.To]
	if !ok {
		http.Error(w, "endpoint not found", http.StatusNotFound)
		return
	}
	url := fmt.Sprintf("%s/%s", ep.GetURL(), req.Route)
	request, err := http.NewRequest("POST", url, bytes.NewBuffer(out))
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "application/json")
	resp := ep.Do(request)
	w.Write(resp)
}
