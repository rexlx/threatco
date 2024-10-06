package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/rexlx/threatco/vendors"
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

type SummarizedEvent struct {
	ID            string `json:"id"`
	AttrCount     int    `json:"attr_count"`
	Link          string `json:"link"`
	ThreatLevelID string `json:"threat_level_id"`
}

type AttributeRequest struct {
	Value   string `json:"value"`
	Type    string `json:"type"`
	EventID string `json:"event_id"`
}
type AddAttrSchema struct {
	EventID        string `json:"event_id"`
	ObjectID       string `json:"object_id"`
	ObjectRelation string `json:"object_relation"`
	Category       string `json:"category"`
	Type           string `json:"type"`
	Value          string `json:"value"`
	ToIDS          bool   `json:"to_ids"`
	UUID           string `json:"uuid"`
	Timestamp      string `json:"timestamp"`
	Distribution   string `json:"distribution"`
	SharingGroupID string `json:"sharing_group_id"`
	Comment        string `json:"comment"`
	Deleted        bool   `json:"deleted"`
	DisableCorr    bool   `json:"disable_correlation"`
	FirstSeen      string `json:"first_seen"`
	LastSeen       string `json:"last_seen"`
}

func (s *Server) AddAttributeHandler(w http.ResponseWriter, r *http.Request) {
	defer s.addStat("add_event_requests", 1)
	defer func(start time.Time) {
		fmt.Println("AddEventHandler took", time.Since(start))
	}(time.Now())
	var ar AttributeRequest
	err := json.NewDecoder(r.Body).Decode(&ar)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if ar.EventID == "" || ar.Value == "" {
		http.Error(w, "missing 'event_id' field", http.StatusBadRequest)
		return
	}
	ep, ok := s.Targets["misp"]
	if !ok {
		http.Error(w, "misp endpoint not found", http.StatusNotFound)
		return
	}
	url := fmt.Sprintf("%s/attributes/add/%v", ep.GetURL(), ar.EventID)
	result := AddAttrSchema{
		EventID:        ar.EventID,
		ObjectID:       "",
		ObjectRelation: "",
		Category:       "Network activity",
		Type:           ar.Type,
		Value:          ar.Value,
		ToIDS:          true,
		UUID:           uuid.New().String(),
		Timestamp:      "",
		Distribution:   "0",
		SharingGroupID: "",
		Comment:        "",
		Deleted:        false,
		DisableCorr:    false,
		FirstSeen:      "",
		LastSeen:       "",
	}
	out, err := json.Marshal(result)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
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

func (s *Server) ProxyHandler(w http.ResponseWriter, r *http.Request) {
	fmt.Println("called")
	defer s.addStat("proxy_requests", 1)
	defer func(start time.Time) {
		fmt.Println("ProxyHandler took", time.Since(start))
	}(time.Now())
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
	go s.addStat(url, float64(len(out)))
	request, err := http.NewRequest("POST", url, bytes.NewBuffer(out))
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "application/json")
	resp := ep.Do(request)
	var response vendors.Response
	err = json.Unmarshal(resp, &response)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if len(response.Response) != 0 {
		if len(response.Response) > 1 {
			sum := SummarizedEvent{}
			sum.ID = "multiple"
			sum.AttrCount = len(response.Response)
			sum.Link = fmt.Sprintf("%s/events/index", s.Details.Address)
			sum.ThreatLevelID = "0"
			resp, err = json.Marshal(sum)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
		} else {
			sum := SummarizedEvent{}
			sum.ID = response.Response[0].Event.ID
			sum.AttrCount = len(response.Response[0].Event.Attribute)
			sum.Link = fmt.Sprintf("%s/events/view/%s", s.Details.Address, sum.ID)
			sum.ThreatLevelID = response.Response[0].Event.ThreatLevelID
			resp, err = json.Marshal(sum)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
		}
	} else {
		sum := SummarizedEvent{}
		sum.ID = "none"
		sum.AttrCount = 0
		sum.Link = "none"
		sum.ThreatLevelID = "0"
		resp, err = json.Marshal(sum)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	}
	w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate") // HTTP 1.1
	w.Header().Set("Pragma", "no-cache")                                   // HTTP 1.0
	w.Header().Set("Expires", "0")
	w.Write(resp)
}
