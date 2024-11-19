package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
)

func (s *Server) FileServer() http.Handler {
	return http.FileServer(http.Dir("./static"))
}

func (s *Server) AddAttributeHandler(w http.ResponseWriter, r *http.Request) {
	defer s.addStat("add_event_requests", 1)
	defer func(start time.Time) {
		s.Log.Println("AddEventHandler took", time.Since(start))
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

func (s *Server) AddServiceHandler(w http.ResponseWriter, r *http.Request) {
	defer s.addStat("add_service_requests", 1)
	// body, err := io.ReadAll(r.Body)
	// if err != nil {
	// 	http.Error(w, err.Error(), http.StatusInternalServerError)
	// 	return
	// }
	// fmt.Println("body", string(body), "body")
	err := r.ParseForm()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	var svc ServiceType
	var rm RouteMap
	for k, v := range r.PostForm {
		switch k {
		case "kind":
			svc.Kind = v[0]
		case "types":
			tmp := strings.Split(v[0], ",")
			for _, t := range tmp {
				svc.Type = append(svc.Type, strings.TrimLeft(t, " "))
			}
		default:
			if len(svc.Type) == len(v) {
				for i, t := range v {
					rm.Route = t
					rm.Type = svc.Type[i]
					// rm.Type = strings.TrimLeft(svc.Type[i], " ")
					svc.RouteMap = append(svc.RouteMap, rm)
				}
			}

		}
	}
	err = s.AddService(svc)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	s.Memory.Lock()
	defer s.Memory.Unlock()
	s.Details.SupportedServices = append(s.Details.SupportedServices, svc)

	out, err := json.Marshal(svc)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Write(out)
}

func (s *Server) GetStatHistoryHandler(w http.ResponseWriter, r *http.Request) {
	// defer s.addStat("get_stat_history_requests", 1)
	defer func(start time.Time) {
		fmt.Println("GetStatHistoryHandler took", time.Since(start))
	}(time.Now())
	s.Memory.RLock()
	out, err := json.Marshal(s.Cache.StatsHistory)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		s.Memory.RUnlock()
		return
	}
	s.Memory.RUnlock()
	w.Write(out)
}

func (s *Server) AddUserHandler(w http.ResponseWriter, r *http.Request) {
	// defer s.addStat("add_user_requests", 1)
	defer func(start time.Time) {
		fmt.Println("AddUserHandler took", time.Since(start))
	}(time.Now())
	var nur NewUserRequest
	err := json.NewDecoder(r.Body).Decode(&nur)
	if err != nil {
		fmt.Println("error", err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if nur.Email == "" {
		fmt.Println("error", err)
		http.Error(w, "missing 'email' field", http.StatusBadRequest)
		return
	}
	//
	var b bool
	if nur.Admin == "on" {
		b = true
	}
	user, err := NewUser(nur.Email, b, s.Details.SupportedServices)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if nur.Password != "" {
		err = user.SetPassword(nur.Password)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	}
	// s.Memory.Lock()
	err = s.AddUser(*user)
	if err != nil {
		fmt.Println("error", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		// s.Memory.Unlock()
		return
	}
	// s.Memory.Unlock()
	out, err := json.Marshal(user)
	if err != nil {
		fmt.Println("error", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Write(out)
}

func (s *Server) ProxyHandler(w http.ResponseWriter, r *http.Request) {
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
	uid := uuid.New().String()
	req.TransactionID = uid
	switch req.To {
	case "misp":
		resp, err := s.MispHelper(req)
		if err != nil {
			fmt.Println("bigtime error", err)
			// fmt.Println("bigtime error", err, string(resp))
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Write(resp)
		return
	case "virustotal":
		// fmt.Println("virustotal", req)
		resp, err := s.VirusTotalHelper(req)
		if err != nil {
			fmt.Println("bigtime error", err)
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Write(resp)
		return
	case "deepfry":
		resp, err := s.DeepFryHelper(req)
		if err != nil {
			fmt.Println("bigtime error", err)
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Write(resp)
		return
	default:
		sumOut := SummarizedEvent{
			From:          req.To,
			Error:         true,
			Background:    "has-background-danger",
			Info:          fmt.Sprintf("unknown target %s", req.To),
			ThreatLevelID: "0",
			Value:         req.Value,
			ID:            "unknown target",
			Link:          req.TransactionID,
		}
		out, err := json.Marshal(sumOut)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Write(out)
	}
}

func (s *Server) EventHandler(w http.ResponseWriter, r *http.Request) {
	fmt.Println("--------------------------------------EventHandler")
	defer s.addStat("event_requests", 1)
	s.Memory.RLock()
	defer s.Memory.RUnlock()
	id := r.URL.Path[len("/events/"):]
	event, ok := s.Cache.Responses[id]
	if !ok {
		http.Error(w, "event not found", http.StatusNotFound)
		return
	}
	// out, err := json.Marshal(event)
	// if err != nil {
	// 	http.Error(w, err.Error(), http.StatusInternalServerError)
	// 	return
	// }
	w.Write(event.Data)
}

func (s *Server) GetServicesHandler(w http.ResponseWriter, r *http.Request) {
	defer s.addStat("get_services_requests", 1)
	defer func(start time.Time) {
		fmt.Println("GetServicesHandler took", time.Since(start))
	}(time.Now())
	s.Memory.RLock()
	defer s.Memory.RUnlock()
	out, err := json.Marshal(s.Details.SupportedServices)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Write(out)
}

type RawResponseRequest struct {
	ID string `json:"id"`
}

func (s *Server) GetUserHandler(w http.ResponseWriter, r *http.Request) {
	defer s.addStat("get_user_requests", 1)
	defer func(start time.Time) {
		fmt.Println("GetUserHandler took", time.Since(start))
	}(time.Now())
	// s.Memory.RLock()
	// defer s.Memory.RUnlock()
	parts := strings.Split(r.Header.Get("Authorization"), ":")
	email := parts[0]
	u, err := s.GetUserByEmail(email)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	out, err := json.Marshal(u)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Write(out)
}

func (s *Server) RawResponseHandler(w http.ResponseWriter, r *http.Request) {
	var rr RawResponseRequest
	err := json.NewDecoder(r.Body).Decode(&rr)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	s.Memory.RLock()
	defer s.Memory.RUnlock()
	res, ok := s.Cache.Responses[rr.ID]
	if !ok {
		http.Error(w, "response not found", http.StatusNotFound)
		return
	}
	w.Write(res.Data)
}

func (s *Server) LoginHandler(w http.ResponseWriter, r *http.Request) {
	tkn, _ := s.GetTokenFromSession(r)
	if tkn != "" {
		http.Error(w, "already logged in", http.StatusForbidden)
		return
	}
	email := r.FormValue("username")
	password := r.FormValue("password")
	u, err := s.GetUserByEmail(email)
	if err != nil || u.Email == "" {
		fmt.Println("LoginHandler: user not found", email)
		http.Error(w, "user not found", http.StatusNotFound)
		return
	}
	ok, err := u.PasswordMatches(password)
	if err != nil {
		fmt.Println("error checking password", err, email)
		http.Error(w, "error checking password", http.StatusInternalServerError)
		return
	}
	if !ok {
		fmt.Println("password does not match", email)
		http.Error(w, "password does not match", http.StatusUnauthorized)
		return
	}
	err = s.AddUser(u)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	tk, err := u.SessionToken.CreateToken(u.ID, 24*time.Hour)
	if err != nil {
		fmt.Println("error creating token", err)
		http.Error(w, "error creating token", http.StatusInternalServerError)
		return
	}
	tk.Email = u.Email
	err = s.SaveToken(*tk)
	if err != nil {
		fmt.Println("error saving token", err)
		http.Error(w, "error saving token", http.StatusInternalServerError)
		return
	}
	err = s.AddTokenToSession(r, w, tk)
	if err != nil {
		fmt.Println("error adding token to session", err)
		http.Error(w, "error adding token to session", http.StatusInternalServerError)
		return
	}
	fmt.Println("login successful", u.Email)
	s.Memory.Lock()
	s.Details.Stats["logins"]++
	s.Memory.Unlock()
	w.Write([]byte("login successful"))
}

func (s *Server) UpdateUserHandler(w http.ResponseWriter, r *http.Request) {
	fmt.Println("UpdateUserHandler")
	var u User
	err := json.NewDecoder(r.Body).Decode(&u)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	fmt.Println("UpdateUserHandler", u)
	user, err := s.GetUserByEmail(u.Email)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	user.Services = u.Services
	user.Updated = time.Now()
	err = s.AddUser(user)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	user.Password = ""
	user.Hash = nil
	out, err := json.Marshal(user)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Write(out)
}

type NewUserRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
	Admin    string `json:"admin"`
}

type ProxyRequest struct {
	To            string `json:"to"`
	Route         string `json:"route"`
	Type          string `json:"type"`
	Value         string `json:"value"`
	From          string `json:"from"`
	TransactionID string `json:"transaction_id"`
}

type GenericOut struct {
	Value string `json:"value"`
	Type  string `json:"type"`
}

type SummarizedEvent struct {
	Matched       bool   `json:"matched"`
	Error         bool   `json:"error"`
	Background    string `json:"background"`
	From          string `json:"from"`
	ID            string `json:"id"`
	AttrCount     int    `json:"attr_count"`
	Link          string `json:"link"`
	ThreatLevelID string `json:"threat_level_id"`
	Value         string `json:"value"`
	Info          string `json:"info"`
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
