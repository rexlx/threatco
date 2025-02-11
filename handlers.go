package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/rexlx/threatco/parser"
)

var store *UploadStore

func PassStore(s *UploadStore) {
	store = s
}

type ParserRequest struct {
	Blob string `json:"blob"`
}

func (s *Server) ParserHandler(w http.ResponseWriter, r *http.Request) {
	var wg sync.WaitGroup
	allBytes := []byte{'['} //  Don't initialize here, will be used later
	first := true
	var mu sync.Mutex
	// defer s.addStat("parser_requests", 1)
	// defer func(start time.Time) {
	// 	s.Log.Println("ParserHandler took", time.Since(start))
	// }(time.Now())
	cx := parser.NewContextualizer()
	var pr ParserRequest
	err := json.NewDecoder(r.Body).Decode(&pr)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	out := make(map[string][]parser.Match)
	for k, v := range cx.Expressions {
		out[k] = cx.GetMatches(pr.Blob, k, v)
	}

	for k, v := range out {
		fmt.Println("parser", k, v)
		for _, svc := range s.Details.SupportedServices {
			for _, t := range svc.Type {
				if t == k && len(v) > 0 { // later check is service is rate limited
					if svc.RateLimited {
						continue
					}
					for _, value := range v {
						var pr ProxyRequest
						if len(svc.RouteMap) > 0 {
							for _, rm := range svc.RouteMap {
								if rm.Type == k {
									pr.Route = rm.Route
								}
							}
						}
						pr.To = svc.Kind
						pr.Type = k
						pr.Value = value.Value
						pr.From = "parser"
						uid := uuid.New().String()
						pr.TransactionID = uid
						fmt.Println("parser match", pr)
						wg.Add(1)
						go func(id string, first *bool) {
							defer wg.Done()
							out, err := s.ProxyHelper(pr)
							if err != nil {
								fmt.Println("error", err)
								// continue
							}
							mu.Lock()
							if len(out) == 0 {
								return
							}
							if !*first {
								allBytes = append(allBytes, ',')
							}
							allBytes = append(allBytes, out...)
							*first = false
							mu.Unlock()
							s.DB.StoreResponse(id, out)
						}(uid, &first)
						// do thing
					}
				}
			}
		}
	}
	wg.Wait()
	allBytes = append(allBytes, ']')
	w.Write(allBytes)
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
	err = s.DB.AddService(svc)
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
		s.Log.Println("GetStatHistoryHandler took", time.Since(start))
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
		s.Log.Println("AddUserHandler took", time.Since(start))
	}(time.Now())
	var nur NewUserRequest
	err := json.NewDecoder(r.Body).Decode(&nur)
	if err != nil {
		s.Log.Println("error", err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if nur.Email == "" {
		s.Log.Println("error", err)
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
	err = s.DB.AddUser(*user)
	if err != nil {
		s.Log.Println("error", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		// s.Memory.Unlock()
		return
	}
	// s.Memory.Unlock()
	out, err := json.Marshal(user)
	if err != nil {
		s.Log.Println("error", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Write(out)
}

func (s *Server) ProxyHandler(w http.ResponseWriter, r *http.Request) {
	// var written int
	var req ProxyRequest
	defer s.addStat("proxy_requests", 1)
	defer func(start time.Time, kind string) {
		s.Log.Println("__ProxyHandler__ took:", time.Since(start), kind)
	}(time.Now(), req.To)

	err := json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		s.Log.Println("ProxyHandler decoder error", err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	// s.Log.Println("ProxyHandler", req)
	uid := uuid.New().String()
	req.TransactionID = uid
	switch req.To {
	case "misp":
		resp, err := s.MispHelper(req)
		if err != nil {
			r, err := CreateAndWriteSummarizedEvent(req, true, fmt.Sprintf("error: %v", err))
			if err != nil {
				s.Log.Println("bigtime error", err)
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			go s.DB.StoreResponse(uid, r)
			w.Write(r)
			return
		}
		go s.DB.StoreResponse(uid, resp)
		w.Write(resp)
		return
	case "virustotal":
		// s.Log.Println("virustotal", req)
		resp, err := s.VirusTotalHelper(req)
		if err != nil {
			r, err := CreateAndWriteSummarizedEvent(req, true, fmt.Sprintf("error: %v", err))
			if err != nil {
				s.Log.Println("bigtime error", err)
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			go s.DB.StoreResponse(uid, r)
			w.Write(r)
			return
		}
		go s.DB.StoreResponse(uid, resp)
		w.Write(resp)
		return
	case "mandiant":
		resp, err := s.MandiantHelper(req)
		if err != nil {
			r, err := CreateAndWriteSummarizedEvent(req, true, fmt.Sprintf("error: %v", err))
			if err != nil {
				s.Log.Println("bigtime error", err)
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			go s.DB.StoreResponse(uid, r)
			w.Write(r)
			return
		}
		go s.DB.StoreResponse(uid, resp)
		w.Write(resp)
		return
	case "deepfry":
		resp, err := s.DeepFryHelper(req)
		if err != nil {
			r, err := CreateAndWriteSummarizedEvent(req, true, fmt.Sprintf("error: %v", err))
			if err != nil {
				s.Log.Println("bigtime error", err)
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			go s.DB.StoreResponse(uid, r)
			w.Write(r)
			return
		}
		go s.DB.StoreResponse(uid, resp)
		w.Write(resp)
		return
	default:
		sumOut := SummarizedEvent{
			Timestamp:     time.Now(),
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
	// s.Memory.Lock()
	// s.Details.Stats["amount_proxied"] += float64(written)
	// s.Memory.Unlock()
}

func (s *Server) EventHandler(w http.ResponseWriter, r *http.Request) {
	// defer s.addStat("event_requests", 1)
	s.Memory.Lock()
	defer s.Memory.Unlock()
	id := r.URL.Path[len("/events/"):]
	s.Log.Println("EventHandler", id)
	event, ok := s.Cache.Responses[id]
	if !ok {
		b, err := s.DB.GetResponse(id)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		event = ResponseItem{
			ID:   id,
			Time: time.Now(),
			Data: b,
		}
		s.Cache.Responses[id] = event
	}
	// out, err := json.Marshal(event)
	// if err != nil {
	// 	http.Error(w, err.Error(), http.StatusInternalServerError)
	// 	return
	// }
	if event.Data == nil || len(event.Data) == 0 {
		w.Write([]byte("no data for this event, but a record exists"))
	}
	fmt.Println("event", string(event.Data))
	w.Write(event.Data)
}

func (s *Server) GetServicesHandler(w http.ResponseWriter, r *http.Request) {
	// defer s.addStat("get_services_requests", 1)
	sanitized_services := []ServiceType{}
	defer func(start time.Time) {
		s.Log.Println("GetServicesHandler took", time.Since(start))
	}(time.Now())
	s.Memory.RLock()
	defer s.Memory.RUnlock()
	for _, svc := range s.Details.SupportedServices {
		sanitized_services = append(sanitized_services, ServiceType{
			Kind:          svc.Kind,
			Type:          svc.Type,
			Selected:      svc.Selected,
			Name:          svc.Name,
			URL:           svc.URL,
			UploadService: svc.UploadService,
		})
	}
	out, err := json.Marshal(sanitized_services)
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
	// defer func(start time.Time) {
	// 	s.Log.Println("GetUserHandler took", time.Since(start))
	// }(time.Now())
	// s.Memory.RLock()
	// defer s.Memory.RUnlock()
	parts := strings.Split(r.Header.Get("Authorization"), ":")
	email := parts[0]
	u, err := s.DB.GetUserByEmail(email)
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
	u, err := s.DB.GetUserByEmail(email)
	if err != nil || u.Email == "" {
		s.Log.Println("LoginHandler: user not found", email)
		http.Error(w, "user not found", http.StatusNotFound)
		return
	}
	ok, err := u.PasswordMatches(password)
	if err != nil {
		s.Log.Println("error checking password", err, email)
		http.Error(w, "error checking password", http.StatusInternalServerError)
		return
	}
	if !ok {
		s.Log.Println("password does not match", email)
		http.Error(w, "password does not match", http.StatusUnauthorized)
		return
	}
	err = s.DB.AddUser(u)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	tk, err := u.SessionToken.CreateToken(u.ID, 24*time.Hour)
	if err != nil {
		s.Log.Println("error creating token", err)
		http.Error(w, "error creating token", http.StatusInternalServerError)
		return
	}
	tk.Email = u.Email
	err = s.DB.SaveToken(*tk)
	if err != nil {
		s.Log.Println("error saving token", err)
		http.Error(w, "error saving token", http.StatusInternalServerError)
		return
	}
	err = s.AddTokenToSession(r, w, tk)
	if err != nil {
		s.Log.Println("error adding token to session", err)
		http.Error(w, "error adding token to session", http.StatusInternalServerError)
		return
	}
	s.Log.Println("login successful", email)
	http.Redirect(w, r, "/services", http.StatusSeeOther)
	s.Memory.Lock()
	s.Details.Stats["logins"]++
	s.Memory.Unlock()
}

func (s *Server) LogoutHandler(w http.ResponseWriter, r *http.Request) {
	err := s.DeleteTokenFromSession(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (s *Server) DeleteUserHandler(w http.ResponseWriter, r *http.Request) {
	s.Log.Println("DeleteUserHandler")
	email := r.FormValue("email")
	err := s.DB.DeleteUser(email)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Write([]byte("ok"))
}

func (s *Server) UpdateUserHandler(w http.ResponseWriter, r *http.Request) {
	s.Log.Println("UpdateUserHandler")
	var u User
	err := json.NewDecoder(r.Body).Decode(&u)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	s.Log.Println("UpdateUserHandler", u)
	user, err := s.DB.GetUserByEmail(u.Email)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if u.Password != "" {
		err = user.SetPassword(u.Password)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	}
	user.Admin = u.Admin
	user.Services = u.Services
	user.Updated = time.Now()
	err = s.DB.AddUser(user)
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

// var UploadResponse = []byte(`{"status": "ok"}`)
type uploadResponse struct {
	Status string `json:"status"`
	ID     string `json:"id"`
}

func (s *Server) UploadFileHandler(w http.ResponseWriter, r *http.Request) {
	var fileData bytes.Buffer
	var UploadResponse uploadResponse
	// Copy the request body (file data) to the buffer
	_, err := io.Copy(&fileData, r.Body)
	if err != nil {
		http.Error(w, "Error reading file data", http.StatusInternalServerError)
		return
	}
	defer s.addStat("upload_file_requests", 1)
	defer func(start time.Time) {
		s.Log.Println("UploadFileHandler took", time.Since(start))
	}(time.Now())
	chunkSize := r.ContentLength
	filename := r.Header.Get("X-filename")
	filename, err = RemoveTimestamp("_", filename)
	if err != nil {
		fmt.Println("error removing timestamp", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	lastChunk := r.Header.Get("X-last-chunk")
	// fmt.Println(chunkSize, filename, lastChunk)
	uploadHanlder, ok := store.GetFile(filename)
	if !ok {
		uploadHanlder = UploadHandler{
			ID:       uuid.New().String(),
			Data:     fileData.Bytes(),
			FileSize: chunkSize,
		}
		go store.AddFile(filename, uploadHanlder)
	} else {
		uploadHanlder.Data = append(uploadHanlder.Data, fileData.Bytes()...)
		uploadHanlder.FileSize += chunkSize
	}

	if lastChunk == "true" {
		fmt.Println("last chunk", uploadHanlder.FileSize)
		uploadHanlder.Complete = true
	}

	go store.AddFile(filename, uploadHanlder)

	if uploadHanlder.Complete {
		uid := uuid.New().String()
		UploadResponse.ID = uid
		UploadResponse.Status = "complete"
		// uploadHanlder.WriteToDisk(fmt.Sprintf("./static/%s", filename))
		go func(id string) {
			res, err := s.VmRayFileSubmissionHelper(filename, uploadHanlder) // use AddResponse(id, []b)
			if err != nil {
				s.RespCh <- ResponseItem{
					ID:   id,
					Time: time.Now(),
					Data: []byte(fmt.Sprintf("error: %v", err)),
				}
				s.Log.Println("error", err)
				return
			}
			// w.Write(res)
			store.DeleteFile(filename)
			newResponse := ResponseItem{
				ID:   id,
				Time: time.Now(),
				Data: res,
			}
			s.RespCh <- newResponse
		}(uid)
	}
	out, err := json.Marshal(UploadResponse)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Write(out)
}

func (s *Server) LogsSSRHandler(w http.ResponseWriter, r *http.Request) {
	s.Log.Println("LogsSSRHandler")
	s.Memory.RLock()
	defer s.Memory.RUnlock()
	step := 50
	if len(s.Cache.Logs) < 50 {
		step = len(s.Cache.Logs)
	}
	chunk := s.Cache.Logs[0:step]
	out := LogItemsToArticle(chunk)

	fmt.Fprint(w, out)
}

func (s *Server) GetLogsHandler(w http.ResponseWriter, r *http.Request) {
	start, _ := strconv.Atoi(r.URL.Query().Get("start"))
	end, _ := strconv.Atoi(r.URL.Query().Get("end"))
	s.Memory.RLock()
	defer s.Memory.RUnlock()
	if start > len(s.Cache.Logs) {
		tmp := []LogItem{}
		out, err := json.Marshal(tmp)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Write(out)
		return
	}
	if start < 1 {
		start = 0
	}
	if end < 1 {
		end = start + 50
	}
	if end > len(s.Cache.Logs) {
		end = len(s.Cache.Logs)
	}
	out, err := json.Marshal(s.Cache.Logs[start:end])
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Write(out)
}

func (s *Server) KillServerDeadHandler(w http.ResponseWriter, r *http.Request) {
	s.Log.Println("KillServerDeadHandler called. must kill the server.")
	w.Write([]byte("ok"))
	s.StopCh <- true
}

func (s *Server) GetResponseCacheListHandler(w http.ResponseWriter, r *http.Request) {
	defer s.addStat("get_response_cache_list_requests", 1)
	defer func(start time.Time) {
		s.Log.Println("GetResponseCacheListHandler took", time.Since(start))
	}(time.Now())
	s.Memory.RLock()
	defer s.Memory.RUnlock()
	tmp := make(map[string]string)
	for k, v := range s.Cache.Responses {
		tmp[k] = fmt.Sprintf("%v: %v", v.ID, v.Time)
	}
	out, err := json.Marshal(tmp)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Write(out)
}

func (s *Server) GetResponseCacheHandler(w http.ResponseWriter, r *http.Request) {
	var out string
	tmpl := `<div class="container is-fluid has-background-black-ter">
		<p class="has-text-info">added: %v link: <a href="/events/%v">%v</a></p>
		</div>`
	s.Memory.RLock()
	defer s.Memory.RUnlock()
	for k, v := range s.Cache.Responses {
		out += fmt.Sprintf(tmpl, v.Time, k, k)
	}
	fmt.Fprint(w, out)
}

// func (s *Server) GetResponsesHandler(w http.ResponseWriter, r *http.Request) {

// 	fmt.Fprint(w, out)
// }

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
	Timestamp     time.Time `json:"timestamp"`
	Matched       bool      `json:"matched"`
	Error         bool      `json:"error"`
	Background    string    `json:"background"`
	From          string    `json:"from"`
	ID            string    `json:"id"`
	AttrCount     int       `json:"attr_count"`
	Link          string    `json:"link"`
	ThreatLevelID string    `json:"threat_level_id"`
	Value         string    `json:"value"`
	Info          string    `json:"info"`
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
