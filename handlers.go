package main

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"path/filepath"
	"sort"
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
	Blob     string `json:"blob"`
	Username string `json:"username"`
}

type LogRequest struct {
	Username string `json:"username"`
	Message  string `json:"message"`
}

func (s *Server) LogHandler(w http.ResponseWriter, r *http.Request) {
	// defer s.addStat("log_requests", 1)
	var lr LogRequest
	err := json.NewDecoder(r.Body).Decode(&lr)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if lr.Username == "" || lr.Message == "" {
		http.Error(w, "missing 'username' or 'message' field", http.StatusBadRequest)
		return
	}
	info := fmt.Sprintf("%s: %s", lr.Username, lr.Message)
	s.LogInfo(info)
	w.Write([]byte("ok"))
}

func (s *Server) ParserHandler(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	var wg sync.WaitGroup
	allBytes := []byte{'['}
	first := true
	var mu sync.Mutex
	// defer s.addStat("parser_requests", 1)
	cx := parser.NewContextualizer(&parser.PrivateChecks{Ipv4: true})
	var pr ParserRequest
	err := json.NewDecoder(r.Body).Decode(&pr)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	defer func(start time.Time, req ParserRequest) {
		reqOut, err := json.Marshal(req)
		if err != nil {
			s.Log.Println("ProxyHandler error", err)
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		s.Log.Println("__ProxyHandler__ took:", time.Since(start), req.Username, string(reqOut))
	}(start, pr)
	out := make(map[string][]parser.Match)
	for k, v := range cx.Expressions {
		out[k] = cx.GetMatches(pr.Blob, k, v)
	}
	promptRequest := PromptRequest{
		TransactinID: uuid.New().String(),
		MatchList:    make([]interface{}, 0),
		Mu:           &sync.RWMutex{},
	}
	for k, v := range out {
		for _, svc := range s.Details.SupportedServices {
			for _, t := range svc.Type {
				if t == k && len(v) > 0 {
					// if svc.RateLimited {
					// 	continue
					// }
					for _, value := range v {
						var proxyReq ProxyRequest
						if len(svc.RouteMap) > 0 {
							for _, rm := range svc.RouteMap {
								if rm.Type == k {
									proxyReq.Route = rm.Route
								}
							}
						}
						proxyReq.To = svc.Kind
						proxyReq.Type = k
						proxyReq.Value = value.Value
						proxyReq.Username = pr.Username
						proxyReq.FQDN = s.Details.FQDN
						proxyReq.From = "api parser"
						uid := uuid.New().String()
						proxyReq.TransactionID = uid
						wg.Add(1)
						go func(name string, id string, first *bool, proxyReq ProxyRequest) {
							defer wg.Done()
							op, ok := s.ProxyOperators[name]
							if !ok {
								fmt.Println("no operator for service", name)
								return
							}
							ep, ok := s.Targets[name]
							if !ok {
								fmt.Println("no endpoint for service", name)
								return
							}
							out, err := op(s.RespCh, *ep, proxyReq)
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
							s.RespCh <- ResponseItem{
								ID:     id,
								Vendor: name,
								Data:   out,
								Time:   time.Now(),
							}
							go s.DB.StoreResponse(false, id, out, proxyReq.To)
							var se SummarizedEvent
							err = json.Unmarshal(out, &se)
							if err != nil {
								fmt.Println("error unmarshaling response", err)
								return
							}
							if se.Matched {
								var tmp struct {
									Info  string `json:"info"`
									Value string `json:"value"`
									Score int    `json:"score"`
								}
								tmp.Info = se.Info
								tmp.Value = se.Value
								tmp.Score = se.ThreatLevelID
								// promptRequest.Mu.Lock()
								promptRequest.Mu.Lock()
								promptRequest.MatchList = append(promptRequest.MatchList, tmp)
								promptRequest.Mu.Unlock()
							}
						}(svc.Kind, uid, &first, proxyReq)
					}
				}
			}
		}
	}
	wg.Wait()
	allBytes = append(allBytes, ']')
	w.Header().Set("Content-Type", "application/json")
	w.Write(allBytes)
	var logIt bool
	fullPrompt, _ := promptRequest.BuildJSONPrompt()
	email, ok := r.Context().Value("email").(string)
	if !ok {
		logIt = true
	}
	s.RespCh <- ResponseItem{
		Log:    logIt,
		Email:  email,
		ID:     promptRequest.TransactinID,
		Notify: true,
		Data:   fullPrompt,
		Time:   time.Now(),
		Vendor: "llm_tools",
	}
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

func (s *Server) GetStatsHandler(w http.ResponseWriter, r *http.Request) {
	// defer s.addStat("get_stat_history_requests", 1)
	defer func(start time.Time) {
		s.Log.Println("GetStatsHandler took", time.Since(start))
	}(time.Now())
	s.Memory.RLock()
	defer s.Memory.RUnlock()
	out, err := json.Marshal(s.Details.Stats)
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
	start := time.Now()
	err := json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		s.Log.Println("ProxyHandler decoder error", err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	uid := uuid.New().String()
	req.TransactionID = uid
	req.FQDN = s.Details.FQDN
	defer func(start time.Time, req ProxyRequest) {
		reqOut, err := json.Marshal(req)
		if err != nil {
			s.Log.Println("ProxyHandler error", err)
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		s.Log.Println("__ProxyHandler__ took:", time.Since(start), req.Username, string(reqOut))
	}(start, req)
	// s.Log.Println("ProxyHandler", req)
	s.Memory.RLock()
	defer s.Memory.RUnlock()
	op, ok := s.ProxyOperators[req.To]
	if !ok {
		s.Log.Printf("no proxy operator for service %s, skipping", req.To)
		http.Error(w, fmt.Sprintf("no proxy operator for service %s", req.To), http.StatusBadRequest)
		return
	}
	ep, ok := s.Targets[req.To]
	if !ok {
		s.Log.Printf("no endpoint for service %s, skipping", req.To)
		http.Error(w, fmt.Sprintf("no endpoint for service %s", req.To), http.StatusBadRequest)
		return
	}
	resp, err := op(s.RespCh, *ep, req)
	if err != nil {
		r, err := CreateAndWriteSummarizedEvent(req, true, fmt.Sprintf("error: %v", err))
		if err != nil {
			s.Log.Println("bigtime error", err)
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		// cant remember why we dont call storeresponse here
		w.Write(r)
		return
	}
	w.Write(resp)
}

func (s *Server) EventHandler(w http.ResponseWriter, r *http.Request) {
	// defer s.addStat("event_requests", 1)
	pathPrefix := "/events/"
	if !strings.HasPrefix(r.URL.Path, pathPrefix) {
		http.Error(w, "invalid path", http.StatusBadRequest)
		return
	}
	id := r.URL.Path[len(pathPrefix):]
	if _, err := uuid.Parse(id); err != nil {
		http.Error(w, "invalid id", http.StatusBadRequest)
		return
	}
	// s.Log.Println("EventHandler", id)
	s.Memory.Lock()
	defer s.Memory.Unlock()
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
	// pretty print logic
	var generic any
	err := json.Unmarshal(event.Data, &generic)
	if err != nil {
		w.Write(event.Data)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	pretty, err := json.MarshalIndent(generic, "", "  ")
	if err != nil {
		s.Log.Println("error pretty printing event", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	if len(pretty) == 0 {
		w.Write([]byte("no data for this event, but a record exists"))
	}
	w.Write(pretty)
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
			RouteMap:      svc.RouteMap,
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
	var u User
	var err error
	parts := strings.Split(r.Header.Get("Authorization"), ":")
	email := parts[0]
	u, err = s.DB.GetUserByEmail(email)
	if err != nil {
		tkn, err := s.GetTokenFromSession(r)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		if tkn != "" {
			tk, e := s.DB.GetTokenByValue(tkn)
			if e != nil {
				http.Error(w, e.Error(), http.StatusInternalServerError)
				return
			}
			u, err = s.DB.GetUserByEmail(tk.Email)
			if err != nil {
				fmt.Println("Error getting user by email:", err, u, tkn)
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
		}
	}
	u.Hash = nil
	// u.Key = ""
	u.Password = ""
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
	s.CleanUserServices(&u)
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

func (s *Server) RectifyServicesHandler(w http.ResponseWriter, r *http.Request) {
	parts := strings.Split(r.Header.Get("Authorization"), ":")
	email := parts[0]
	u, err := s.DB.GetUserByEmail(email)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	s.CleanUserServices(&u)
	err = s.DB.AddUser(u)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	out := `{"status": "ok", "message": "services rectified for user ` + email + `"}`
	w.Write([]byte(out))
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

func (s *Server) ArchiveResponseHandler(w http.ResponseWriter, r *http.Request) {
	var req RawResponseRequest
	err := json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	res, err := s.DB.GetResponses(time.Now().Add(-(24 * 30) * time.Hour))
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	for _, r := range res {
		if r.ID == req.ID {
			s.Log.Println("Archiving response", r.ID, r.Vendor)
			err = s.DB.StoreResponse(true, r.ID, r.Data, r.Vendor)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
		}
	}
	w.Write([]byte(`{"status": "ok"}`))
}

// TODO should use summarized event here i think. will have to handle mutliple ids perhaps idk
func (s *Server) UploadFileHandler(w http.ResponseWriter, r *http.Request) {
	var fileData bytes.Buffer
	var UploadResponse SummarizedEvent
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
	safeFilename := filepath.Base(filename)

	newFile, err := RemoveTimestamp("_", safeFilename)
	if err != nil {
		fmt.Println("error removing timestamp", err)
		// http.Error(w, err.Error(), http.StatusInternalServerError)
		// return
	}
	if newFile != "" {
		filename = newFile
	}

	lastChunk := r.Header.Get("X-last-chunk")
	// fmt.Println(chunkSize, filename, lastChunk)
	uploadHanlder, ok := store.GetFile(filename)
	uid := uuid.New().String()
	if !ok {
		uploadHanlder = UploadHandler{
			ID:       uid,
			Data:     fileData.Bytes(),
			FileSize: chunkSize,
		}
		go store.AddFile(filename, uploadHanlder)
	} else {
		uid = uploadHanlder.ID
		uploadHanlder.Data = append(uploadHanlder.Data, fileData.Bytes()...)
		uploadHanlder.FileSize += chunkSize
	}

	if lastChunk == "true" {
		tkn, err := s.GetTokenFromSession(r)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		tk, err := s.DB.GetTokenByValue(tkn)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		u, err := s.DB.GetUserByEmail(tk.Email)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		uploadHanlder.Complete = true
		uploadHanlder.For = u.Email

	}

	store.AddFile(filename, uploadHanlder)

	if uploadHanlder.Complete {
		copiedTargets := make(map[string]*Endpoint)
		s.Memory.RLock()
		for k, v := range s.Targets {
			if v.UploadService {
				copiedTargets[k] = v
			}
		}
		s.Memory.RUnlock()

		go func() {
			store.FanOut(s.RespCh, filename, copiedTargets, uid)
			store.DeleteFile(filename)
		}()
		UploadResponse.ID = uid
		UploadResponse.Link = uid
		UploadResponse.Info = fmt.Sprintf("File %s uploaded successfully with ID %s", filename, uid)
		info := fmt.Sprintf("%v: File %s uploaded with ID %s", uid, filename, uid)
		s.LogInfo(info)
	}
	out, err := json.Marshal(UploadResponse)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Write(out)
}

func (s *Server) GetCoordinateHandler(w http.ResponseWriter, r *http.Request) {
	s.Memory.RLock()
	defer s.Memory.RUnlock()
	coord, err := json.Marshal(s.Cache.Coordinates)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Write(coord)
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
	out := LogItemsToPanel(chunk)

	fmt.Fprint(w, out)
}

func (s *Server) BackupHandler(w http.ResponseWriter, r *http.Request) {
	user := r.Context().Value("email").(string)
	s.LogInfo(fmt.Sprintf("%v requested a backup", user))
	u, err := s.DB.GetUserByEmail(user)
	if err != nil {
		http.Error(w, "error retrieving user info", http.StatusInternalServerError)
		return
	}
	if !u.Admin {
		http.Error(w, "only admin users can request backups", http.StatusForbidden)
		return
	}

	// Set response headers *before* writing any data
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Encoding", "gzip")

	// Create a dynamic filename
	filename := fmt.Sprintf("threatco_backup_%s.sql.gz", time.Now().Format("2006-01-02_150405"))
	w.Header().Set("Content-Disposition", "attachment; filename=\""+filename+"\"")

	// Create a gzip writer that writes to the http.ResponseWriter
	gz := gzip.NewWriter(w)
	defer gz.Close()

	// Pass the gzip writer to your Backup function
	err = s.DB.Backup(gz)
	if err != nil {
		// IMPORTANT: If the backup fails mid-stream, the headers
		// are already sent, so we can't send a clean http.Error.
		// We log the error here for server-side debugging.
		s.Log.Printf("ERROR during backup stream: %v", err)
		return
	}

	s.LogInfo("Backup stream completed successfully.")
}

// bump
func (s *Server) GetLogsHandler(w http.ResponseWriter, r *http.Request) {
	var MaxLogs = 1000
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
	if end-start > MaxLogs {
		end = start + MaxLogs
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

type ResponseCacheRequest struct {
	TotalResponses int `json:"total_responses"`
	Start          int `json:"start"`
	End            int `json:"end"`
}

func (s *Server) GetResponseCacheHandler(w http.ResponseWriter, r *http.Request) {
	var out string
	table := `<table class="table is-fullwidth is-striped">
			<thead>
				<tr>
					<th>time</th>
					<th>vendor</th>
					<th>link</th>
				</tr>
			</thead>
			<tbody>
				%v
			</tbody>
		</table>`
	tmpl := `<tr>
		<td>%v</td>
		<td>%v</td>
		<td><a href="/events/%v">%v</a></td>
	</tr>`
	s.Memory.RLock()
	defer s.Memory.RUnlock()
	responses, err := s.DB.GetResponses(time.Now().Add(-24 * time.Hour))
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if len(responses) == 0 {
		fmt.Fprint(w, "No responses in cache")
		return
	}
	sort.Slice(responses, func(i, j int) bool {
		return responses[i].Time.After(responses[j].Time)
	})
	if len(responses) > 100 {
		responses = responses[:100]
	}
	for _, v := range responses {
		out += fmt.Sprintf(tmpl, v.Time, v.Vendor, v.ID, v.ID)
	}
	out = fmt.Sprintf(table, out)
	fmt.Fprint(w, out)
}

// ResponseFilterOptions defines the available query parameters for filtering and pagination.
type ResponseFilterOptions struct {
	Vendor string
	Start  int
	Limit  int
}

// NewResponseFilterOptions creates a new options object from the request's query parameters.
// It sets sensible defaults for pagination.
func NewResponseFilterOptions(r *http.Request) (*ResponseFilterOptions, error) {
	opts := &ResponseFilterOptions{
		Vendor: r.URL.Query().Get("vendor"),
		Start:  0,
		Limit:  100, // Default limit
	}

	// Parse 'start' query parameter
	startStr := r.URL.Query().Get("start")
	if startStr != "" {
		start, err := strconv.Atoi(startStr)
		if err != nil {
			return nil, fmt.Errorf("invalid 'start' parameter: must be an integer")
		}
		if start < 0 {
			return nil, fmt.Errorf("invalid 'start' parameter: must be non-negative")
		}
		opts.Start = start
	}

	// Parse 'limit' query parameter
	limitStr := r.URL.Query().Get("limit")
	if limitStr != "" {
		limit, err := strconv.Atoi(limitStr)
		if err != nil {
			return nil, fmt.Errorf("invalid 'limit' parameter: must be an integer")
		}
		if limit < 0 {
			return nil, fmt.Errorf("invalid 'limit' parameter: must be non-negative")
		}
		opts.Limit = limit
	}

	return opts, nil
}

// GetResponseCacheHandler handles requests for viewing cached responses.
// It now supports filtering by vendor and pagination using 'start' and 'limit' query parameters.
// Example URL: /responses?vendor=some_vendor&start=0&limit=50
func (s *Server) GetResponseCacheHandler2(w http.ResponseWriter, r *http.Request) {
	// Add headers to prevent caching by clients.
	// This ensures that the user's browser will always fetch the latest data.
	w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate") // HTTP 1.1.
	w.Header().Set("Pragma", "no-cache")                                   // HTTP 1.0.
	w.Header().Set("Expires", "0")                                         // Proxies.

	// Parse filter and pagination options from query parameters
	options, err := NewResponseFilterOptions(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	s.Memory.RLock()
	defer s.Memory.RUnlock()

	// 1. Fetch all responses from the last 24 hours
	responses, err := s.DB.GetResponses(time.Now().Add(-24 * time.Hour))
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	if len(responses) == 0 {
		fmt.Fprint(w, "No responses in cache for the last 24 hours.")
		return
	}

	// 2. Sort all responses by time (most recent first)
	sort.Slice(responses, func(i, j int) bool {
		return responses[i].Time.After(responses[j].Time)
	})

	// 3. Apply Vendor Filter
	var filteredResponses []ResponseItem
	if options.Vendor != "" {
		for _, v := range responses {
			if v.Vendor == options.Vendor {
				filteredResponses = append(filteredResponses, v)
			}
		}
	} else {
		// If no vendor is specified, use the whole list
		filteredResponses = responses
	}

	if len(filteredResponses) == 0 {
		fmt.Fprintf(w, "No responses found for vendor: %s", options.Vendor)
		return
	}

	// 4. Apply Slicing/Pagination
	var paginatedResponses []ResponseItem
	start := options.Start
	end := options.Start + options.Limit

	if start >= len(filteredResponses) {
		fmt.Println("Start index is out of bounds, returning empty set.")
		// If the start index is out of bounds, return an empty set
		paginatedResponses = []ResponseItem{}
	} else {
		// Ensure the end index does not go out of bounds
		if end > len(filteredResponses) {
			end = len(filteredResponses)
		}
		paginatedResponses = filteredResponses[start:end]
	}

	// 5. Render the final list as an HTML table
	var out string
	table := `<table class="table is-fullwidth is-striped">
            <thead>
                <tr>
                    <th>time</th>
                    <th>vendor</th>
                    <th>link</th>
                </tr>
            </thead>
            <tbody>
                %v
            </tbody>
        </table>`
	tmpl := `<tr>
        <td>%v</td>
        <td>%v</td>
        <td><a href="/events/%v">%v</a></td>
    </tr>`

	for _, v := range paginatedResponses {
		out += fmt.Sprintf(tmpl, v.Time.Format(time.RFC3339), v.Vendor, v.ID, v.ID)
	}

	if out == "" {
		fmt.Fprint(w, "No results for the specified page/filter.")
		return
	}

	out = fmt.Sprintf(table, out)
	fmt.Fprint(w, out)
}

type previousResponseQuery struct {
	Start string `json:"start"`
	End   string `json:"end"`
	Value string `json:"value"`
}

func (s *Server) GetPreviousResponsesHandler(w http.ResponseWriter, r *http.Request) {
	var matches []SummarizedEvent
	defer func(start time.Time) {
		s.Log.Println("GetPreviousResponsesHandler took", time.Since(start))
	}(time.Now())
	s.Memory.RLock()
	defer s.Memory.RUnlock()
	var prq previousResponseQuery
	fmt.Println("GetPreviousResponsesHandler called")
	err := json.NewDecoder(r.Body).Decode(&prq)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if prq.Value == "" {
		http.Error(w, "missing 'value' field", http.StatusBadRequest)
		return
	}
	fmt.Println("GetPreviousResponsesHandler value", prq.Value)
	// Get all responses from the last 144 hours (6 days)
	responses, err := s.DB.GetResponses(time.Now().Add(-144 * time.Hour))
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if len(responses) == 0 {
		s.Log.Println("GetPreviousResponsesHandler no responses in cache")
		fmt.Fprint(w, "No responses in cache")
		return
	}

	// --- MODIFIED LOGIC ---
	// Iterate through the responses from the database.
	for _, v := range responses {
		// The error "cannot unmarshal array into Go value of type main.ProxyRequest"
		// indicates the data is a nested array, e.g., [[...], ...].
		// We need to unmarshal the outer array first.
		var outerSlice []json.RawMessage
		err := json.Unmarshal(v.Data, &outerSlice)
		if err != nil {
			s.Log.Printf("error unmarshaling outer slice for ID %s: %v", v.ID, err)
			continue
		}

		if len(outerSlice) == 0 {
			s.Log.Printf("outer response data slice is empty for ID %s", v.ID)
			continue
		}

		// Now unmarshal the first element of the outer slice, which we expect
		// to be the inner array containing the ProxyRequest.
		var innerSlice []json.RawMessage
		err = json.Unmarshal(outerSlice[0], &innerSlice)
		if err != nil {
			// This will catch the error if the first element is not an array.
			s.Log.Printf("error unmarshaling inner slice for ID %s: %v", v.ID, err)
			continue
		}

		if len(innerSlice) == 0 {
			s.Log.Printf("inner response data slice is empty for ID %s", v.ID)
			continue
		}

		// Finally, unmarshal the first element of the inner slice into the ProxyRequest struct.
		var originalProxyRequest ProxyRequest
		err = json.Unmarshal(innerSlice[0], &originalProxyRequest)
		if err != nil {
			s.Log.Printf("error unmarshaling ProxyRequest from inner slice for ID %s: %v", v.ID, err)
			continue
		}

		s.Log.Println("GetPreviousResponsesHandler checking", originalProxyRequest.Value, "against", prq.Value)
		if originalProxyRequest.Value == prq.Value {
			matches = append(matches, SummarizedEvent{
				Timestamp:  v.Time,
				Matched:    true,
				Error:      false,
				Background: "has-background-warning",
				From:       originalProxyRequest.Username,
				ID:         v.ID,
				AttrCount:  len(innerSlice),
				Link:       v.ID,
				Value:      originalProxyRequest.Value,
				Info:       fmt.Sprintf("%v: Matched value %s in response ID %s", originalProxyRequest.Username, originalProxyRequest.Value, v.ID),
			})
		}
	}
	// --- END MODIFIED LOGIC ---

	out, err := json.Marshal(matches)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	s.Log.Println("GetPreviousResponsesHandler matches", len(matches), "for value", prq.Value)
	w.Header().Set("Content-Type", "application/json")
	w.Write(out)
}

type NottyRequest struct {
	To      string    `json:"to"`
	From    string    `json:"from"`
	Info    string    `json:"info"`
	Error   bool      `json:"error"`
	Created time.Time `json:"created"`
}

func (s *Server) SendTestNotificationHandler(w http.ResponseWriter, r *http.Request) {
	var req NottyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	// Simulate sending a notification
	s.Log.Printf("Sending test notification to %s from %s: %s", req.To, req.From, req.Info)
	if req.To == "" || req.From == "" {
		http.Error(w, "Missing required fields", http.StatusBadRequest)
		return
	}
	info := fmt.Sprintf("Test notification from %s to %s: %s", req.From, req.To, req.Info)
	notification := Notification{
		Info:    info,
		Error:   req.Error,
		Created: time.Now(),
	}
	s.Hub.SendToUser(s.RespCh, req.To, notification)
	json.NewEncoder(w).Encode(map[string]string{"status": "notification sent"})
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
	FQDN          string `json:"fqdn"`
	To            string `json:"to"`
	Route         string `json:"route"`
	Type          string `json:"type"`
	Value         string `json:"value"`
	From          string `json:"from"`
	TransactionID string `json:"transaction_id"`
	Username      string `json:"username"`
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
	ThreatLevelID int       `json:"threat_level_id"`
	Value         string    `json:"value"`
	Info          string    `json:"info"`
	RawLink       string    `json:"raw_link"`
	Type          string    `json:"type"`
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
