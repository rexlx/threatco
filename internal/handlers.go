package internal

import (
	"archive/zip"
	"bytes"
	"compress/gzip"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"html"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/rexlx/threatco/optional"
	"github.com/rexlx/threatco/parser"
	"github.com/rexlx/threatco/vendors"
	"golang.org/x/crypto/ssh"
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
	ignoreList := []string{"nullferatu.com"}
	var mu sync.Mutex
	cx := parser.NewContextualizer(true, ignoreList, ignoreList)

	var pr ParserRequest
	if err := json.NewDecoder(r.Body).Decode(&pr); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	defer func(start time.Time, req ParserRequest) {
		reqOut, _ := json.Marshal(req)
		s.Log.Println("__ProxyHandler__ took:", time.Since(start), req.Username, string(reqOut))
	}(start, pr)

	email, ok := r.Context().Value("email").(string)
	logIt := !ok
	out := cx.ExtractAll(pr.Blob)

	// Deduplicate unique values for efficient batch history recording
	uniqueValues := make([]string, 0)
	seen := make(map[string]struct{})
	for _, results := range out {
		for _, res := range results {
			if _, exists := seen[res.Value]; !exists {
				seen[res.Value] = struct{}{}
				uniqueValues = append(uniqueValues, res.Value)
			}
		}
	}

	// Record all search history in a single batch operation
	if email != "" && len(uniqueValues) > 0 {
		go func(vals []string, user string) {
			if err := s.DB.RecordSearchBatch(vals, user); err != nil {
				s.Log.Printf("Batch search history update failed: %v", err)
			}
		}(uniqueValues, email)
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
						go func(name string, id string, firstPtr *bool, req ProxyRequest) {
							defer wg.Done()
							op, ok := s.ProxyOperators[name]
							ep, ok2 := s.Targets[name]
							if !ok || !ok2 {
								return
							}

							out, err := op(s.RespCh, *ep, req)
							if err != nil || len(out) == 0 {
								return
							}

							mu.Lock()
							if !*firstPtr {
								allBytes = append(allBytes, ',')
							}
							allBytes = append(allBytes, out...)
							*firstPtr = false
							mu.Unlock()

							// StoreResponse is removed; handled by ProcessTransientResponses via RespCh
							s.RespCh <- ResponseItem{
								ID:     id,
								Vendor: name,
								Data:   out,
								Time:   time.Now(),
							}

							var se SummarizedEvent
							if err := json.Unmarshal(out, &se); err == nil && se.Matched {
								promptRequest.Mu.Lock()
								promptRequest.MatchList = append(promptRequest.MatchList, struct {
									Info  string `json:"info"`
									Value string `json:"value"`
									Score int    `json:"score"`
								}{se.Info, se.Value, se.ThreatLevelID})
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

	fullPrompt, _ := promptRequest.BuildJSONPrompt(optional.LlmToolsBasicPrompt)
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

func (s *Server) ParseFileHandler(w http.ResponseWriter, r *http.Request) {
	// Limit upload size to 10MB to prevent memory exhaustion
	r.ParseMultipartForm(10 << 20)

	file, _, err := r.FormFile("file")
	if err != nil {
		http.Error(w, "Error retrieving file from request", http.StatusBadRequest)
		return
	}
	defer file.Close()

	var buf bytes.Buffer
	if _, err := io.Copy(&buf, file); err != nil {
		http.Error(w, "Error reading file content", http.StatusInternalServerError)
		return
	}

	content := buf.String()

	domains := []string{"nullferatu.com"}
	cx := parser.NewContextualizer(true, domains, domains)
	out := cx.ExtractAll(content)

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(out); err != nil {
		s.Log.Println("Error encoding parse results:", err)
	}
}

// ... existing handlers ...

// --- CASE HANDLERS ---

func (s *Server) CreateCaseHandler(w http.ResponseWriter, r *http.Request) {
	var c Case
	if err := json.NewDecoder(r.Body).Decode(&c); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Auth context
	email := r.Context().Value("email").(string)

	c.ID = uuid.New().String()
	c.CreatedBy = email
	c.CreatedAt = time.Now()
	c.Status = "Open"
	if c.IOCs == nil {
		c.IOCs = []string{}
	}
	if c.Comments == nil {
		c.Comments = []Comment{}
	}

	if err := s.DB.CreateCase(c); err != nil {
		s.Log.Println("Error creating case:", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	s.LogInfo(fmt.Sprintf("User %s created case: %s", email, c.Name))

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(c)
}

func (s *Server) GetCasesHandler(w http.ResponseWriter, r *http.Request) {
	// 1. Parse 'limit' (default to 50)
	limit := 50
	if l := r.URL.Query().Get("limit"); l != "" {
		if val, err := strconv.Atoi(l); err == nil && val > 0 {
			limit = val
		}
	}

	// 2. Parse 'page' (default to 1) to calculate offset
	page := 1
	if p := r.URL.Query().Get("page"); p != "" {
		if val, err := strconv.Atoi(p); err == nil && val > 0 {
			page = val
		}
	}
	offset := (page - 1) * limit

	// 3. Call DB with pagination
	cases, err := s.DB.GetCases(limit, offset)
	if err != nil {
		s.Log.Println("Error getting cases:", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(cases)
}

func (s *Server) DeleteCaseHandler(w http.ResponseWriter, r *http.Request) {
	// Parse ID from JSON body
	var req struct {
		ID string `json:"id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	if req.ID == "" {
		http.Error(w, "missing case id", http.StatusBadRequest)
		return
	}

	if err := s.DB.DeleteCase(req.ID); err != nil {
		s.Log.Println("Error deleting case:", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	s.LogInfo(fmt.Sprintf("Case %s deleted by %s", req.ID, r.Context().Value("email")))
	w.Write([]byte(`{"status":"deleted"}`))
}

func (s *Server) GetCaseHandler(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	if id == "" {
		http.Error(w, "missing id", http.StatusBadRequest)
		return
	}
	c, err := s.DB.GetCase(id)
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(c)
}

func (s *Server) UpdateCaseHandler(w http.ResponseWriter, r *http.Request) {
	// We expect the payload to contain the full updated case state or partial logic here.
	// For simplicity, we accept the struct with the ID.
	var incoming Case
	if err := json.NewDecoder(r.Body).Decode(&incoming); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	if incoming.ID == "" {
		http.Error(w, "missing case id", http.StatusBadRequest)
		return
	}

	// Fetch existing to ensure ownership or valid ID (optional checks skipped for brevity)
	existing, err := s.DB.GetCase(incoming.ID)
	if err != nil {
		http.Error(w, "Case not found", http.StatusNotFound)
		return
	}

	// Merge updates
	// If incoming has new comments (we assume frontend sends the NEW comment to append, or the whole list)
	// Strategy: Frontend sends the delta or specific action.
	// Let's assume the frontend sends the *whole* updated object for IOCs,
	// but maybe we handle comments specially?
	// Let's trust the frontend sends the complete updated fields for now.

	existing.Status = incoming.Status
	existing.Description = incoming.Description
	existing.IOCs = incoming.IOCs
	existing.Comments = incoming.Comments // Overwrite strategy

	if err := s.DB.UpdateCase(existing); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Write([]byte(`{"status":"ok"}`))
}

// Add to internal/handlers.go

func (s *Server) ToolsInspectArchiveHandler(w http.ResponseWriter, r *http.Request) {
	// 1. Increase limit to 500MB for this specific handler
	// We use MaxBytesReader to prevent the server from accepting infinite streams
	const MaxArchiveSize = 500 * 1024 * 1024 // 500MB
	r.Body = http.MaxBytesReader(w, r.Body, MaxArchiveSize)

	// 2. Stream directly to a Temp File (Avoids loading 500MB into RAM)
	// "multipart/form-data" usually requires parsing, but we can iterate the parts
	// to find the file and stream it.
	// Standard ParseMultipartForm spills to disk anyway, but this gives us control.
	reader, err := r.MultipartReader()
	if err != nil {
		http.Error(w, "Upload error: "+err.Error(), http.StatusBadRequest)
		return
	}

	// Prepare response structure
	type FileInfo struct {
		Name       string `json:"name"`
		Size       uint64 `json:"size"`
		Compressed uint64 `json:"compressed_size"`
		SHA256     string `json:"sha256"`
		Suspicious bool   `json:"suspicious"`
		Warning    string `json:"warning"`
	}
	var results []FileInfo

	for {
		part, err := reader.NextPart()
		if err == io.EOF {
			break
		}
		if err != nil {
			http.Error(w, "Read error", http.StatusInternalServerError)
			return
		}

		// We only care about the form field named "file"
		if part.FormName() == "file" {
			// Create a temp file that is NOT accessible via web
			tmpFile, err := os.CreateTemp("", "threatco-inspect-*.zip")
			if err != nil {
				http.Error(w, "Temp file creation failed", http.StatusInternalServerError)
				return
			}
			// CRITICAL: Ensure file is deleted when function exits
			defer os.Remove(tmpFile.Name())
			defer tmpFile.Close()

			// Stream upload to the temp file
			size, err := io.Copy(tmpFile, part)
			if err != nil {
				http.Error(w, "Stream copy failed", http.StatusInternalServerError)
				return
			}

			// 3. Open the Temp File as a Zip Reader
			// usage of archive/zip requires ReaderAt, which os.File provides
			zReader, err := zip.NewReader(tmpFile, size)
			if err != nil {
				// If it fails to parse, it might not be a zip or is corrupted
				http.Error(w, "Invalid ZIP archive: "+err.Error(), http.StatusBadRequest)
				return
			}

			// 4. Inspect Contents safely
			for _, zf := range zReader.File {
				info := FileInfo{
					Name:       zf.Name,
					Size:       zf.UncompressedSize64,
					Compressed: zf.CompressedSize64,
					Suspicious: false,
				}

				// Check 1: Zip Slip (Directory Traversal)
				if strings.Contains(zf.Name, "..") {
					info.Suspicious = true
					info.Warning = "Potential Zip Slip (path traversal)"
				}

				// Check 2: Zip Bomb (Compression Ratio)
				// Ratio > 100x and size > 10MB is suspicious
				if zf.CompressedSize64 > 0 {
					ratio := float64(zf.UncompressedSize64) / float64(zf.CompressedSize64)
					if ratio > 100 && zf.UncompressedSize64 > (10*1024*1024) {
						info.Suspicious = true
						info.Warning = fmt.Sprintf("High compression ratio (%.0fx)", ratio)
					}
				}

				// Check 3: Absolute Paths
				if filepath.IsAbs(zf.Name) {
					info.Suspicious = true
					info.Warning = "Absolute path detected"
				}

				// Calculate Hash (Safe Streaming)
				if !zf.FileInfo().IsDir() {
					// Only hash if not suspiciously huge to avoid DoS on the hasher
					if info.Suspicious && info.Size > (100*1024*1024) {
						info.SHA256 = "SKIPPED_DUE_TO_RISK"
					} else {
						rc, err := zf.Open()
						if err == nil {
							hasher := sha256.New()
							// Limit hashing to first 100MB to preserve server resources
							// If a file is 10GB, we don't want to spend CPU hashing it all
							limitReader := io.LimitReader(rc, 100*1024*1024)
							if _, err := io.Copy(hasher, limitReader); err == nil {
								info.SHA256 = hex.EncodeToString(hasher.Sum(nil))
								if zf.UncompressedSize64 > 100*1024*1024 {
									info.SHA256 += " (partial)"
								}
							}
							rc.Close()
						}
					}
				}

				results = append(results, info)
			}
			// We only process one file
			break
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(results)
}

// Add to internal/handlers.go imports:
// "crypto/x509"
// "encoding/pem"
// "golang.org/x/crypto/ssh"

func (s *Server) ToolsGenerateSSHKeyHandler(w http.ResponseWriter, r *http.Request) {
	keyType := r.URL.Query().Get("type") // "rsa" or "ecdsa"

	var privKeyPEM []byte
	var pubKeySSH []byte

	if keyType == "ecdsa" {
		privateKey, _ := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
		b, _ := x509.MarshalECPrivateKey(privateKey)
		privKeyPEM = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: b})
		publicKey, _ := ssh.NewPublicKey(&privateKey.PublicKey)
		pubKeySSH = ssh.MarshalAuthorizedKey(publicKey)
	} else {
		// Default to RSA 4096
		privateKey, _ := rsa.GenerateKey(rand.Reader, 4096)
		privKeyPEM = pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(privateKey)})
		publicKey, _ := ssh.NewPublicKey(&privateKey.PublicKey)
		pubKeySSH = ssh.MarshalAuthorizedKey(publicKey)
	}

	resp := map[string]string{
		"private": string(privKeyPEM),
		"public":  string(pubKeySSH),
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
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
	if nur.Admin == "on" || nur.Admin == "true" {
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
	enc, err := s.Encrypt(user.Key)
	if err != nil {
		s.Log.Println("error", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	tmp := user.Key
	user.Key = enc
	err = s.DB.AddUser(*user)
	if err != nil {
		s.Log.Println("error", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		// s.Memory.Unlock()
		return
	}
	user.Key = tmp
	// s.Memory.Unlock()
	out, err := json.Marshal(user)
	if err != nil {
		s.Log.Println("error", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Write(out)
}

func (s *Server) NewApiKeyGeneratorHandler(w http.ResponseWriter, r *http.Request) {
	email := r.Context().Value("email").(string)
	user, err := s.DB.GetUserByEmail(email)
	if err != nil {
		fmt.Println("error getting user by email:", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	err = user.UpdateApiKey()
	if err != nil {
		fmt.Println("error updating api key:", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	enc, err := s.Encrypt(user.Key)
	if err != nil {
		s.Log.Println("error", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	tmp := user.Key
	user.Key = enc
	err = s.DB.AddUser(user)
	if err != nil {
		s.Log.Println("error", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		// s.Memory.Unlock()
		return
	}
	user.Key = tmp
	out, err := json.Marshal(user)
	if err != nil {
		s.Log.Println("error", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Write(out)
}

type GenerateAPIKeyRequest struct {
	Email string `json:"email"`
}

func (s *Server) GenerateAPIKeyHandler(w http.ResponseWriter, r *http.Request) {
	var gar GenerateAPIKeyRequest
	err := json.NewDecoder(r.Body).Decode(&gar)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	user, err := s.DB.GetUserByEmail(gar.Email)
	if err != nil {
		fmt.Println("error getting user by email:", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	err = user.UpdateApiKey()
	if err != nil {
		fmt.Println("error updating user API key:", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	enc, err := s.Encrypt(user.Key)
	if err != nil {
		s.Log.Println("error", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	tmp := user.Key
	user.Key = enc
	err = s.DB.AddUser(user)
	if err != nil {
		s.Log.Println("error", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		// s.Memory.Unlock()
		return
	}
	user.Key = tmp
	out, err := json.Marshal(user)
	if err != nil {
		s.Log.Println("error", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Write(out)
}

func (s *Server) ProxyHandler(w http.ResponseWriter, r *http.Request) {
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
			s.Log.Println("ProxyHandler marshal error", err)
			return
		}
		s.Log.Println("__ProxyHandler__ took:", time.Since(start), req.Username, string(reqOut))
	}(start, req)

	s.Memory.RLock()
	op, ok := s.ProxyOperators[req.To]
	ep, ok2 := s.Targets[req.To]
	s.Memory.RUnlock()

	if !ok || !ok2 {
		msg := fmt.Sprintf("service %s not found or has no operator", req.To)
		s.Log.Println(msg)
		http.Error(w, msg, http.StatusBadRequest)
		return
	}

	// Execute the vendor-specific proxy operator
	resp, err := op(s.RespCh, *ep, req)
	if err != nil {
		// Create a failure event to return to the UI
		failResp, _ := CreateAndWriteSummarizedEvent(req, true, fmt.Sprintf("error: %v", err))
		w.Write(failResp)
		return
	}

	// Centralize search history recording using the new batch method
	email, _ := r.Context().Value("email").(string)
	if email != "" && req.Value != "" {
		go func(val string, user string) {
			// Even for a single search, using the batch interface ensures
			// consistent logic for appending emails to the history table.
			if err := s.DB.RecordSearchBatch([]string{val}, user); err != nil {
				s.Log.Printf("Failed to record search history: %v", err)
			}
		}(req.Value, email)
	}

	// Send to RespCh for centralized Caching, Merging, and StoreResponse
	// This allows you to avoid calling s.DB.StoreResponse directly here.
	s.RespCh <- ResponseItem{
		ID:     uid,
		Vendor: req.To,
		Data:   resp,
		Time:   time.Now(),
		Email:  email, // Pass email if you want notification logic to trigger
	}

	w.Header().Set("Content-Type", "application/json")
	w.Write(resp)
}

func (s *Server) RexsTestHandler(w http.ResponseWriter, r *http.Request) {
	sum := SummarizedEvent{
		Matched: true,
		Info:    "This is a test event from Rex's Test Handler",
		Value:   "testvalue"}
	out, err := json.Marshal(sum)
	if err != nil {
		s.Log.Println("RexsTestHandler error", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	s.RespCh <- ResponseItem{
		ID:     uuid.New().String(),
		Vendor: "rexs_test_handler",
		Data:   out,
		Time:   time.Now(),
	}
	w.Write(out)
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
	http.Redirect(w, r, "/app", http.StatusSeeOther)
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
	if len(u.Services) > 0 {
		user.Services = u.Services
	}
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
	const MaxUploadSize = 50 * 1024 * 1024
	r.Body = http.MaxBytesReader(w, r.Body, MaxUploadSize)
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

type deleteRequest struct {
	ID       string `json:"id"`
	Archived bool   `json:"archived"`
}

func (s *Server) DeleteResponseHandler(w http.ResponseWriter, r *http.Request) {
	var dr deleteRequest
	err := json.NewDecoder(r.Body).Decode(&dr)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	s.Log.Println("Deleting response", dr.ID, "archived:", dr.Archived)
	err = s.DB.DeleteResponse(dr.ID)

	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Write([]byte(`{"status": "ok"}`))
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
	Vendor  string
	Start   int
	Limit   int
	Matched bool
	ID      string
}

// NewResponseFilterOptions creates a new options object from the request's query parameters.
// It sets sensible defaults for pagination.
func NewResponseFilterOptions(r *http.Request) (*ResponseFilterOptions, error) {
	opts := &ResponseFilterOptions{
		Vendor:  r.URL.Query().Get("vendor"),
		Start:   0,
		Limit:   100, // Default limit
		Matched: r.URL.Query().Get("matched") == "true",
		ID:      r.URL.Query().Get("id"),
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

func (s *Server) GetRuntimeHandler(w http.ResponseWriter, r *http.Request) {
	uptime := time.Since(s.Details.StartTime)
	out := map[string]string{
		"uptime":     uptime.String(),
		"start_time": s.Details.StartTime.Format(time.RFC3339),
	}
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(out); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

// GetResponseCacheHandler handles requests for viewing cached responses.
// It now supports filtering by vendor and pagination using 'start' and 'limit' query parameters.
// Example URL: /responses?vendor=some_vendor&start=0&limit=50

func (s *Server) GetResponseCacheHandler2(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	defer func(t time.Time) {
		fmt.Println("GetResponseCacheHandler2 took", time.Since(t))
	}(start)
	w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("Expires", "0")

	options, err := NewResponseFilterOptions(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Determine time range
	searchID := r.URL.Query().Get("id")
	lookbackTime := time.Now().Add(-24 * time.Hour)
	if r.URL.Query().Get("archived") == "true" || searchID != "" {
		lookbackTime = time.Time{}
	}

	s.Memory.RLock()
	defer s.Memory.RUnlock()

	// 1. Fetch
	responses, err := s.DB.GetResponses(lookbackTime)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	if len(responses) == 0 {
		fmt.Fprint(w, "No responses found in the selected time range.")
		return
	}

	// 2. Filter
	filteredResponses := applyResponseFilters(responses, options, searchID)
	totalCount := len(filteredResponses)
	w.Header().Set("X-Total-Count", strconv.Itoa(totalCount))

	if len(filteredResponses) == 0 {
		if searchID != "" {
			fmt.Fprintf(w, "No response found with ID: %s", searchID)
		} else if options.Matched {
			fmt.Fprint(w, "No matched responses found.")
		} else {
			fmt.Fprintf(w, "No responses found for vendor: %s", options.Vendor)
		}
		return
	}

	// 3. Paginate
	paginatedResponses := paginateResponses(filteredResponses, options.Start, options.Limit)

	// 4. Render
	if err := renderResponseTable(w, paginatedResponses); err != nil {
		s.Log.Println("Error rendering response table:", err)
		http.Error(w, "Error rendering output", http.StatusInternalServerError)
	}
}

func (s *Server) DNSLookupHandler(w http.ResponseWriter, r *http.Request) {
	// 1. Get the generic 'value' (could be IP or Domain)
	target := r.URL.Query().Get("value")
	if target == "" {
		http.Error(w, "Value required", http.StatusBadRequest)
		return
	}

	// 2. Auth Check (Same as before)
	var email string
	if val := r.Context().Value("email"); val != nil {
		email = val.(string)
	} else {
		tkn, err := s.GetTokenFromSession(r)
		if err != nil || tkn == "" {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		tk, err := s.DB.GetTokenByValue(tkn)
		if err != nil {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		email = tk.Email
	}

	// 3. Perform Lookup Asynchronously based on type
	go func(q, user string) {
		var info string
		var isError bool
		var err error
		// if strings.Contains(q, "@") {

		// }
		// Check if it's an IP address
		if net.ParseIP(q) != nil {
			// It is an IP -> Perform Reverse Lookup (PTR)
			var names []string
			names, err = net.LookupAddr(q)
			if err == nil {
				info = fmt.Sprintf("Reverse lookup (IP -> Domain) for %s: %s", q, strings.Join(names, ", "))
			}
		} else {
			// It is likely a Domain -> Perform Forward Lookup (A/AAAA)
			var ips []string
			ips, err = net.LookupHost(q)
			if err == nil {
				info = fmt.Sprintf("Forward lookup (Domain -> IP) for %s: %s", q, strings.Join(ips, ", "))
			}
		}

		if err != nil {
			info = fmt.Sprintf("DNS lookup failed for %s: %v", q, err)
			isError = true
		}

		// Send notification
		s.Hub.SendToUser(s.RespCh, user, Notification{
			Info:    info,
			Error:   isError,
			Created: time.Now(),
		})
	}(target, email)

	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(`{"status": "dns lookup started"}`))
}

func (s *Server) DNSLookupHandler2(w http.ResponseWriter, r *http.Request) {
	// 1. Get the generic 'value' (could be IP or Domain)
	target := r.URL.Query().Get("value")
	if target == "" {
		http.Error(w, "Value required", http.StatusBadRequest)
		return
	}

	// 2. Auth Check (Same as before)
	var email string
	if val := r.Context().Value("email"); val != nil {
		email = val.(string)
	} else {
		tkn, err := s.GetTokenFromSession(r)
		if err != nil || tkn == "" {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		tk, err := s.DB.GetTokenByValue(tkn)
		if err != nil {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		email = tk.Email
	}

	// 3. Perform Lookup Asynchronously based on type

	var info string
	var isError bool
	var err error
	// if strings.Contains(q, "@") {

	// }
	// Check if it's an IP address
	if net.ParseIP(target) != nil {
		// It is an IP -> Perform Reverse Lookup (PTR)
		var names []string
		names, err = net.LookupAddr(target)
		if err == nil {
			info = fmt.Sprintf("Reverse lookup (IP -> Domain) for %s: %s", target, strings.Join(names, ", "))
		}
	} else {
		// It is likely a Domain -> Perform Forward Lookup (A/AAAA)
		var ips []string
		ips, err = net.LookupHost(target)
		if err == nil {
			info = fmt.Sprintf("Forward lookup (Domain -> IP) for %s: %s", target, strings.Join(ips, ", "))
		}
	}

	if err != nil {
		info = fmt.Sprintf("DNS lookup failed for %s: %v", target, err)
		isError = true
	}
	tmp := make(map[string]any)
	tmp["from"] = email
	tmp["info"] = info
	tmp["error"] = isError
	tmp["created"] = time.Now()

	out, err := json.Marshal(tmp)
	if err != nil {
		s.Log.Println("DNSLookupHandler2 marshal error:", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Write(out)
}

// applyResponseFilters applies ID, Vendor, and Matched filters to the dataset.
func applyResponseFilters(responses []ResponseItem, opts *ResponseFilterOptions, searchID string) []ResponseItem {
	var filtered []ResponseItem

	// 1. Apply ID Filter (Highest Priority)
	if searchID != "" {
		for _, v := range responses {
			if v.ID == searchID {
				// ID is unique, so we can return immediately
				return []ResponseItem{v}
			}
		}
		return []ResponseItem{}
	}

	// 2. Apply Vendor Filter
	if opts.Vendor != "" {
		for _, v := range responses {
			if v.Vendor == opts.Vendor {
				filtered = append(filtered, v)
			}
		}
	} else {
		filtered = responses
	}

	// 3. Apply Matched Filter
	if opts.Matched {
		var matched []ResponseItem
		for _, v := range filtered {
			if containsMatch(v.Data) {
				matched = append(matched, v)
			}
		}
		filtered = matched
	}

	// 4. sort
	type sortableItem struct {
		item        ResponseItem
		threatLevel int
	}

	temp := make([]sortableItem, len(filtered))
	for i, v := range filtered {
		tid, err := ExtractThreatLevelID(v.Data)
		if err != nil {
			tid = 0
		}
		temp[i] = sortableItem{
			item:        v,
			threatLevel: tid,
		}
	}
	slices.SortFunc(temp, func(a, b sortableItem) int {
		// First: Compare Threat Level (Descending: b - a)
		if a.threatLevel != b.threatLevel {
			return b.threatLevel - a.threatLevel
		}
		// Second: Compare Time to prevent jitter (Descending: b after a)
		if b.item.Time.After(a.item.Time) {
			return 1
		}
		if b.item.Time.Before(a.item.Time) {
			return -1
		}
		return 0
	})
	finalResults := make([]ResponseItem, len(temp))
	for i, v := range temp {
		finalResults[i] = v.item
	}
	return finalResults
}

// containsMatch recursively checks if "matched": true exists in the JSON data.
func containsMatch(data []byte) bool {
	if len(data) == 0 {
		return false
	}
	// Try as single event
	var evt SummarizedEvent
	if err := json.Unmarshal(data, &evt); err == nil && evt.Matched {
		return true
	}
	// Try as array
	var arr []json.RawMessage
	if err := json.Unmarshal(data, &arr); err == nil {
		for _, item := range arr {
			if containsMatch(item) {
				return true
			}
		}
	}
	return false
}

// paginateResponses slices the response slice based on start and limit.
func paginateResponses(responses []ResponseItem, start, limit int) []ResponseItem {
	if start >= len(responses) {
		return []ResponseItem{}
	}
	end := start + limit
	if end > len(responses) {
		end = len(responses)
	}
	return responses[start:end]
}

// Helper to identify potential domains (simple heuristic)
func isLikelyDomain(s string) bool {
	// Must contain a dot, no spaces, no '@' symbol (to exclude emails), and be a valid length
	return strings.Contains(s, ".") && !strings.Contains(s, " ") && !strings.Contains(s, "@") && len(s) < 255
}

// renderResponseTable writes the HTML table to the writer.
func renderResponseTable(w io.Writer, responses []ResponseItem) error {
	tableHeader := `<table class="table is-fullwidth is-striped" style="table-layout: fixed">
            <thead>
                <tr>
                    <th>Time</th>
                    <th>Vendor</th>
                    <th>Value</th>
                    <th>Actions</th> 
                </tr>
            </thead>
            <tbody>`
	tableFooter := `</tbody></table>`

	// Updated row template to accept %s for the extra DNS action button
	rowTmpl := `<tr>
        <td>%v</td>
        <td>%v</td>
        <td style="word-break: break-all;">%v</td>
        <td>
            <div class="field is-grouped">
                <p class="control">
                    <a href="/events/%v" class="button is-small is-info is-light" title="View Event">
                        <span class="icon is-small"><i class="material-icons">visibility</i></span>
                    </a>
                </p>
                <p class="control">
                    <button class="button is-small is-danger is-light delete-btn" data-id="%v">
                        <span class="icon is-small"><i class="material-icons">delete</i></span>
                    </button>
                </p>
                %s
            </div>
        </td>
    </tr>`

	var buffer bytes.Buffer
	buffer.WriteString(tableHeader)

	for _, v := range responses {
		displayValue, matched := extractDisplayValue(v.Data)

		// Determine if we should show the DNS lookup button
		dnsAction := ""
		if net.ParseIP(displayValue) != nil || isLikelyDomain(displayValue) {
			// FIX: Use data-value attribute and html.EscapeString
			// We give it a specific class 'dns-lookup-btn' to hook into with JS later
			dnsAction = fmt.Sprintf(`<p class="control">
                    <button class="button is-small is-warning is-light dns-lookup-btn" data-value="%s" title="DNS Lookup">
                        <span class="icon is-small"><i class="material-icons">dns</i></span>
                    </button>
                </p>`, html.EscapeString(displayValue))
		}

		displayHtml := displayValue
		if matched {
			displayHtml = fmt.Sprintf(`<span class="has-text-warning has-text-weight-bold">%s</span>`, displayValue)
		}

		// Inject the dnsAction string into the template
		row := fmt.Sprintf(rowTmpl, v.Time.Format(time.RFC3339), v.Vendor, displayHtml, v.ID, v.ID, dnsAction)
		buffer.WriteString(row)
	}

	buffer.WriteString(tableFooter)
	_, err := w.Write(buffer.Bytes())
	return err
}

// extractDisplayValue attempts to find a meaningful value to display in the table.
// It handles nested JSON arrays (e.g., [[{...}]]).
func extractDisplayValue(data []byte) (string, bool) {
	var rawParts []json.RawMessage
	var evt SummarizedEvent
	matched := containsMatch(data)

	if err := json.Unmarshal(data, &rawParts); err == nil && len(rawParts) > 0 {
		// Check if first element is ITSELF an array (nested)
		var nestedParts []json.RawMessage
		if err := json.Unmarshal(rawParts[0], &nestedParts); err == nil && len(nestedParts) > 0 {
			// It is nested, unmarshal the inner element
			if err := json.Unmarshal(nestedParts[0], &evt); err == nil {
				return evt.Value, matched
			}
		} else {
			// It is not nested, unmarshal the top level element
			if err := json.Unmarshal(rawParts[0], &evt); err == nil {
				return evt.Value, matched
			}
		}
	}

	// Fallback: try as single object if array unmarshal failed
	if err := json.Unmarshal(data, &evt); err == nil && evt.Value != "" {
		return evt.Value, matched
	}

	return "N/A", matched
}

func (s *Server) ExportResponseCSVHandler(w http.ResponseWriter, r *http.Request) {
	// 1. Parse Options (reuse existing filter logic)
	options, err := NewResponseFilterOptions(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// 2. Determine time range
	searchID := r.URL.Query().Get("id")
	lookbackTime := time.Now().Add(-24 * time.Hour)
	// If searching by ID or looking at archives, ignore the time limit
	if r.URL.Query().Get("archived") == "true" || searchID != "" {
		lookbackTime = time.Time{}
	}

	s.Memory.RLock()
	defer s.Memory.RUnlock()

	// 3. Fetch from DB
	responses, err := s.DB.GetResponses(lookbackTime)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// 4. Filter (reuse existing filter logic)
	filteredResponses := applyResponseFilters(responses, options, searchID)

	// 5. Set Headers for Download
	filename := fmt.Sprintf("responses_%s.csv", time.Now().Format("20060102-150405"))
	w.Header().Set("Content-Type", "text/csv")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment;filename=%s", filename))

	// 6. Write CSV
	writer := csv.NewWriter(w)
	defer writer.Flush()

	// Write Header
	if err := writer.Write([]string{"Time", "ID", "Vendor", "Value"}); err != nil {
		s.Log.Println("Error writing CSV header:", err)
		return
	}

	// Write Rows
	for _, v := range filteredResponses {
		// reuse extractDisplayValue to get the readable value
		displayValue, _ := extractDisplayValue(v.Data)
		row := []string{
			v.Time.Format(time.RFC3339),
			v.ID,
			v.Vendor,
			displayValue,
		}
		if err := writer.Write(row); err != nil {
			s.Log.Println("Error writing CSV row:", err)
			return
		}
	}
}

type previousResponseQuery struct {
	Start string `json:"start"`
	End   string `json:"end"`
	Value string `json:"value"`
}

func (s *Server) GetPreviousResponsesHandler(w http.ResponseWriter, r *http.Request) {
	var prq struct {
		Value string `json:"value"`
	}

	// Decode the incoming request from the frontend
	if err := json.NewDecoder(r.Body).Decode(&prq); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Query the dedicated history table instead of scanning response logs
	history, err := s.DB.GetSearchHistory(prq.Value)
	if err != nil {
		// If no history exists, return an empty array rather than a 404/500
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte("[]"))
		return
	}

	// Convert the history record into the SummarizedEvent format for the UI
	matches := []SummarizedEvent{}
	for _, email := range history.Emails {
		matches = append(matches, SummarizedEvent{
			Timestamp:  history.CreatedAt,
			Background: "has-background-info-dark", // Distinguish past searches in UI
			From:       "Historical Search",
			Value:      history.Value,
			Info:       fmt.Sprintf("User %s previously searched for this value.", email),
			Matched:    true,
		})
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(matches)
} //

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

func (s *Server) TriggerMispWorkflowHandler(w http.ResponseWriter, r *http.Request) {
	defer s.addStat("misp_workflow_requests", 1)
	start := time.Now()
	defer func() {
		s.Log.Println("TriggerMispWorkflowHandler took", time.Since(start))
	}()

	// 1. Parse Request
	var req vendors.MispWorkflowRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, fmt.Sprintf("Invalid request body: %v", err), http.StatusBadRequest)
		return
	}

	// Validate required fields
	if req.EventInfo == "" || req.AttributeValue == "" || req.AttributeType == "" {
		http.Error(w, "Missing required fields: event_info, attribute_value, or attribute_type", http.StatusBadRequest)
		return
	}
	finalType := GetMispType(req.AttributeType)
	// 2. Create the Event Object
	// Using defaults for: Distribution (0=Org), Analysis (0=Initial), Threat (3=Low)
	newEvent := vendors.NewEvent(
		"2",           // OrgID (optional)
		"0",           // Distribution
		req.EventInfo, // Info
		"0",           // Analysis
		"3",           // Threat Level
		"",            // Extends UUID
	)
	newEvent.OrgCID = "2"
	// 3. Send Event to MISP
	eventID, _, err := s.CreateMispEvent(*newEvent)
	if err != nil {
		s.LogError(fmt.Errorf("misp workflow failed at event creation: %w", err))
		http.Error(w, fmt.Sprintf("Failed to create event: %v", err), http.StatusInternalServerError)
		return
	}
	parts := strings.Split(eventID, "|")
	if len(parts) < 2 {
		s.LogError(fmt.Errorf("misp workflow failed: invalid event ID format: %s", eventID))
		http.Error(w, fmt.Sprintf("Invalid event ID format: %s", eventID), http.StatusInternalServerError)
		return
	}
	category := GetMispCategory(finalType)
	link := parts[0]
	eId := parts[1]
	// 4. Add the Attribute
	// We map "Network activity" as a default category, but you could make this dynamic
	_, err = s.AddMispAttribute(
		eId,
		finalType,
		req.AttributeValue,
		category,
		"0",
		"added via threatco workflow",
		nil, // ToIDS defaults to true
	)
	if err != nil {
		// We log the error but don't fail the whole request, as the event was created successfully
		s.LogError(fmt.Errorf("misp workflow warning: event %s created, but attribute failed: %w", eventID, err))
	}

	// 5. Add the Tag (if provided)
	if req.TagName != "" {
		err = s.AddMispTag(eId, req.TagName)
		if err != nil {
			s.LogError(fmt.Errorf("misp workflow warning: event %s created, but tagging failed: %w", eventID, err))
		}
	}

	// 6. Response
	response := map[string]string{
		"link":     link,
		"status":   "success",
		"event_id": eventID,
		"message":  fmt.Sprintf("Event created, attribute added, tag '%s' applied.", req.TagName),
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// New Struct for Batch Requests
type MispBatchRequest struct {
	EventInfo  string `json:"event_info"`
	TagName    string `json:"tag_name"`
	Attributes []struct {
		Value string `json:"value"`
		Type  string `json:"type"`
	} `json:"attributes"`
}

func (s *Server) TriggerMispBatchWorkflowHandler(w http.ResponseWriter, r *http.Request) {
	defer s.addStat("misp_batch_requests", 1)

	// 1. Decode Payload
	var req MispBatchRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// 2. Create the Event Object
	// Defaulting to Distribution: Org(0), Threat: Low(3), Analysis: Initial(0)
	// Make sure to use the pointers we fixed earlier!
	newEvent := vendors.NewEvent(
		"2",           // OrgID (Change per your config)
		"0",           // Distribution
		req.EventInfo, // Info
		"0",           // Analysis
		"3",           // Threat Level
		"",            // Extends UUID
	)
	newEvent.OrgCID = "2"
	// 3. Attach All Attributes to the Event Object
	// MISP allows creating attributes nested inside the Event creation call
	for _, attr := range req.Attributes {
		finalType := GetMispType(attr.Type)
		category := GetMispCategory(finalType)

		newAttr := vendors.Attribute{
			Type:         finalType,
			Value:        attr.Value,
			Category:     category,
			ToIDS:        true,
			UUID:         uuid.New().String(),
			Distribution: "0",
			Comment:      "Imported via ThreatCo Case Management",
		}
		newEvent.Attribute = append(newEvent.Attribute, newAttr)
	}

	// 4. Attach Tag (optional)
	// Note: Tags inside the Event creation payload must be done via the Tag object list
	// or applied after creation. Applying after is safer for simple string tags.

	// 5. Create Event (with attributes)
	eventID, _, err := s.CreateMispEvent(*newEvent)
	if err != nil {
		s.LogError(fmt.Errorf("misp batch failed: %w", err))
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// 6. Apply Tag if needed (Post-Creation)
	parts := strings.Split(eventID, "|")
	if len(parts) >= 2 && req.TagName != "" {
		// parts[1] is usually the numeric ID needed for tagging
		_ = s.AddMispTag(parts[1], req.TagName)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"status":   "success",
		"event_id": eventID,
		"message":  fmt.Sprintf("Created event with %d attributes", len(req.Attributes)),
	})
}

func (s *Server) SearchCasesHandler(w http.ResponseWriter, r *http.Request) {
	// Get 'q' from query string
	query := r.URL.Query().Get("q")
	if query == "" {
		// If empty, just return all open cases (or you could return empty)
		// Let's redirect to GetCases behavior for consistency if query is empty
		s.GetCasesHandler(w, r)
		return
	}

	cases, err := s.DB.SearchCases(query)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(cases)
}

func deriveKey(password string, salt []byte) []byte {
	key := sha256.Sum256(append([]byte(password), salt...))
	for i := 0; i < 10000; i++ {
		key = sha256.Sum256(key[:])
	}
	return key[:]
}

func (s *Server) ToolsEncryptHandler(w http.ResponseWriter, r *http.Request) {
	r.ParseMultipartForm(10 << 20)
	password := r.FormValue("password")
	if password == "" {
		http.Error(w, "Password is required", http.StatusBadRequest)
		return
	}
	var data []byte
	var filename string
	file, header, err := r.FormFile("file")
	if err == nil {
		defer file.Close()
		buf := bytes.NewBuffer(nil)
		io.Copy(buf, file)
		data = buf.Bytes()
		filename = header.Filename + ".enc"
	} else {
		text := r.FormValue("text")
		if text == "" {
			http.Error(w, "No text or file provided", http.StatusBadRequest)
			return
		}
		data = []byte(text)
		filename = "encrypted.txt"
	}
	salt := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		http.Error(w, "Crypto error", http.StatusInternalServerError)
		return
	}
	key := deriveKey(password, salt)
	block, err := aes.NewCipher(key)
	if err != nil {
		http.Error(w, "Cipher error", http.StatusInternalServerError)
		return
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		http.Error(w, "GCM error", http.StatusInternalServerError)
		return
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		http.Error(w, "Nonce error", http.StatusInternalServerError)
		return
	}
	ciphertext := gcm.Seal(nil, nonce, data, nil)
	var result bytes.Buffer
	result.Write(salt)
	result.Write(nonce)
	result.Write(ciphertext)
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("X-Filename", filename)
	w.Write(result.Bytes())
}

func (s *Server) ToolsDecryptHandler(w http.ResponseWriter, r *http.Request) {
	r.ParseMultipartForm(10 << 20)
	password := r.FormValue("password")
	if password == "" {
		http.Error(w, "Password is required", http.StatusBadRequest)
		return
	}
	var data []byte
	var outName string
	file, header, err := r.FormFile("file")
	if err == nil {
		defer file.Close()
		buf := bytes.NewBuffer(nil)
		io.Copy(buf, file)
		data = buf.Bytes()
		outName = header.Filename
		if len(outName) > 4 && outName[len(outName)-4:] == ".enc" {
			outName = outName[:len(outName)-4]
		} else {
			outName = "decrypted_" + outName
		}
	} else {
		http.Error(w, "Please upload the encrypted file", http.StatusBadRequest)
		return
	}
	if len(data) < 28 {
		http.Error(w, "Invalid data: too short", http.StatusBadRequest)
		return
	}
	salt := data[:16]
	nonce := data[16:28]
	ciphertext := data[28:]
	key := deriveKey(password, salt)
	block, err := aes.NewCipher(key)
	if err != nil {
		http.Error(w, "Cipher error", http.StatusInternalServerError)
		return
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		http.Error(w, "GCM error", http.StatusInternalServerError)
		return
	}
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		http.Error(w, "Decryption failed (Wrong password?)", http.StatusUnauthorized)
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("X-Filename", outName)
	w.Write(plaintext)
}

func (s *Server) ToolsChecksumHandler(w http.ResponseWriter, r *http.Request) {
	// 10MB is used for other tool handlers, maintaining consistency.
	r.ParseMultipartForm(10 << 20)

	file, _, err := r.FormFile("file")
	if err != nil {
		if err.Error() == "http: no such file" {
			http.Error(w, "File upload missing.", http.StatusBadRequest)
			return
		}
		fmt.Printf("Error retrieving file from form: %v", err)
		http.Error(w, "Error retrieving file from form", http.StatusInternalServerError)
		return
	}
	defer file.Close()

	checksum, err := CalculateSHA256(file)
	if err != nil {
		fmt.Printf("Error calculating SHA-256: %v", err)
		http.Error(w, "Error calculating file checksum", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	w.Write([]byte(checksum))
}

// internal/handlers.go

type SSHDeployRequest struct {
	Hosts      []string `json:"hosts"`
	Method     string   `json:"method"`
	Password   string   `json:"password"`
	PrivateKey string   `json:"private_key"`
	PublicKey  string   `json:"public_key"`
}

func (s *Server) ToolsSSHDeployHandler(w http.ResponseWriter, r *http.Request) {
	var req SSHDeployRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	email := r.Context().Value("email").(string)

	// Process in background
	go func() {
		for _, hostAddr := range req.Hosts {
			var auth ssh.AuthMethod
			if req.Method == "key" {
				signer, err := ssh.ParsePrivateKey([]byte(req.PrivateKey))
				if err != nil {
					s.sendSshNotification(email, hostAddr, fmt.Sprintf("Key Error: %v", err), true)
					continue
				}
				auth = ssh.PublicKeys(signer)
			} else {
				auth = ssh.Password(req.Password)
			}

			// Parse user@host:port
			user := "root"
			addr := hostAddr
			if strings.Contains(hostAddr, "@") {
				parts := strings.Split(hostAddr, "@")
				user = parts[0]
				addr = parts[1]
			}
			if !strings.Contains(addr, ":") {
				addr += ":22"
			}

			config := &ssh.ClientConfig{
				User:            user,
				Auth:            []ssh.AuthMethod{auth},
				HostKeyCallback: ssh.InsecureIgnoreHostKey(),
				Timeout:         10 * time.Second,
			}

			client, err := ssh.Dial("tcp", addr, config)
			if err != nil {
				s.sendSshNotification(email, hostAddr, fmt.Sprintf("Conn Failed: %v", err), true)
				continue
			}

			session, err := client.NewSession()
			if err != nil {
				s.sendSshNotification(email, hostAddr, "Session Error", true)
				client.Close()
				continue
			}

			// Deployment command
			cmd := fmt.Sprintf("mkdir -p ~/.ssh && chmod 700 ~/.ssh && echo '%s' >> ~/.ssh/authorized_keys && chmod 600 ~/.ssh/authorized_keys", req.PublicKey)
			err = session.Run(cmd)

			if err != nil {
				s.sendSshNotification(email, hostAddr, fmt.Sprintf("Deploy Failed: %v", err), true)
			} else {
				s.sendSshNotification(email, hostAddr, "Public key successfully deployed.", false)
			}

			session.Close()
			client.Close()
		}
	}()

	w.WriteHeader(http.StatusAccepted)
	w.Write([]byte(`{"status": "processing"}`))
}

// Helper to send notifications back to the user via WebSocket Hub
func (s *Server) sendSshNotification(user, host, msg string, isError bool) {
	s.Hub.SendToUser(s.RespCh, user, Notification{
		Info:    fmt.Sprintf("[SSH %s] %s", host, msg),
		Error:   isError,
		Created: time.Now(),
	})
}

// internal/handlers.go

// internal/handlers.go

type SSHExecRequest struct {
	Host       string   `json:"host"`
	Method     string   `json:"method"`
	Password   string   `json:"password"`
	PrivateKey string   `json:"private_key"`
	Commands   []string `json:"commands"`
}

func (s *Server) ToolsSSHExecHandler(w http.ResponseWriter, r *http.Request) {
	var req SSHExecRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// 1. Parse Host (user@address:port)
	user := "root"
	addr := req.Host
	if strings.Contains(req.Host, "@") {
		parts := strings.Split(req.Host, "@")
		user = parts[0]
		addr = parts[1]
	}
	if !strings.Contains(addr, ":") {
		addr += ":22"
	}

	// 2. Setup Auth
	var auth ssh.AuthMethod
	if req.Method == "key" {
		signer, err := ssh.ParsePrivateKey([]byte(req.PrivateKey))
		if err != nil {
			json.NewEncoder(w).Encode(map[string]any{"output": "Invalid Private Key", "error": true})
			return
		}
		auth = ssh.PublicKeys(signer)
	} else {
		auth = ssh.Password(req.Password)
	}

	// 3. Connect and Execute
	config := &ssh.ClientConfig{
		User:            user,
		Auth:            []ssh.AuthMethod{auth},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         15 * time.Second,
	}

	client, err := ssh.Dial("tcp", addr, config)
	if err != nil {
		json.NewEncoder(w).Encode(map[string]any{"output": "Connection Failed: " + err.Error(), "error": true})
		return
	}
	defer client.Close()

	session, err := client.NewSession()
	if err != nil {
		json.NewEncoder(w).Encode(map[string]any{"output": "Session Failed", "error": true})
		return
	}
	defer session.Close()

	// Join commands with semicolon
	fullCmd := strings.Join(req.Commands, "; ")
	output, err := session.CombinedOutput(fullCmd)

	resp := map[string]any{
		"output": string(output),
		"error":  err != nil,
	}
	if err != nil {
		resp["output"] = string(output) + "\nExecution Error: " + err.Error()
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

type NpmCheckResult struct {
	FileName string     `json:"file_name"`
	Matches  []NpmMatch `json:"matches"`
	Error    string     `json:"error,omitempty"`
}

type NpmMatch struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	Severity    string `json:"severity"`
	Type        string `json:"type"` // Added field
}

func (s *Server) ToolsNpmCheckHandler(w http.ResponseWriter, r *http.Request) {
	// 1. Parse uploaded files (multipart) with a 10MB limit
	if err := r.ParseMultipartForm(10 << 20); err != nil {
		http.Error(w, "File upload error", http.StatusBadRequest)
		return
	}

	files := r.MultipartForm.File["files"]
	results := make([]NpmCheckResult, 0)

	for _, fileHeader := range files {
		res := NpmCheckResult{FileName: fileHeader.Filename}

		f, err := fileHeader.Open()
		if err != nil {
			res.Error = "Could not open file"
			results = append(results, res)
			continue
		}

		var pkg map[string]interface{}
		if err := json.NewDecoder(f).Decode(&pkg); err != nil {
			res.Error = "Invalid JSON format"
			f.Close()
			results = append(results, res)
			continue
		}
		f.Close()

		// 2. Extract dependencies and devDependencies
		deps := make(map[string]bool)
		for _, key := range []string{"dependencies", "devDependencies"} {
			if d, ok := pkg[key].(map[string]interface{}); ok {
				for name := range d {
					deps[name] = true
				}
			}
		}

		// 3. Check against static map from npm_db.go
		for name, vuln := range MaliciousNpmPackages {
			if deps[name] {
				res.Matches = append(res.Matches, NpmMatch{
					Name:        name,
					Description: vuln.Description,
					Severity:    vuln.Severity,
					Type:        vuln.Type, // Map the type
				})
			}
		}
		results = append(results, res)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(results)
}

func (s *Server) ToolsGenerateUUIDHandler(w http.ResponseWriter, r *http.Request) {
	uuidStr := uuid.New().String()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"uuid": uuidStr})
}

type PasswordRequest struct {
	Length int  `json:"length"`
	Upper  bool `json:"upper"`
	Lower  bool `json:"lower"`
	Num    bool `json:"num"`
	Sym    bool `json:"sym"`
}

func (s *Server) ToolsGeneratePasswordHandler(w http.ResponseWriter, r *http.Request) {
	var req PasswordRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	if req.Length < 1 {
		req.Length = 32
	}
	if req.Length > 256 {
		req.Length = 256 // Reasonable limit
	}

	const (
		upper = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
		lower = "abcdefghijklmnopqrstuvwxyz"
		num   = "0123456789"
		sym   = "!@#$%^&*()_+~`|}{[]:;?><,./-="
	)

	var charset string
	if req.Upper {
		charset += upper
	}
	if req.Lower {
		charset += lower
	}
	if req.Num {
		charset += num
	}
	if req.Sym {
		charset += sym
	}

	// Fallback if nothing selected
	if charset == "" {
		charset = lower + upper + num
	}

	password := make([]byte, req.Length)
	for i := 0; i < req.Length; i++ {
		// Use crypto/rand for secure index selection
		n, err := rand.Int(rand.Reader, big.NewInt(int64(len(charset))))
		if err != nil {
			http.Error(w, "Random generation error", http.StatusInternalServerError)
			return
		}
		password[i] = charset[n.Int64()]
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"password": string(password)})
}

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

type GenericOut struct {
	Value string `json:"value"`
	Type  string `json:"type"`
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
