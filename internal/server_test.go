package internal

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/json"
	"io"
	"log"
	"sync"
	"testing"
	"time"
)

type MockDB struct {
	responses []ResponseItem
	cases     map[string]Case
	users     []User
}

func (m *MockDB) CleanResponses(t time.Duration) error { return nil }
func (m *MockDB) Backup(w io.Writer) error             { return nil }
func (m *MockDB) Restore(filePath string) error        { return nil }
func (m *MockDB) GetUserByEmail(email string) (User, error) {
	for _, u := range m.users {
		if u.Email == email {
			return u, nil
		}
	}
	return User{}, nil
}
func (m *MockDB) DeleteUser(email string) error                     { return nil }
func (m *MockDB) GetAllUsers() ([]User, error)                      { return m.users, nil }
func (m *MockDB) AddUser(u User) error                              { m.users = append(m.users, u); return nil }
func (m *MockDB) GetServiceByKind(kind string) (ServiceType, error) { return ServiceType{}, nil }
func (m *MockDB) AddService(st ServiceType) error                   { return nil }
func (m *MockDB) GetTokenByValue(tk string) (Token, error)          { return Token{}, nil }
func (m *MockDB) SaveToken(t Token) error                           { return nil }
func (m *MockDB) StoreResponse(archive bool, id string, data []byte, vendor string) error {
	m.responses = append(m.responses, ResponseItem{ID: id, Data: data, Vendor: vendor, Time: time.Now()})
	return nil
}
func (m *MockDB) GetResponse(id string) ([]byte, error) {
	for _, r := range m.responses {
		if r.ID == id {
			return r.Data, nil
		}
	}
	return nil, nil
}
func (m *MockDB) GetResponses(expiration time.Time) ([]ResponseItem, error) {
	return m.responses, nil
}
func (m *MockDB) DeleteResponse(id string) error { return nil }
func (m *MockDB) TestAndRecconect() error        { return nil }
func (m *MockDB) CreateCase(c Case) error        { m.cases[c.ID] = c; return nil }
func (m *MockDB) GetCases(limit, offset int, filter string) ([]Case, error) {
	var res []Case
	for _, c := range m.cases {
		res = append(res, c)
	}
	return res, nil
}
func (m *MockDB) GetCase(id string) (Case, error) { return m.cases[id], nil }
func (m *MockDB) UpdateCase(c Case) error         { m.cases[c.ID] = c; return nil }
func (m *MockDB) DeleteCase(id string) error      { delete(m.cases, id); return nil }
func (m *MockDB) SearchCases(query string, limit int) ([]Case, error) {
	var res []Case
	for _, c := range m.cases {
		for _, ioc := range c.IOCs {
			if ioc == query {
				res = append(res, c)
			}
		}
	}
	return res, nil
}
func (m *MockDB) RecordSearchBatch(values []string, email string) error { return nil }
func (m *MockDB) GetSearchHistory(value string) (SearchRecord, error)   { return SearchRecord{}, nil }
func (m *MockDB) CleanSearchHistory(days int) error                     { return nil }
func (m *MockDB) AddNotification(email string, n Notification) error    { return nil }
func (m *MockDB) GetNotifications(email string) ([]Notification, error) { return nil, nil }
func (m *MockDB) ClearNotifications(email string) error                 { return nil }

func setupTestServer() *Server {
	key := make([]byte, 32)
	block, _ := aes.NewCipher(key)
	aesGCM, _ := cipher.NewGCM(block)

	db := &MockDB{
		cases: make(map[string]Case),
	}

	s := &Server{
		Log:    log.New(io.Discard, "", 0),
		DB:     db,
		Memory: &sync.RWMutex{},
		Cache: &Cache{
			Coordinates: make(map[string][]Coord),
			Responses:   make(map[string]ResponseItem),
		},
	}
	s.Details.Key = &aesGCM
	s.Details.Stats = make(map[string]float64)
	return s
}

func TestEncryptDecrypt(t *testing.T) {
	s := setupTestServer()
	plaintext := "secret-api-key"

	encrypted, err := s.Encrypt(plaintext)
	if err != nil {
		t.Fatalf("Encryption failed: %v", err)
	}

	decrypted, keyType, err := s.Decrypt(encrypted)
	if err != nil {
		t.Fatalf("Decryption failed: %v", err)
	}
	if keyType != KeyUsedNew {
		t.Errorf("Expected key type %s, got %s", KeyUsedNew, keyType)
	}
	if decrypted != plaintext {
		t.Errorf("Expected %s, got %s", plaintext, decrypted)
	}
}

func TestCleanupClosedCases(t *testing.T) {
	s := setupTestServer()
	db := s.DB.(*MockDB)

	oldDate := time.Now().AddDate(0, 0, -100)
	db.cases["c1"] = Case{ID: "c1", Status: "Closed", CreatedAt: oldDate}
	db.cases["c2"] = Case{ID: "c2", Status: "Open", CreatedAt: oldDate}
	db.cases["c3"] = Case{ID: "c3", Status: "Closed", CreatedAt: time.Now()}

	s.CleanupClosedCases()

	if _, exists := db.cases["c1"]; exists {
		t.Error("Case c1 should have been deleted")
	}
	if _, exists := db.cases["c2"]; !exists {
		t.Error("Case c2 should not have been deleted (Open)")
	}
	if _, exists := db.cases["c3"]; !exists {
		t.Error("Case c3 should not have been deleted (Recent)")
	}
}

func TestAutomatedThreatScan(t *testing.T) {
	s := setupTestServer()
	db := s.DB.(*MockDB)

	data := []map[string]interface{}{
		{
			"searched_by":     "analyst@threat.co",
			"value":           "1.2.3.4",
			"info":            "Known C2 IP",
			"threat_level_id": 5,
			"matched":         true,
		},
	}
	payload, _ := json.Marshal(data)

	db.responses = []ResponseItem{
		{
			ID:     "resp-123",
			Vendor: "threat-intel",
			Data:   payload,
			Time:   time.Now(),
		},
	}

	s.AutomatedThreatScan()

	var createdCase *Case
	for _, c := range db.cases {
		if c.IsAuto && len(c.IOCs) > 0 && c.IOCs[0] == "1.2.3.4" {
			createdCase = &c
			break
		}
	}

	if createdCase == nil {
		t.Fatal("Automated case was not created")
	}
	if createdCase.CreatedBy != "analyst@threat.co bot" {
		t.Errorf("Expected creator 'analyst@threat.co bot', got %s", createdCase.CreatedBy)
	}
}

func TestAddStat(t *testing.T) {
	s := setupTestServer()
	s.addStat("test_hits", 10)
	s.addStat("test_hits", 5)

	if s.Details.Stats["test_hits"] != 15 {
		t.Errorf("Expected 15, got %v", s.Details.Stats["test_hits"])
	}
}

func TestLogHandlers(t *testing.T) {
	s := setupTestServer()

	s.LogInfo("System started")
	if len(s.Cache.Logs) != 1 || s.Cache.Logs[0].Error {
		t.Error("LogInfo failed to record correctly")
	}

	s.LogError(io.EOF)
	if len(s.Cache.Logs) != 2 || !s.Cache.Logs[1].Error {
		t.Error("LogError failed to record correctly")
	}
}

func TestFakeLoggingEvent(t *testing.T) {
	s := setupTestServer()
	s.FakeLoggingEvent(5)

	if len(s.Cache.Logs) != 5 {
		t.Errorf("Expected 5 logs, got %d", len(s.Cache.Logs))
	}
}
