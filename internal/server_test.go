package internal

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/rexlx/threatco/views"
)

// MockDB satisfies the Database interface for testing
type MockDB struct {
	StoreResponseFunc func(archive bool, id string, data []byte, vendor string) error
}

func (m *MockDB) StoreResponse(archive bool, id string, data []byte, vendor string) error {
	if m.StoreResponseFunc != nil {
		return m.StoreResponseFunc(archive, id, data, vendor)
	}
	return nil
}

// Stubs for other interface methods
func (m *MockDB) Backup(w io.Writer) error                          { return nil }
func (m *MockDB) Restore(filePath string) error                     { return nil }
func (m *MockDB) GetUserByEmail(email string) (User, error)         { return User{}, nil }
func (m *MockDB) DeleteUser(email string) error                     { return nil }
func (m *MockDB) GetAllUsers() ([]User, error)                      { return nil, nil }
func (m *MockDB) AddUser(u User) error                              { return nil }
func (m *MockDB) GetServiceByKind(kind string) (ServiceType, error) { return ServiceType{}, nil }
func (m *MockDB) AddService(st ServiceType) error                   { return nil }
func (m *MockDB) GetTokenByValue(tk string) (Token, error)          { return Token{}, nil }
func (m *MockDB) SaveToken(t Token) error                           { return nil }
func (m *MockDB) GetResponse(id string) ([]byte, error)             { return nil, nil }
func (m *MockDB) GetResponses(t time.Time) ([]ResponseItem, error)  { return nil, nil }
func (m *MockDB) DeleteResponse(id string) error                    { return nil }
func (m *MockDB) TestAndRecconect() error                           { return nil }
func (m *MockDB) CleanResponses(t time.Duration) error              { return nil }
func (m *MockDB) CreateCase(c Case) error                           { return nil }
func (m *MockDB) GetCases(limit, offset int) ([]Case, error)        { return nil, nil }
func (m *MockDB) GetCase(id string) (Case, error)                   { return Case{}, nil }
func (m *MockDB) UpdateCase(c Case) error                           { return nil }
func (m *MockDB) DeleteCase(id string) error                        { return nil }
func (m *MockDB) SearchCases(query string) ([]Case, error)          { return nil, nil }

func setupTestServer() *Server {
	// Generate a random key for the test server to support Encryption tests
	key := make([]byte, 32)
	rand.Read(key)
	block, _ := aes.NewCipher(key)
	aesGCM, _ := cipher.NewGCM(block)

	return &Server{
		ID:     "test-server",
		RespCh: make(chan ResponseItem, 10),
		Memory: &sync.RWMutex{},
		Cache: &Cache{
			Responses:   make(map[string]ResponseItem),
			Coordinates: make(map[string][]Coord),
			Charts:      []byte(views.NoDataView),
		},
		Details: Details{
			Key:   &aesGCM, // Injected Cipher
			Stats: make(map[string]float64),
			SupportedServices: []ServiceType{
				{Kind: "valid_service"},
				{Kind: "misp"},
			},
		},
		Log: log.New(io.Discard, "", 0),
		DB:  &MockDB{},
		Hub: NewHub(),
	}
}

func TestProcessTransientResponses_Integration(t *testing.T) {
	s := setupTestServer()

	if s.Details.Stats == nil {
		t.Fatal("s.Details.Stats is NIL. setupTestServer failed to initialize it.")
	}

	go s.ProcessTransientResponses()

	testID := uuid.New().String()
	// CHANGED: Removed space after colon to match json.Marshal behavior
	initialData := []byte(`[{"value":"test1"}]`)

	// 1. Send first response
	s.RespCh <- ResponseItem{
		ID:     testID,
		Vendor: "test_vendor",
		Time:   time.Now(),
		Data:   initialData,
	}

	time.Sleep(50 * time.Millisecond)

	s.Memory.RLock()
	cached, ok := s.Cache.Responses[testID]
	s.Memory.RUnlock()

	if !ok {
		t.Fatalf("Response was not added to cache")
	}
	if string(cached.Data) != string(initialData) {
		t.Errorf("Data mismatch.\nGot:  %s\nWant: %s", cached.Data, initialData)
	}

	// 2. Send second response (Trigger Merge)
	// CHANGED: Removed space after colon
	secondData := []byte(`[{"value":"test2"}]`)
	s.RespCh <- ResponseItem{
		ID:     testID,
		Vendor: "test_vendor",
		Time:   time.Now(),
		Data:   secondData,
	}

	time.Sleep(50 * time.Millisecond)

	s.Memory.RLock()
	cachedMerged, _ := s.Cache.Responses[testID]
	s.Memory.RUnlock()

	// 3. Verify Merge
	// CHANGED: Removed space after colon
	expectedSubset := `"value":"test2"`
	if !strings.Contains(string(cachedMerged.Data), expectedSubset) {
		t.Errorf("Merged data missing expected subset.\nGot:  %s\nWant to contain: %s", cachedMerged.Data, expectedSubset)
	}

	if string(cachedMerged.Data) == string(initialData) {
		t.Errorf("Data was not merged. Still has old data: %s", cachedMerged.Data)
	}
}

func BenchmarkProcessResponse_LargeJSON(b *testing.B) {
	s := setupTestServer()

	// 1MB of existing data
	largeArray := make([]map[string]string, 0)
	for i := 0; i < 5000; i++ {
		largeArray = append(largeArray, map[string]string{
			"key":   fmt.Sprintf("k-%d", i),
			"value": fmt.Sprintf("some-long-data-string-%d", i),
		})
	}
	baseData, _ := json.Marshal(largeArray)

	testID := "benchmark-id"
	s.Cache.Responses[testID] = ResponseItem{
		ID:   testID,
		Data: baseData,
	}

	newData := []byte(`[{"new":"data"}]`)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		s.Memory.Lock()
		r, ok := s.Cache.Responses[testID]
		if ok {
			mergedData, _ := MergeJSONData(r.Data, newData)
			r.Data = mergedData
			s.Cache.Responses[testID] = r
		}
		s.Memory.Unlock()
	}
}

func TestConcurrency_Responsiveness(t *testing.T) {
	s := setupTestServer()

	// 1. Start your optimized background processor
	go s.ProcessTransientResponses()

	// 2. Prepare heavy data (1MB JSON)
	largeArray := make([]map[string]string, 2000)
	for i := 0; i < 2000; i++ {
		largeArray[i] = map[string]string{"k": "v", "data": strings.Repeat("x", 500)}
	}
	largeData, _ := json.Marshal(largeArray)
	testID := uuid.New().String()

	// 3. Flood the processor with 10 heavy requests in a row
	// This queues up ~30ms worth of CPU work.
	go func() {
		for i := 0; i < 10; i++ {
			s.RespCh <- ResponseItem{
				ID:     testID,
				Vendor: "concurrent_test",
				Time:   time.Now(),
				Data:   largeData,
			}
		}
	}()

	// Give the processor a split second to start chewing on the data
	time.Sleep(2 * time.Millisecond)

	// 4. Simulate a user loading the dashboard (Needs Read Lock)
	start := time.Now()

	// This Read Lock attempt...
	s.Memory.RLock()
	// ...accessed the data...
	_ = s.Cache.Responses
	s.Memory.RUnlock()

	duration := time.Since(start)

	t.Logf("Dashboard access took: %v", duration)

	// In the old code, this would take >3ms (waiting for the write lock).
	// In your new code, this should be nearly instant (<1ms) because the
	// write lock is only held for microseconds.
	if duration > 2*time.Millisecond {
		t.Errorf("Server is LOCKING UP! Read took %v", duration)
	} else {
		t.Log("SUCCESS: Server remained responsive during heavy processing.")
	}
}

func TestServer_EncryptDecrypt(t *testing.T) {
	s := setupTestServer()
	originalText := "secret-api-key-123"

	// 1. Test Encryption
	encrypted, err := s.Encrypt(originalText)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}
	if encrypted == originalText {
		t.Fatal("Encrypt returned plaintext")
	}

	// 2. Test Decryption
	decrypted, keyUsed, err := s.Decrypt(encrypted)
	if err != nil {
		t.Fatalf("Decrypt failed: %v", err)
	}

	if decrypted != originalText {
		t.Errorf("Decrypted text mismatch.\nGot:  %s\nWant: %s", decrypted, originalText)
	}

	if keyUsed != KeyUsedNew {
		t.Errorf("Expected key used to be '%s', got '%s'", KeyUsedNew, keyUsed)
	}
}

func TestServer_CleanUserServices(t *testing.T) {
	s := setupTestServer() // Configured with "valid_service" and "misp"

	// Create user with mixed valid and invalid services
	u, _ := NewUser("test@test.com", false, []ServiceType{
		{Kind: "valid_service"}, // Should be kept
		{Kind: "hacker_tool"},   // Should be removed
		{Kind: "misp"},          // Should be kept
	})

	// Pre-check
	if len(u.Services) != 3 {
		t.Fatalf("Setup error: expected 3 services initially, got %d", len(u.Services))
	}

	// Run Clean
	s.CleanUserServices(u)

	// Post-check
	if len(u.Services) != 2 {
		t.Errorf("CleanUserServices failed: expected 2 services, got %d", len(u.Services))
	}

	for _, svc := range u.Services {
		if svc.Kind == "hacker_tool" {
			t.Error("CleanUserServices failed: invalid service 'hacker_tool' was not removed")
		}
	}
}
