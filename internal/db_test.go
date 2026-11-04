package internal

import (
	"encoding/json"
	"path/filepath"
	"testing"
	"time"

	"go.etcd.io/bbolt"
)

func setupTestBboltDB(t *testing.T) (*BboltDB, func()) {
	t.Helper()
	tempDir := t.TempDir()
	dbPath := filepath.Join(tempDir, "threatco_test.db")

	db, err := bbolt.Open(dbPath, 0600, nil)
	if err != nil {
		t.Fatalf("failed to open bbolt database: %v", err)
	}

	bboltDB := &BboltDB{DB: db}
	cleanup := func() {
		_ = db.Close()
	}
	return bboltDB, cleanup
}

func TestBboltDB_UsersCRUD(t *testing.T) {
	db, cleanup := setupTestBboltDB(t)
	defer cleanup()

	// 1. Get non-existent user
	u, err := db.GetUserByEmail("nonexistent@threat.co")
	if err != nil {
		t.Fatalf("unexpected error querying nonexistent user: %v", err)
	}
	if u.Email != "" {
		t.Errorf("expected empty user for nonexistent email, got %+v", u)
	}

	// 2. Add users
	user1 := User{
		ID:       "u-001",
		Email:    "analyst1@threat.co",
		Admin:    false,
		Key:      "enc-key-1",
		Password: "hashed-password-1",
		Services: []ServiceType{{Kind: "virustotal", Name: "VT"}},
	}
	user2 := User{
		ID:       "u-002",
		Email:    "admin@threat.co",
		Admin:    true,
		Key:      "enc-key-2",
		Password: "hashed-password-2",
	}

	if err := db.AddUser(user1); err != nil {
		t.Fatalf("AddUser failed for user1: %v", err)
	}
	if err := db.AddUser(user2); err != nil {
		t.Fatalf("AddUser failed for user2: %v", err)
	}

	// 3. Get user by email
	fetched, err := db.GetUserByEmail("analyst1@threat.co")
	if err != nil {
		t.Fatalf("GetUserByEmail failed: %v", err)
	}
	if fetched.ID != user1.ID || fetched.Email != user1.Email || fetched.Key != user1.Key {
		t.Errorf("user data mismatch: got %+v, want %+v", fetched, user1)
	}
	if len(fetched.Services) != 1 || fetched.Services[0].Kind != "virustotal" {
		t.Errorf("user services mismatch: got %+v", fetched.Services)
	}

	// 4. GetAllUsers
	allUsers, err := db.GetAllUsers()
	if err != nil {
		t.Fatalf("GetAllUsers failed: %v", err)
	}
	if len(allUsers) != 2 {
		t.Fatalf("expected 2 users, got %d", len(allUsers))
	}

	// 5. DeleteUser
	if err := db.DeleteUser("analyst1@threat.co"); err != nil {
		t.Fatalf("DeleteUser failed: %v", err)
	}

	deleted, err := db.GetUserByEmail("analyst1@threat.co")
	if err != nil {
		t.Fatalf("unexpected error querying deleted user: %v", err)
	}
	if deleted.Email != "" {
		t.Errorf("expected empty email after deletion, got %s", deleted.Email)
	}

	remainingUsers, err := db.GetAllUsers()
	if err != nil {
		t.Fatalf("GetAllUsers after delete failed: %v", err)
	}
	if len(remainingUsers) != 1 || remainingUsers[0].Email != "admin@threat.co" {
		t.Errorf("expected 1 remaining user (admin@threat.co), got %+v", remainingUsers)
	}
}

func TestBboltDB_Services(t *testing.T) {
	db, cleanup := setupTestBboltDB(t)
	defer cleanup()

	// 1. Query non-existent service
	svc, err := db.GetServiceByKind("splunk")
	if err != nil {
		t.Fatalf("unexpected error querying nonexistent service: %v", err)
	}
	if svc.Kind != "" {
		t.Errorf("expected empty service for nonexistent kind, got %+v", svc)
	}

	// 2. Add service
	st := ServiceType{
		Name:        "VirusTotal API",
		Kind:        "virustotal",
		Key:         "vt-key-xyz",
		AuthType:    "apikey",
		MaxRequests: 50,
		RouteMap: []RouteMap{
			{Type: "ipv4", Route: "ip_addresses"},
		},
	}
	if err := db.AddService(st); err != nil {
		t.Fatalf("AddService failed: %v", err)
	}

	// 3. Get service by kind
	fetched, err := db.GetServiceByKind("virustotal")
	if err != nil {
		t.Fatalf("GetServiceByKind failed: %v", err)
	}
	if fetched.Name != st.Name || fetched.Kind != st.Kind || fetched.Key != st.Key || fetched.MaxRequests != st.MaxRequests {
		t.Errorf("service mismatch: got %+v, want %+v", fetched, st)
	}
}

func TestBboltDB_Tokens(t *testing.T) {
	db, cleanup := setupTestBboltDB(t)
	defer cleanup()

	// 1. Query non-existent token
	tk, err := db.GetTokenByValue("nonexistent-token")
	if err != nil {
		t.Fatalf("unexpected error querying nonexistent token: %v", err)
	}
	if tk.Token != "" {
		t.Errorf("expected empty token for nonexistent value, got %+v", tk)
	}

	// 2. Save token
	testToken := Token{
		Token:     "tok-session-12345",
		Email:     "user@threat.co",
		UserID:    "u-123",
		ExpiresAt: time.Now().Add(24 * time.Hour).Truncate(time.Millisecond),
	}
	if err := db.SaveToken(testToken); err != nil {
		t.Fatalf("SaveToken failed: %v", err)
	}

	// 3. Get token by value
	fetched, err := db.GetTokenByValue("tok-session-12345")
	if err != nil {
		t.Fatalf("GetTokenByValue failed: %v", err)
	}
	if fetched.Token != testToken.Token || fetched.Email != testToken.Email || fetched.UserID != testToken.UserID {
		t.Errorf("token mismatch: got %+v, want %+v", fetched, testToken)
	}
}

func TestBboltDB_Responses(t *testing.T) {
	db, cleanup := setupTestBboltDB(t)
	defer cleanup()

	now := time.Now().Truncate(time.Second)
	respItemActive := ResponseItem{
		ID:     "resp-active-1",
		Data:   []byte(`{"status":"malicious","score":90}`),
		Vendor: "virustotal",
		Time:   now,
	}
	respItemArchived := ResponseItem{
		ID:     "resp-archived-1",
		Data:   []byte(`{"status":"clean","score":0}`),
		Vendor: "cloudflare",
		Time:   now.Add(-48 * time.Hour),
	}

	activeBytes, _ := json.Marshal(respItemActive)
	archivedBytes, _ := json.Marshal(respItemArchived)

	// 1. Store active response
	if err := db.StoreResponse(false, "resp-active-1", activeBytes, "virustotal"); err != nil {
		t.Fatalf("StoreResponse (active) failed: %v", err)
	}

	// 2. Store archived response
	if err := db.StoreResponse(true, "resp-archived-1", archivedBytes, "cloudflare"); err != nil {
		t.Fatalf("StoreResponse (archived) failed: %v", err)
	}

	// 3. GetResponse
	rawResp, err := db.GetResponse("resp-active-1")
	if err != nil {
		t.Fatalf("GetResponse failed: %v", err)
	}
	var unmarshaled ResponseItem
	if err := json.Unmarshal(rawResp, &unmarshaled); err != nil {
		t.Fatalf("failed to unmarshal retrieved active response: %v", err)
	}
	if unmarshaled.Vendor != "virustotal" || string(unmarshaled.Data) != string(respItemActive.Data) {
		t.Errorf("retrieved response mismatch: got %+v, want %+v", unmarshaled, respItemActive)
	}

	// 4. GetResponses (with expiration cutoff)
	activeList, err := db.GetResponses(now.Add(-1 * time.Hour))
	if err != nil {
		t.Fatalf("GetResponses failed: %v", err)
	}
	if len(activeList) != 1 || activeList[0].ID != "resp-active-1" {
		t.Errorf("expected 1 active response, got %+v", activeList)
	}

	// 5. GetArchivedResponses
	archivedList, err := db.GetArchivedResponses()
	if err != nil {
		t.Fatalf("GetArchivedResponses failed: %v", err)
	}
	if len(archivedList) != 1 || archivedList[0].ID != "resp-archived-1" {
		t.Errorf("expected 1 archived response, got %+v", archivedList)
	}

	// 6. DeleteResponse
	if err := db.DeleteResponse("resp-active-1"); err != nil {
		t.Fatalf("DeleteResponse failed: %v", err)
	}
	deletedResp, err := db.GetResponse("resp-active-1")
	if err != nil {
		t.Fatalf("unexpected error after delete: %v", err)
	}
	if len(deletedResp) != 0 {
		t.Errorf("expected nil/empty response after delete, got %s", string(deletedResp))
	}
}
