package internal

import (
	"bytes"
	"reflect"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"
)

var mockServices = []ServiceType{
	{Kind: "misp", Key: "mispkey", Secret: "mispsecret"},
	{Kind: "virustotal", Key: "vtkey", Secret: "vtsecret"},
}

func TestGenerateAPIKey(t *testing.T) {
	key, err := generateAPIKey()
	if err != nil {
		t.Fatalf("generateAPIKey failed: %v", err)
	}

	if key == "" {
		t.Error("generateAPIKey returned an empty key")
	}

	// The key is sha256 (32 bytes) then base64 StdEncoded (padded).
	// Base64 of 32 bytes is (32 / 3) * 4 = 42.66, so 44 characters (since it's padded to a multiple of 4).
	if len(key) != 44 {
		t.Errorf("expected key length of 44, got %d", len(key))
	}

	key2, err := generateAPIKey()
	if err != nil {
		t.Fatalf("generateAPIKey failed for second call: %v", err)
	}

	if key == key2 {
		t.Error("two generated keys should be different")
	}
}

func TestNewUser(t *testing.T) {
	email := "test@example.com"
	admin := true
	services := mockServices

	user, err := NewUser(email, admin, services)
	if err != nil {
		t.Fatalf("NewUser failed: %v", err)
	}

	// 1. Check basic fields
	if user.Email != email {
		t.Errorf("expected email %s, got %s", email, user.Email)
	}
	if user.Admin != admin {
		t.Errorf("expected admin %v, got %v", admin, user.Admin)
	}
	if user.ID == "" {
		t.Error("user ID should not be empty")
	}
	if user.Key == "" {
		t.Error("user API Key should not be empty")
	}
	if user.Selected == nil || len(user.Selected) != 0 {
		t.Error("user Selected map should be initialized and empty")
	}

	// 2. Check timestamps
	now := time.Now()
	if user.Created.After(now) || user.Updated.After(now) {
		t.Error("created/updated time should not be in the future")
	}
	if !user.Created.Equal(user.Updated) {
		t.Error("created and updated time should be equal initially")
	}

	// 3. Check services sanitization
	if len(user.Services) != len(services) {
		t.Fatalf("expected %d services, got %d", len(services), len(user.Services))
	}
	for i, svc := range user.Services {
		if svc.Key != "" || svc.Secret != "" {
			t.Errorf("service at index %d was not sanitized: Key: '%s', Secret: '%s'", i, svc.Key, svc.Secret)
		}
		if svc.Kind != services[i].Kind {
			t.Errorf("service Kind mismatch: expected %s, got %s", services[i].Kind, svc.Kind)
		}
	}
}

func TestUser_SetPassword(t *testing.T) {
	user, _ := NewUser("test@example.com", false, nil)
	password := "securepassword123"

	err := user.SetPassword(password)
	if err != nil {
		t.Fatalf("SetPassword failed: %v", err)
	}

	if user.Hash == nil || len(user.Hash) == 0 {
		t.Error("user Hash should be set")
	}
	// The plain-text password is saved in the Password field, which is generally bad practice,
	// but we must check that it is set according to the file logic (which saves the hash string).
	if string(user.Hash) != user.Password {
		t.Error("user Password field should be set to the hash string")
	}

	// Verify the hash is a valid bcrypt hash for the password
	err = bcrypt.CompareHashAndPassword(user.Hash, []byte(password))
	if err != nil {
		t.Errorf("bcrypt.CompareHashAndPassword failed: %v", err)
	}
}

func TestUser_UpdateApiKey(t *testing.T) {
	user, _ := NewUser("test@example.com", false, nil)
	originalKey := user.Key

	err := user.UpdateApiKey()
	if err != nil {
		t.Fatalf("UpdateApiKey failed: %v", err)
	}

	if user.Key == originalKey {
		t.Error("UpdateApiKey did not change the key")
	}
	if user.Key == "" {
		t.Error("Updated key should not be empty")
	}
}

func TestUser_PasswordMatches(t *testing.T) {
	user, _ := NewUser("test@example.com", false, nil)
	password := "correctHorseBatteryStaple"
	user.SetPassword(password)

	tests := []struct {
		name      string
		input     string
		wantMatch bool
		wantErr   bool
	}{
		{"Correct Password", password, true, false},
		{"Incorrect Password", "wrongPassword", false, false},
		{"Empty Password", "", false, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotMatch, err := user.PasswordMatches(tt.input)
			if (err != nil) != tt.wantErr {
				t.Fatalf("PasswordMatches() error = %v, wantErr %v", err, tt.wantErr)
			}
			if gotMatch != tt.wantMatch {
				t.Errorf("PasswordMatches() gotMatch = %v, wantMatch %v", gotMatch, tt.wantMatch)
			}
		})
	}
}

func TestUser_Sanitize(t *testing.T) {
	user, _ := NewUser("test@example.com", false, nil)
	password := "secret"
	user.SetPassword(password)

	// Ensure fields are set before sanitizing
	if user.Hash == nil || len(user.Password) == 0 {
		t.Fatal("pre-check failed: Hash or Password field is empty before Sanitize")
	}

	user.Sanitize()

	if user.Hash != nil {
		t.Errorf("Sanitize failed: Hash should be nil, got %v", user.Hash)
	}
	if user.Password != "" {
		t.Errorf("Sanitize failed: Password should be empty string, got %s", user.Password)
	}
}

func TestUser_MarshalUnmarshalBinary(t *testing.T) {
	// 1. Create a user with all fields populated
	admin := true
	email := "marshal.test@example.com"
	testToken := &Token{
		Handle:    "h1",
		ID:        "id1",
		Email:     email,
		UserID:    "user123",
		Token:     "t-t-t",
		CreatedAt: time.Now().Add(-time.Hour),
		ExpiresAt: time.Now().Add(time.Hour),
		Hash:      []byte("somehash"),
	}

	user, _ := NewUser(email, admin, mockServices)
	user.SetPassword("supersecret")
	user.Selected["misp"] = 5
	user.SessionToken = testToken
	// Set the password back to the hash string before marshaling, as per SetPassword's logic.
	user.Password = string(user.Hash)

	// 2. Marshal the user
	data, err := user.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary failed: %v", err)
	}

	// 3. Unmarshal the data into a new User struct
	newUser := &User{}
	err = newUser.UnmarshalBinary(data)
	if err != nil {
		t.Fatalf("UnmarshalBinary failed: %v", err)
	}

	// 4. Compare the original and new structs
	// We manually compare all fields as comparing the whole struct with deep equal might fail on time.Time due to nanoseconds/location differences.
	if user.ID != newUser.ID {
		t.Errorf("ID mismatch: want %s, got %s", user.ID, newUser.ID)
	}
	if user.Email != newUser.Email {
		t.Errorf("Email mismatch: want %s, got %s", user.Email, newUser.Email)
	}
	if user.Key != newUser.Key {
		t.Errorf("Key mismatch: want %s, got %s", user.Key, newUser.Key)
	}
	if !bytes.Equal(user.Hash, newUser.Hash) {
		t.Errorf("Hash mismatch: want %v, got %v", user.Hash, newUser.Hash)
	}
	if user.Password != newUser.Password {
		t.Errorf("Password mismatch: want %s, got %s", user.Password, newUser.Password)
	}
	if user.Admin != newUser.Admin {
		t.Errorf("Admin mismatch: want %v, got %v", user.Admin, newUser.Admin)
	}
	if len(user.Services) != len(newUser.Services) || user.Services[0].Kind != newUser.Services[0].Kind {
		t.Error("Services mismatch")
	}
	if !reflect.DeepEqual(user.Selected, newUser.Selected) {
		t.Errorf("Selected mismatch: want %v, got %v", user.Selected, newUser.Selected)
	}

	// Check Token
	if user.SessionToken.UserID != newUser.SessionToken.UserID {
		t.Error("SessionToken mismatch")
	}
}

func TestToken_MarshalUnmarshalBinary(t *testing.T) {
	originalToken := &Token{
		Handle:    "handle-abc",
		ID:        "token-id-123",
		Email:     "token@test.com",
		UserID:    "user-uuid-xyz",
		Token:     "raw-token-string",
		CreatedAt: time.Now().Add(-2 * time.Hour).Truncate(time.Millisecond), // Truncate for reliable JSON comparison
		ExpiresAt: time.Now().Add(24 * time.Hour).Truncate(time.Millisecond),
		Hash:      []byte("token-hash-data"),
	}

	// 1. Marshal the token
	data, err := originalToken.MarshalBinary()
	if err != nil {
		t.Fatalf("Token.MarshalBinary failed: %v", err)
	}

	// 2. Unmarshal the data into a new Token struct
	newToken := &Token{}
	err = newToken.UnmarshalBinary(data)
	if err != nil {
		t.Fatalf("Token.UnmarshalBinary failed: %v", err)
	}

	// 3. Compare the original and new structs
	// Use DeepEqual for comparison
	if !reflect.DeepEqual(originalToken, newToken) {
		t.Errorf("Token mismatch after (Un)MarshalBinary.\nOriginal: %+v\nNew: %+v", originalToken, newToken)
		// Check specific fields if DeepEqual fails for a clearer error
		if originalToken.CreatedAt.String() != newToken.CreatedAt.String() {
			t.Errorf("CreatedAt mismatch: want %s, got %s", originalToken.CreatedAt, newToken.CreatedAt)
		}
		if !bytes.Equal(originalToken.Hash, newToken.Hash) {
			t.Errorf("Hash mismatch: want %v, got %v", originalToken.Hash, newToken.Hash)
		}
	}
}
