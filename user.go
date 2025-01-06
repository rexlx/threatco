package main

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

type User struct {
	ID           string         `json:"id"`
	Email        string         `json:"email"`
	Key          string         `json:"key"`
	Hash         []byte         `json:"hash"`
	Password     string         `json:"password"`
	Created      time.Time      `json:"created"`
	Updated      time.Time      `json:"updated"`
	Selected     map[string]int `json:"selected"`
	Services     []ServiceType  `json:"services"`
	Admin        bool           `json:"admin"`
	SessionToken *Token         `json:"session_token"`
}

func generateAPIKey() (string, error) {
	thatThing := make([]byte, 32)
	_, err := rand.Read(thatThing)
	if err != nil {
		return "", err
	}
	hashed := sha256.Sum256(thatThing)
	key := base64.StdEncoding.EncodeToString(hashed[:])
	return key, nil
}

func NewUser(email string, admin bool, services []ServiceType) (*User, error) {
	key, err := generateAPIKey()
	if err != nil {
		return nil, err
	}
	// fmt.Println("NewUser", email, admin)
	uid := uuid.New()
	thisCopy := make([]ServiceType, len(services))
	for i, svc := range services {
		thisCopy[i] = svc
		thisCopy[i].Secret = ""
		thisCopy[i].Key = ""
	}
	u := &User{
		ID:       uid.String(),
		Email:    email,
		Key:      key,
		Created:  time.Now(),
		Updated:  time.Now(),
		Selected: make(map[string]int),
		Services: thisCopy,
		Admin:    admin,
	}
	return u, nil
}

func (u *User) SetPassword(password string) error {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), 14)
	if err != nil {
		return err
	}
	u.Hash = hash
	u.Password = string(hash)
	fmt.Println("SetPassword", u.Email)
	return nil
}

func (u *User) MarshalBinary() ([]byte, error) {
	return json.Marshal(u)
}

func (u *User) UnmarshalBinary(data []byte) error {
	return json.Unmarshal(data, u)
}

func (u *User) PasswordMatches(input string) (bool, error) {
	err := bcrypt.CompareHashAndPassword(u.Hash, []byte(input))
	if err != nil {
		switch {
		case errors.Is(err, bcrypt.ErrMismatchedHashAndPassword):
			//invalid password
			return false, nil
		default:
			//unknown error
			return false, err
		}
	}

	return true, nil
}

func (u *User) Sanitize() {
	u.Hash = nil
	u.Password = ""
}

type Token struct {
	Handle    string
	ID        string
	Email     string
	UserID    string
	Token     string
	CreatedAt time.Time
	ExpiresAt time.Time
	Hash      []byte
}

func (t *Token) MarshalBinary() ([]byte, error) {
	return json.Marshal(t)
}

func (t *Token) UnmarshalBinary(data []byte) error {
	return json.Unmarshal(data, t)
}
