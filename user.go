package main

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
)

type User struct {
	ID       string         `json:"id"`
	Email    string         `json:"email"`
	Key      string         `json:"key"`
	Created  time.Time      `json:"created"`
	Updated  time.Time      `json:"updated"`
	Selected map[string]int `json:"selected"`
	Admin    bool           `json:"admin"`
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

func NewUser(email string, admin bool) (*User, error) {
	key, err := generateAPIKey()
	if err != nil {
		return nil, err
	}
	fmt.Println("NewUser", email, admin)
	uid := uuid.New()
	u := &User{
		ID:       uid.String(),
		Email:    email,
		Key:      key,
		Created:  time.Now(),
		Updated:  time.Now(),
		Selected: make(map[string]int),
		Admin:    admin,
	}
	fmt.Println("NewUser--------------------------------------------------------------", u)
	return u, nil
}

// func (u *User) MarshalJSON() ([]byte, error) {
// 	return json.Marshal(u)
// }

// func (u *User) UnmarshalJSON(data []byte) error {
// 	return json.Unmarshal(data, u)
// }

func (u *User) MarshalBinary() ([]byte, error) {
	return json.Marshal(u)
}

func (u *User) UnmarshalBinary(data []byte) error {
	return json.Unmarshal(data, u)
}
