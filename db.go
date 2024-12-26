package main

import (
	"time"

	"go.etcd.io/bbolt"
)

type Database interface {
	GetUserByEmail(email string) (User, error)
	DeleteUser(email string) error
	GetAllUsers() ([]User, error)
	AddUser(u User) error
	GetServiceByKind(kind string) (ServiceType, error)
	AddService(st ServiceType) error
	GetTokenByValue(tk string) (Token, error)
	SaveToken(t Token) error
}

type BboltDB struct {
	DB *bbolt.DB
}

func (db *BboltDB) GetUserByEmail(email string) (User, error) {
	var user User
	err := db.DB.View(func(tx *bbolt.Tx) error {
		b := tx.Bucket([]byte("users"))
		v := b.Get([]byte(email))
		if v == nil {
			return nil
		}

		return user.UnmarshalBinary(v)
	})
	return user, err
}

func (db *BboltDB) DeleteUser(email string) error {
	return db.DB.Update(func(tx *bbolt.Tx) error {
		b := tx.Bucket([]byte("users"))
		return b.Delete([]byte(email))
	})
}

func (db *BboltDB) GetAllUsers() ([]User, error) {
	var users []User
	err := db.DB.View(func(tx *bbolt.Tx) error {
		b := tx.Bucket([]byte("users"))
		return b.ForEach(func(k, v []byte) error {
			var user User
			if err := user.UnmarshalBinary(v); err != nil {
				return err
			}
			users = append(users, user)
			return nil
		})
	})
	return users, err
}

func (db *BboltDB) AddUser(u User) error {
	// s.Log.Println("AddUser", u)
	u.Updated = time.Now()
	return db.DB.Update(func(tx *bbolt.Tx) error {
		b, err := tx.CreateBucketIfNotExists([]byte("users"))
		if err != nil {
			return err
		}
		v, err := u.MarshalBinary()
		if err != nil {
			return err
		}
		return b.Put([]byte(u.Email), v)
	})
}

func (db *BboltDB) GetServiceByKind(kind string) (ServiceType, error) {
	var service ServiceType
	err := db.DB.View(func(tx *bbolt.Tx) error {
		b := tx.Bucket([]byte("services"))
		v := b.Get([]byte(kind))
		if v == nil {
			return nil
		}

		return service.UnmarshalBinary(v)
	})
	return service, err
}

func (db *BboltDB) AddService(st ServiceType) error {
	return db.DB.Update(func(tx *bbolt.Tx) error {
		b, err := tx.CreateBucketIfNotExists([]byte("services"))
		if err != nil {
			return err
		}
		v, err := st.MarshalBinary()
		if err != nil {
			return err
		}
		return b.Put([]byte(st.Kind), v)
	})
}

func (db *BboltDB) GetTokenByValue(tk string) (Token, error) {
	var token Token
	err := db.DB.View(func(tx *bbolt.Tx) error {
		b := tx.Bucket([]byte("tokens"))
		v := b.Get([]byte(tk))
		if v == nil {
			return nil
		}

		return token.UnmarshalBinary(v)
	})
	return token, err
}

func (db *BboltDB) SaveToken(t Token) error {
	return db.DB.Update(func(tx *bbolt.Tx) error {
		b, err := tx.CreateBucketIfNotExists([]byte("tokens"))
		if err != nil {
			return err
		}
		v, err := t.MarshalBinary()
		if err != nil {
			return err
		}
		return b.Put([]byte(t.Token), v)
	})
}
