package main

import (
	"time"

	"go.etcd.io/bbolt"
)

func (s *Server) GetUserByEmail(email string) (User, error) {
	s.Memory.Lock()
	defer s.Memory.Unlock()
	s.Details.Stats["user_queries"]++
	// s.Log.Println("GetUserByEmail", email)
	var user User
	err := s.DB.View(func(tx *bbolt.Tx) error {
		b := tx.Bucket([]byte("users"))
		v := b.Get([]byte(email))
		if v == nil {
			s.Log.Println("GetUserByEmail: user not found")
			s.Details.Stats["user_not_found"]++
			return nil
		}

		return user.UnmarshalBinary(v)
	})
	return user, err
}

func (s *Server) DeleteUser(email string) error {
	s.Memory.Lock()
	defer s.Memory.Unlock()
	s.Details.Stats["user_deletes"]++
	return s.DB.Update(func(tx *bbolt.Tx) error {
		b := tx.Bucket([]byte("users"))
		return b.Delete([]byte(email))
	})
}

func (s *Server) GetAllUsers() ([]User, error) {
	s.Memory.Lock()
	defer s.Memory.Unlock()
	s.Details.Stats["user_queries"]++
	var users []User
	err := s.DB.View(func(tx *bbolt.Tx) error {
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

func (s *Server) AddUser(u User) error {
	// s.Log.Println("AddUser", u)
	u.Updated = time.Now()
	s.Memory.Lock()
	defer s.Memory.Unlock()
	s.Details.Stats["user_saves"]++
	return s.DB.Update(func(tx *bbolt.Tx) error {
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

func (s *Server) GetServiceByKind(kind string) (ServiceType, error) {
	s.Memory.Lock()
	defer s.Memory.Unlock()
	s.Details.Stats["service_queries"]++
	s.Log.Println("GetServiceByKind", kind)
	var service ServiceType
	err := s.DB.View(func(tx *bbolt.Tx) error {
		b := tx.Bucket([]byte("services"))
		v := b.Get([]byte(kind))
		if v == nil {
			s.Log.Println("GetServiceByKind: service not found")
			s.Details.Stats["service_not_found"]++
			return nil
		}

		return service.UnmarshalBinary(v)
	})
	return service, err
}

func (s *Server) AddService(st ServiceType) error {
	s.Log.Println("AddService", st)
	s.Memory.Lock()
	defer s.Memory.Unlock()
	s.Details.Stats["service_saves"]++
	return s.DB.Update(func(tx *bbolt.Tx) error {
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

func (s *Server) GetTokenByValue(tk string) (Token, error) {
	s.Memory.Lock()
	defer s.Memory.Unlock()
	s.Details.Stats["token_queries"]++
	s.Log.Println("GetTokenByValue", tk)
	var token Token
	err := s.DB.View(func(tx *bbolt.Tx) error {
		b := tx.Bucket([]byte("tokens"))
		v := b.Get([]byte(tk))
		if v == nil {
			s.Log.Println("GetTokenByValue: token not found")
			s.Details.Stats["token_not_found"]++
			return nil
		}

		return token.UnmarshalBinary(v)
	})
	return token, err
}

func (s *Server) SaveToken(t Token) error {
	s.Log.Println("SaveToken", t)
	s.Memory.Lock()
	defer s.Memory.Unlock()
	s.Details.Stats["token_saves"]++
	return s.DB.Update(func(tx *bbolt.Tx) error {
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
