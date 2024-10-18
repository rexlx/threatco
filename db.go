package main

import (
	"fmt"
	"time"

	"go.etcd.io/bbolt"
)

func (s *Server) GetUserByEmail(email string) (User, error) {
	s.Memory.Lock()
	defer s.Memory.Unlock()
	s.Details.Stats["user_queries"]++
	fmt.Println("GetUserByEmail", email)
	var user User
	err := s.DB.View(func(tx *bbolt.Tx) error {
		b := tx.Bucket([]byte("users"))
		v := b.Get([]byte(email))
		if v == nil {
			fmt.Println("GetUserByEmail: user not found")
			s.Details.Stats["user_not_found"]++
			return nil
		}

		return user.UnmarshalBinary(v)
	})
	return user, err
}

func (s *Server) AddUser(u User) error {
	fmt.Println("AddUser", u)
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
	fmt.Println("GetServiceByKind", kind)
	var service ServiceType
	err := s.DB.View(func(tx *bbolt.Tx) error {
		b := tx.Bucket([]byte("services"))
		v := b.Get([]byte(kind))
		if v == nil {
			fmt.Println("GetServiceByKind: service not found")
			s.Details.Stats["service_not_found"]++
			return nil
		}

		return service.UnmarshalBinary(v)
	})
	return service, err
}

func (s *Server) AddService(st ServiceType) error {
	fmt.Println("AddService", st)
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
