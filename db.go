package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io" // <-- ADDED THIS
	"os/exec"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"go.etcd.io/bbolt"
)

type Database interface {
	Backup(w io.Writer) error // <-- CHANGED THIS
	Restore(filePath string) error
	GetUserByEmail(email string) (User, error)
	DeleteUser(email string) error
	GetAllUsers() ([]User, error)
	AddUser(u User) error
	GetServiceByKind(kind string) (ServiceType, error)
	AddService(st ServiceType) error
	GetTokenByValue(tk string) (Token, error)
	SaveToken(t Token) error
	StoreResponse(archive bool, id string, data []byte, vendor string) error
	GetResponse(id string) ([]byte, error)
	GetResponses(expiration time.Time) ([]ResponseItem, error)
	DeleteResponse(id string) error
	TestAndRecconect() error
}

type BboltDB struct {
	DB *bbolt.DB
}

func (db *BboltDB) TestAndRecconect() error {
	fmt.Println("TestAndRecconect")
	return nil
}

// TODO verify me
func (db *BboltDB) GetResponses(expiration time.Time) ([]ResponseItem, error) {
	var responses []ResponseItem
	err := db.DB.View(func(tx *bbolt.Tx) error {
		b := tx.Bucket([]byte("responses"))
		if b == nil {
			return nil
		}
		return b.ForEach(func(k, v []byte) error {
			var resp ResponseItem
			if err := json.Unmarshal(v, &resp); err != nil {
				return fmt.Errorf("unmarshal response: %w", err)
			}
			if resp.Time.After(expiration) {
				resp.ID = string(k)
				responses = append(responses, resp)
			}
			return nil
		})
	})
	return responses, err
}

func (db *BboltDB) GetUserByEmail(email string) (User, error) {
	var user User
	err := db.DB.Update(func(tx *bbolt.Tx) error {
		_, err := tx.CreateBucketIfNotExists([]byte("users"))
		return err
	})
	if err != nil {
		return user, err
	}

	err = db.DB.View(func(tx *bbolt.Tx) error {
		b := tx.Bucket([]byte("users"))
		v := b.Get([]byte(email))
		if v == nil {
			return nil
		}

		return user.UnmarshalBinary(v)
	})
	return user, err
}

func (db *BboltDB) StoreResponse(archive bool, id string, data []byte, vendor string) error {
	return db.DB.Update(func(tx *bbolt.Tx) error {
		b, err := tx.CreateBucketIfNotExists([]byte("responses"))
		if err != nil {
			return err
		}
		return b.Put([]byte(id), data)
	})
}

func (db *BboltDB) Backup(w io.Writer) error { // <-- CHANGED THIS
	fmt.Println("not implemented: BboltDB Backup")
	return nil
}

func (db *BboltDB) Restore(filePath string) error {
	fmt.Println("not implemented: BboltDB Restore")
	return nil
}

func (db *BboltDB) GetResponse(id string) ([]byte, error) {
	var data []byte
	err := db.DB.View(func(tx *bbolt.Tx) error {
		b := tx.Bucket([]byte("responses"))
		v := b.Get([]byte(id))
		if v == nil {
			return nil
		}
		data = make([]byte, len(v))
		copy(data, v)
		return nil
	})
	return data, err
}

func (db *BboltDB) DeleteResponse(id string) error {
	return db.DB.Update(func(tx *bbolt.Tx) error {
		b, err := tx.CreateBucketIfNotExists([]byte("responses"))
		if err != nil {
			fmt.Println("create bucket: ", err)
			return err
		}
		return b.Delete([]byte(id))
	})
}

func (db *BboltDB) DeleteUser(email string) error {
	return db.DB.Update(func(tx *bbolt.Tx) error {
		b, err := tx.CreateBucketIfNotExists([]byte("users"))
		if err != nil {
			return fmt.Errorf("create bucket: %s", err)
		}
		return b.Delete([]byte(email))
	})
}

func (db *BboltDB) GetAllUsers() ([]User, error) {
	var users []User
	err := db.DB.Update(func(tx *bbolt.Tx) error {
		_, err := tx.CreateBucketIfNotExists([]byte("users"))
		return err
	})
	if err != nil {
		return nil, err
	}
	err = db.DB.View(func(tx *bbolt.Tx) error {
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
	err := db.DB.Update(func(tx *bbolt.Tx) error {
		_, err := tx.CreateBucketIfNotExists([]byte("services"))
		return err
	})
	if err != nil {
		return service, err
	}
	err = db.DB.View(func(tx *bbolt.Tx) error {
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
	err := db.DB.Update(func(tx *bbolt.Tx) error {
		_, err := tx.CreateBucketIfNotExists([]byte("tokens"))
		return err
	})
	if err != nil {
		return token, err
	}
	err = db.DB.View(func(tx *bbolt.Tx) error {
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

// POSTGRES TYPE
type PostgresDB struct {
	Pool *pgxpool.Pool
}

func NewPostgresDB(dsn string) (*PostgresDB, error) {
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return nil, err
	}
	pool, err := pgxpool.NewWithConfig(context.Background(), cfg)
	if err != nil {
		return nil, err
	}
	p := &PostgresDB{Pool: pool}
	if err := p.createTables(); err != nil {
		return nil, err
	}
	fmt.Println("PostgresDB created, cleaning old responses")
	err = p.CleanResponses()
	if err != nil {
		return nil, err
	}
	return p, nil
}

func (db *PostgresDB) createTables() error {
	_, err := db.Pool.Exec(context.Background(),
		`CREATE TABLE IF NOT EXISTS services (
            id SERIAL PRIMARY KEY,
            upload_service BOOLEAN,
            expires INT,
            secret TEXT,
            selected BOOLEAN,
            insecure BOOLEAN,
            name TEXT,
            url TEXT,
            rate_limited BOOLEAN,
            max_requests INT,
            refill_rate INT,
            auth_type TEXT,
            key TEXT,
            kind TEXT,
            type TEXT[],
            route_map JSONB
        );
        CREATE TABLE IF NOT EXISTS responses (
        id TEXT PRIMARY KEY,
        data BYTEA NOT NULL,
        created TIMESTAMP,
        vendor TEXT NOT NULL
);
    CREATE TABLE IF NOT EXISTS archived_responses (
            id TEXT PRIMARY KEY,
            data BYTEA NOT NULL,
            created TIMESTAMP,
            vendor TEXT NOT NULL
    );
        CREATE TABLE IF NOT EXISTS users (
                email TEXT PRIMARY KEY,
                admin BOOLEAN,
                key TEXT,
                hash BYTEA,
                services JSONB,
                created TIMESTAMP,
                updated TIMESTAMP
        );
        CREATE TABLE IF NOT EXISTS tokens (
                token TEXT PRIMARY KEY,
                expires_at TIMESTAMP,
                email TEXT,
                hash BYTEA
                );
            `)
	return err
}

// Backup executes pg_dump and streams its output to the provided io.Writer.
func (db *PostgresDB) Backup(w io.Writer) error {
	dsn := db.Pool.Config().ConnString()

	// Prepare the pg_dump command
	// By omitting -f, pg_dump writes to stdout.
	cmd := exec.Command("pg_dump",
		"-d", dsn,
		// "-f", filePath, // <-- REMOVED
		"--clean",     // Add 'DROP' statements before 'CREATE'
		"--if-exists", // Add 'IF EXISTS' to 'DROP' statements
	)

	cmd.Stdout = w

	var stderr bytes.Buffer
	cmd.Stderr = &stderr

	// Run the command
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("pg_dump failed: %s: %w", stderr.String(), err)
	}

	fmt.Println("Database backup stream successful.")
	return nil
}

// Restore executes psql using the pool's connection string.
// !! WARNING: This is a destructive operation.
func (db *PostgresDB) Restore(filePath string) error {
	// Get the original connection string for re-connecting
	// and for the psql command.
	dsn := db.Pool.Config().ConnString()

	// --- 1. Close the current connection pool ---
	db.Pool.Close()
	fmt.Println("Database pool closed for restore.")

	// --- 2. Prepare and run the psql command ---
	// psql also accepts the full DSN with the -d flag.
	cmd := exec.Command("psql",
		"-d", dsn,
		"-f", filePath, // Input file
	)

	var stderr bytes.Buffer
	cmd.Stderr = &stderr

	// Run the command
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("psql restore failed: %s: %w", stderr.String(), err)
	}

	fmt.Printf("Database restore successful from: %s\n", filePath)

	// --- 3. Re-open the connection pool ---
	poolCfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return fmt.Errorf("failed to parse config for re-connect: %w", err)
	}

	pool, err := pgxpool.NewWithConfig(context.Background(), poolCfg)
	if err != nil {
		return fmt.Errorf("failed to re-connect pool after restore: %w", err)
	}

	// Assign the new pool back to the struct
	db.Pool = pool
	fmt.Println("Database pool re-connected.")
	return nil
}

func (db *PostgresDB) CleanResponses() error {
	var expiration time.Time = time.Now().Add(-time.Hour * 24)
	_, err := db.Pool.Exec(context.Background(), "DELETE FROM responses WHERE created < $1", expiration)
	return err
}

func (db *PostgresDB) StoreResponse(archive bool, id string, data []byte, vendor string) error {
	tableName := "responses"
	if archive {
		tableName = "archived_responses"
	}
	_, err := db.Pool.Exec(context.Background(),
		fmt.Sprintf("INSERT INTO %s (id, data, created, vendor) VALUES ($1, $2, $3, $4) ON CONFLICT (id) DO UPDATE SET data = EXCLUDED.data, created = EXCLUDED.created, vendor = EXCLUDED.vendor",
			tableName),
		id, data, time.Now(), vendor)
	return err
}

func (db *PostgresDB) GetResponse(id string) ([]byte, error) {
	var data []byte

	err := db.Pool.QueryRow(context.Background(), "SELECT data FROM responses WHERE id = $1", id).Scan(&data)
	if err == nil {
		return data, nil
	}

	if errors.Is(err, pgx.ErrNoRows) {
		err = db.Pool.QueryRow(context.Background(), "SELECT data FROM archived_responses WHERE id = $1", id).Scan(&data)
		if err != nil {
			return nil, fmt.Errorf("response not found in primary or archive table for id %s: %w", id, err)
		}
		fmt.Println("Response found in archive for id:", id)
		return data, nil
	}

	// any other type of error (connection issue, etc.)
	return nil, fmt.Errorf("database error checking primary table for id %s: %w", id, err)
}

func (db *PostgresDB) DeleteResponse(id string) error {
	_, err := db.Pool.Exec(context.Background(), "DELETE FROM responses WHERE id = $1", id)
	return err
}

func (db *PostgresDB) TestAndRecconect() error {
	return db.Pool.Ping(context.Background())
}

func (db *PostgresDB) GetResponses(expiration time.Time) ([]ResponseItem, error) {
	rows, err := db.Pool.Query(context.Background(), "SELECT id, data, created, vendor FROM responses WHERE created > $1", expiration)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var responses []ResponseItem
	for rows.Next() {
		var resp ResponseItem
		var data []byte
		if err := rows.Scan(&resp.ID, &data, &resp.Time, &resp.Vendor); err != nil {
			return nil, err
		}
		resp.Data = data
		responses = append(responses, resp)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return responses, nil
}

func (db *PostgresDB) GetUserByEmail(email string) (User, error) {
	var user User
	err := db.Pool.QueryRow(context.Background(), "SELECT * FROM users WHERE email = $1", email).Scan(
		&user.Email, &user.Admin, &user.Key, &user.Hash, &user.Services, &user.Created, &user.Updated,
	)
	return user, err
}

func (db *PostgresDB) AddUser(u User) error {
	_, err := db.Pool.Exec(context.Background(), `
        INSERT INTO users (email, admin, key, hash, services, created, updated)
        VALUES ($1, $2, $3, $4, $5, $6, $7)
        ON CONFLICT (email) DO UPDATE SET
            admin = EXCLUDED.admin,
            key = EXCLUDED.key,
            hash = EXCLUDED.hash,
            services = EXCLUDED.services,
            created = EXCLUDED.created,
            updated = EXCLUDED.updated
    `, u.Email, u.Admin, u.Key, u.Hash, u.Services, u.Created, u.Updated)
	return err
}

func (db *PostgresDB) DeleteUser(email string) error {
	_, err := db.Pool.Exec(context.Background(), "DELETE FROM users WHERE email = $1", email)
	return err
}

func (db *PostgresDB) GetAllUsers() ([]User, error) {
	rows, err := db.Pool.Query(context.Background(), "SELECT * FROM users")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var users []User
	for rows.Next() {
		var user User
		if err := rows.Scan(&user.Email, &user.Admin, &user.Key, &user.Hash, &user.Services, &user.Created, &user.Updated); err != nil {
			return nil, err
		}
		users = append(users, user)
	}
	return users, nil
}

func (db *PostgresDB) GetServiceByKind(kind string) (ServiceType, error) {
	var service ServiceType
	err := db.Pool.QueryRow(context.Background(), "SELECT * FROM services WHERE kind = $1", kind).Scan(
		&service.UploadService, &service.Expires, &service.Secret, &service.Selected, &service.Insecure, &service.Name,
		&service.URL, &service.RateLimited, &service.MaxRequests, &service.RefillRate, &service.AuthType, &service.Key, &service.Kind,
		&service.Type, &service.RouteMap,
	)
	return service, err
}

func (db *PostgresDB) AddService(st ServiceType) error {
	_, err := db.Pool.Exec(context.Background(),
		`INSERT INTO services (upload_service, expires, secret, selected, insecure, name, url, rate_limited, max_requests, refill_rate, auth_type, key, kind, type, route_map)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)`,
		st.UploadService, st.Expires, st.Secret, st.Selected, st.Insecure, st.Name, st.URL, st.RateLimited, st.MaxRequests, st.RefillRate, st.AuthType, st.Key, st.Kind, st.Type, st.RouteMap,
	)
	return err
}

func (db *PostgresDB) GetTokenByValue(tk string) (Token, error) {
	var token Token
	err := db.Pool.QueryRow(context.Background(), "SELECT * FROM tokens WHERE token = $1", tk).Scan(
		&token.Token, &token.ExpiresAt, &token.Email, &token.Hash,
	)
	return token, err
}

func (db *PostgresDB) SaveToken(t Token) error {
	_, err := db.Pool.Exec(context.Background(),
		"INSERT INTO tokens (token, expires_at, email, hash) VALUES ($1, $2, $3, $4)",
		t.Token, t.ExpiresAt, t.Email, t.Hash,
	)
	return err
}
