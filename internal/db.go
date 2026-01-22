package internal

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io" // <-- ADDED THIS
	"os/exec"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"go.etcd.io/bbolt"
)

type Database interface {
	CleanResponses(t time.Duration) error
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
	CreateCase(c Case) error
	GetCases(limit int, offset int) ([]Case, error)
	GetCase(id string) (Case, error)
	UpdateCase(c Case) error
	DeleteCase(id string) error
	SearchCases(query string) ([]Case, error)
	RecordSearchBatch(values []string, email string) error
	GetSearchHistory(value string) (SearchRecord, error)
	CleanSearchHistory(days int) error
}

type BboltDB struct {
	DB *bbolt.DB
}

type Case struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	Description string    `json:"description"`
	CreatedBy   string    `json:"created_by"`
	CreatedAt   time.Time `json:"created_at"`
	Status      string    `json:"status"` // "Open", "Closed"
	IOCs        []string  `json:"iocs"`
	Comments    []Comment `json:"comments"`
	IOCCount    int       `json:"ioc_count"`
}

type Comment struct {
	User      string    `json:"user"`
	Text      string    `json:"text"`
	CreatedAt time.Time `json:"created_at"`
}

type SearchRecord struct {
	ID        string    `json:"id"`
	Value     string    `json:"value"`
	Emails    []string  `json:"emails"`
	CreatedAt time.Time `json:"created_at"`
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

func (db *BboltDB) GetCases(limit int, offset int) ([]Case, error) {
	fmt.Println("not implemented: BboltDB GetCases")
	return nil, nil
}

func (db *BboltDB) GetCase(id string) (Case, error) {
	fmt.Println("not implemented: BboltDB GetCase")
	return Case{}, nil
}

func (db *BboltDB) CreateCase(c Case) error {
	fmt.Println("not implemented: BboltDB CreateCase")
	return nil
}

func (db *BboltDB) SearchCases(query string) ([]Case, error) {
	fmt.Println("not implemented: BboltDB SearchCases")
	return nil, nil
}

func (db *BboltDB) UpdateCase(c Case) error {
	fmt.Println("not implemented: BboltDB UpdateCase")
	return nil
}

func (db *BboltDB) DeleteCase(id string) error {
	fmt.Println("not implemented: BboltDB DeleteCase")
	return nil
}

func (db *BboltDB) RecordSearch(value string, email string) error {
	fmt.Println("not implemented: BboltDB RecordSearch")
	return nil
}

func (db *BboltDB) GetSearchHistory(value string) (SearchRecord, error) {
	fmt.Println("not implemented: BboltDB GetSearchHistory")
	return SearchRecord{}, nil
}

func (db *BboltDB) CleanSearchHistory(days int) error {
	fmt.Println("not implemented: BboltDB CleanSearchHistory")
	return nil
}

func (db *BboltDB) CleanResponses(t time.Duration) error {
	fmt.Println("not implemented: BboltDB CleanResponses")
	return nil
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
	err = p.CleanResponsesAtStart(time.Hour * 24) // clean responses older than 24 hours
	if err != nil {
		return nil, err
	}
	return p, nil
}

func (db *PostgresDB) createTables() error {
	// First, standard table creation
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
        CREATE TABLE IF NOT EXISTS cases (
            id TEXT PRIMARY KEY,
            name TEXT,
            description TEXT,
            created_by TEXT,
            created_at TIMESTAMP,
            status TEXT,
            iocs JSONB,
            comments JSONB
        );
		CREATE TABLE IF NOT EXISTS search_history (
			id TEXT PRIMARY KEY,
			value TEXT UNIQUE,
			emails JSONB DEFAULT '[]'::jsonb,
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
		);
		CREATE INDEX IF NOT EXISTS idx_search_history_value ON search_history(value);`)
	if err != nil {
		return err
	}

	// OPTIMIZATION: Create Indexes and Extensions
	// We execute these separately to ensure the extension exists before using it in indexes.
	_, err = db.Pool.Exec(context.Background(), `
        -- Enable pg_trgm for efficient partial text searching (ILIKE)
        CREATE EXTENSION IF NOT EXISTS pg_trgm;

        -- Index for sorting by date and filtering by status (Speed up List View)
        CREATE INDEX IF NOT EXISTS idx_cases_status_created ON cases(status, created_at DESC);

        -- GIN Trigram indexes for fast text searching on Name and Description
        CREATE INDEX IF NOT EXISTS idx_cases_name_trgm ON cases USING gin (name gin_trgm_ops);
        CREATE INDEX IF NOT EXISTS idx_cases_desc_trgm ON cases USING gin (description gin_trgm_ops);

        -- SPECIAL INDEX: Index the CAST text version of the JSONB array.
        -- This makes "iocs::text ILIKE" fast for partial IP/Domain searches.
        CREATE INDEX IF NOT EXISTS idx_cases_iocs_text_trgm ON cases USING gin ((iocs::text) gin_trgm_ops);
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

func (db *PostgresDB) CleanResponsesAtStart(t time.Duration) error {
	var expiration time.Time = time.Now().Add(-t)
	_, err := db.Pool.Exec(context.Background(), "DELETE FROM responses WHERE created < $1", expiration)
	return err
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

func (db *PostgresDB) CleanResponses(t time.Duration) error {
	var expiration time.Time = time.Now().Add(t)
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
	// 1. Try to delete from the active 'responses' table
	ct, err := db.Pool.Exec(context.Background(), "DELETE FROM responses WHERE id = $1", id)
	if err != nil {
		return fmt.Errorf("db error deleting from responses: %w", err)
	}

	// If we deleted at least 1 row, we are done.
	if ct.RowsAffected() > 0 {
		return nil
	}

	// 2. If RowsAffected was 0, try the 'archived_responses' table
	ct, err = db.Pool.Exec(context.Background(), "DELETE FROM archived_responses WHERE id = $1", id)
	if err != nil {
		return fmt.Errorf("db error deleting from archived_responses: %w", err)
	}

	// 3. If RowsAffected is still 0, the ID doesn't exist in either table
	if ct.RowsAffected() == 0 {
		return fmt.Errorf("response id %s not found in either table", id)
	}

	return nil
}

func (db *PostgresDB) TestAndRecconect() error {
	return db.Pool.Ping(context.Background())
}

func (db *PostgresDB) GetResponses(expiration time.Time) ([]ResponseItem, error) {
	var query string
	var args []interface{}

	if expiration.IsZero() {
		// CASE 1: Show Archived (Checkbox Checked)
		// Combine both tables using UNION ALL.
		query = `
            SELECT id, data, created, vendor FROM responses
            UNION ALL
            SELECT id, data, created, vendor FROM archived_responses
            ORDER BY created DESC`
	} else {
		// CASE 2: Standard View (Checkbox Unchecked)
		// Select only from the active table with the time filter.
		query = `
            SELECT id, data, created, vendor FROM responses 
            WHERE created > $1 
            ORDER BY created DESC`
		args = append(args, expiration)
	}
	// Pass the variable arguments (args...) to the query
	rows, err := db.Pool.Query(context.Background(), query, args...)
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

func (db *PostgresDB) CreateCase(c Case) error {
	_, err := db.Pool.Exec(context.Background(),
		`INSERT INTO cases (id, name, description, created_by, created_at, status, iocs, comments)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
		c.ID, c.Name, c.Description, c.CreatedBy, c.CreatedAt, c.Status, c.IOCs, c.Comments,
	)
	return err
}

// Optimized GetCases with Pagination and Column Selection
func (db *PostgresDB) GetCases(limit, offset int) ([]Case, error) {
	// Optimized query: fetches the count instead of the full array
	sql := `
        SELECT id, name, description, created_by, created_at, status, 
               jsonb_array_length(iocs) as ioc_count 
        FROM cases 
        ORDER BY created_at DESC 
        LIMIT $1 OFFSET $2
    `
	rows, err := db.Pool.Query(context.Background(), sql, limit, offset)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var cases []Case
	for rows.Next() {
		var c Case
		// SCAN directly into c.IOCCount
		if err := rows.Scan(&c.ID, &c.Name, &c.Description, &c.CreatedBy, &c.CreatedAt, &c.Status, &c.IOCCount); err != nil {
			return nil, err
		}
		cases = append(cases, c)
	}
	return cases, nil
}

func (db *PostgresDB) GetCase(id string) (Case, error) {
	var c Case
	err := db.Pool.QueryRow(context.Background(), "SELECT * FROM cases WHERE id = $1", id).Scan(
		&c.ID, &c.Name, &c.Description, &c.CreatedBy, &c.CreatedAt, &c.Status, &c.IOCs, &c.Comments,
	)
	return c, err
}

func (db *PostgresDB) UpdateCase(c Case) error {
	_, err := db.Pool.Exec(context.Background(),
		`UPDATE cases SET name = $1, description = $2, created_by = $3, created_at = $4, status = $5, iocs = $6, comments = $7
		WHERE id = $8`,
		c.Name, c.Description, c.CreatedBy, c.CreatedAt, c.Status, c.IOCs, c.Comments, c.ID,
	)
	return err
}

func (db *PostgresDB) DeleteCase(id string) error {
	_, err := db.Pool.Exec(context.Background(), "DELETE FROM cases WHERE id = $1", id)
	return err
}

func (db *PostgresDB) SearchCases(query string) ([]Case, error) {
	// We select specific columns.
	// We use ILIKE which will now use the 'gin_trgm_ops' indexes created above.
	// We LIMIT 100 to protect the app/db from massive result sets.
	sql := `
        SELECT id, name, description, created_by, created_at, status, iocs, comments 
        FROM cases 
        WHERE status = 'Open' 
        AND (
            name ILIKE $1 
            OR description ILIKE $1 
            OR iocs::text ILIKE $1
        )
        ORDER BY created_at DESC
        LIMIT 100
    `
	// Add wildcards for "contains" search
	likeQuery := "%" + query + "%"

	rows, err := db.Pool.Query(context.Background(), sql, likeQuery)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var cases []Case
	for rows.Next() {
		var c Case
		// We still scan iocs/comments, but the LIMIT 100 keeps it safe.
		if err := rows.Scan(&c.ID, &c.Name, &c.Description, &c.CreatedBy, &c.CreatedAt, &c.Status, &c.IOCs, &c.Comments); err != nil {
			return nil, err
		}
		cases = append(cases, c)
	}
	return cases, nil
}

func (db *PostgresDB) RecordSearchBatch(values []string, email string) error {
	batch := &pgx.Batch{}
	sql := `
		INSERT INTO search_history (id, value, emails, created_at)
		VALUES ($1, $2, jsonb_build_array($3::text), NOW())
		ON CONFLICT (value) DO UPDATE SET
			emails = (
				SELECT jsonb_agg(DISTINCT e)
				FROM jsonb_array_elements_text(search_history.emails || EXCLUDED.emails) AS e
			),
			created_at = NOW();`

	for _, val := range values {
		batch.Queue(sql, uuid.New().String(), val, email)
	}

	results := db.Pool.SendBatch(context.Background(), batch)
	return results.Close()
}

// Implement a no-op for BboltDB to satisfy the interface if necessary
func (db *BboltDB) RecordSearchBatch(values []string, email string) error { return nil }

func (db *PostgresDB) GetSearchHistory(value string) (SearchRecord, error) {
	var sr SearchRecord
	// We query the search_history table created earlier to see who else
	// looked for this specific IP, domain, or hash.
	query := `SELECT id, value, emails, created_at FROM search_history WHERE value = $1`

	err := db.Pool.QueryRow(context.Background(), query, value).Scan(
		&sr.ID, &sr.Value, &sr.Emails, &sr.CreatedAt,
	)
	return sr, err
}

func (db *PostgresDB) CleanSearchHistory(days int) error {
	_, err := db.Pool.Exec(context.Background(),
		"DELETE FROM search_history WHERE created_at < NOW() - ($1 || ' days')::interval", days)
	return err
}
