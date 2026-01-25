package database

import (
	"database/sql"
	"sync"

	_ "github.com/mattn/go-sqlite3"
)

// DB wraps the SQLite database connection with thread-safe operations
type DB struct {
	conn *sql.DB
	mu   sync.RWMutex
}

// NewDB creates a new database connection and initializes the schema
func NewDB(dbPath string) (*DB, error) {
	conn, err := sql.Open("sqlite3", dbPath)
	if err != nil {
		return nil, err
	}

	// Set pragmas for performance and reliability
	_, err = conn.Exec(`
		PRAGMA journal_mode=WAL;
		PRAGMA synchronous=NORMAL;
		PRAGMA cache_size=-64000;
		PRAGMA foreign_keys=ON;
		PRAGMA busy_timeout=5000;
	`)
	if err != nil {
		conn.Close()
		return nil, err
	}

	// Initialize schema
	if _, err := conn.Exec(Schema); err != nil {
		conn.Close()
		return nil, err
	}

	return &DB{conn: conn}, nil
}

// Close closes the database connection
func (db *DB) Close() error {
	return db.conn.Close()
}

// Begin starts a new transaction
func (db *DB) Begin() (*sql.Tx, error) {
	return db.conn.Begin()
}

// Ping verifies the database connection is alive
func (db *DB) Ping() error {
	return db.conn.Ping()
}
