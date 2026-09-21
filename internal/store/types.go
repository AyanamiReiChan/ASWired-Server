package store

import (
	"database/sql"
	"encoding/json"
	"errors"
	"time"
)

var (
	ErrNotFound    = errors.New("record not found")
	ErrConflict    = errors.New("record already exists or was modified")
	ErrInitialized = errors.New("controller is already initialized")
	ErrInvalid     = errors.New("invalid record")
)

type Config struct {
	Driver string
	DSN    string
}

type Store struct {
	eventLog   func(map[string]any) error
	db         *sql.DB
	driver     string
	encryption *EncryptionCodec
}

type User struct {
	ID           string    `json:"id"`
	Username     string    `json:"username"`
	PasswordHash string    `json:"-"`
	Role         string    `json:"role"`
	Disabled     bool      `json:"disabled"`
	TokenVersion int64     `json:"-"`
	CreatedAt    time.Time `json:"createdAt"`
	UpdatedAt    time.Time `json:"updatedAt"`
}

type Record struct {
	Collection string         `json:"collection"`
	ID         string         `json:"id"`
	OwnerID    string         `json:"ownerId,omitempty"`
	Data       map[string]any `json:"data"`
	Version    int64          `json:"version"`
	CreatedAt  time.Time      `json:"createdAt"`
	UpdatedAt  time.Time      `json:"updatedAt"`
}

type AuditEvent struct {
	ID        string         `json:"id"`
	ActorID   string         `json:"actorId"`
	Action    string         `json:"action"`
	Target    string         `json:"target"`
	Details   map[string]any `json:"details,omitempty"`
	CreatedAt time.Time      `json:"createdAt"`
}

type Metric struct {
	ID         string         `json:"id"`
	ServerID   string         `json:"serverId"`
	RecordedAt time.Time      `json:"recordedAt"`
	Values     map[string]any `json:"values"`
}

type Task struct {
	expectedStatus    string
	expectedUpdatedAt time.Time
	ID                string          `json:"id"`
	ServerID          string          `json:"serverId"`
	ActorID           string          `json:"actorId"`
	Kind              string          `json:"kind"`
	Status            string          `json:"status"`
	LogsDeleted       bool            `json:"-"`
	LogReason         string          `json:"-"`
	Input             json.RawMessage `json:"input,omitempty"`
	Result            json.RawMessage `json:"result,omitempty"`
	Error             string          `json:"error,omitempty"`
	CreatedAt         time.Time       `json:"createdAt"`
	UpdatedAt         time.Time       `json:"updatedAt"`
}
