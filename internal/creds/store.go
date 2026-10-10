// Package creds provides session-scoped, memory-only credential handling.
//
// Secrets are held as []byte (never string) so they can be explicitly zeroed
// after use, are never written to disk, and expire after a TTL or after a
// single consumption.
package creds

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"sync"
	"time"
)

// ErrNotFound is returned when a session id is unknown or expired.
var ErrNotFound = errors.New("creds: session not found or expired")

// Credential is a short-lived in-memory secret.
type Credential struct {
	Domain   string
	Username string

	secret  []byte
	created time.Time
	expires time.Time
}

// Reveal returns the raw secret. Callers MUST NOT retain it beyond the
// immediate operation and should call Destroy when finished.
func (c *Credential) Reveal() []byte { return c.secret }

// Expires returns the expiry time.
func (c *Credential) Expires() time.Time { return c.expires }

// Destroy zeroes the secret in place.
func (c *Credential) Destroy() { Zero(c.secret) }

// Zero overwrites b with zero bytes.
func Zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

type entry struct {
	cred    *Credential
	oneShot bool
}

// Store is a concurrency-safe, TTL-bounded, in-memory credential store.
type Store struct {
	mu      sync.Mutex
	m       map[string]*entry
	ttl     time.Duration
	max     int
	nowFunc func() time.Time
}

// NewStore creates a store whose credentials expire after ttl and which holds
// at most max live credentials (0 = unlimited).
func NewStore(ttl time.Duration, max int) *Store {
	if ttl <= 0 {
		ttl = 15 * time.Minute
	}
	return &Store{m: make(map[string]*entry), ttl: ttl, max: max, nowFunc: time.Now}
}

// Put stores a copy of secret and returns a fresh session id. The caller's
// slice is copied so the store never aliases caller memory.
func (s *Store) Put(domain, username string, secret []byte) (string, time.Time, error) {
	if len(secret) == 0 {
		return "", time.Time{}, errors.New("creds: empty secret")
	}
	id, err := newID()
	if err != nil {
		return "", time.Time{}, err
	}
	buf := make([]byte, len(secret))
	copy(buf, secret)
	now := s.nowFunc()
	c := &Credential{Domain: domain, Username: username, secret: buf, created: now, expires: now.Add(s.ttl)}

	s.mu.Lock()
	defer s.mu.Unlock()
	s.sweepLocked(now)
	if s.max > 0 && len(s.m) >= s.max {
		s.evictOldestLocked()
	}
	s.m[id] = &entry{cred: c}
	return id, c.expires, nil
}

// Get returns a credential without consuming it. Expired entries are removed.
func (s *Store) Get(id string) (*Credential, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sweepLocked(s.nowFunc())
	e, ok := s.m[id]
	if !ok {
		return nil, ErrNotFound
	}
	return e.cred, nil
}

// Take returns a credential and removes it from the store (one-shot use).
func (s *Store) Take(id string) (*Credential, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sweepLocked(s.nowFunc())
	e, ok := s.m[id]
	if !ok {
		return nil, ErrNotFound
	}
	delete(s.m, id)
	return e.cred, nil
}

// Delete removes and zeroes a credential.
func (s *Store) Delete(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if e, ok := s.m[id]; ok {
		e.cred.Destroy()
		delete(s.m, id)
	}
}

// Len returns the number of live credentials (after sweeping expired ones).
func (s *Store) Len() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sweepLocked(s.nowFunc())
	return len(s.m)
}

// Close zeroes and drops every credential.
func (s *Store) Close() {
	s.mu.Lock()
	defer s.mu.Unlock()
	for id, e := range s.m {
		e.cred.Destroy()
		delete(s.m, id)
	}
}

func (s *Store) sweepLocked(now time.Time) {
	for id, e := range s.m {
		if now.After(e.cred.expires) {
			e.cred.Destroy()
			delete(s.m, id)
		}
	}
}

func (s *Store) evictOldestLocked() {
	var oldestID string
	var oldest time.Time
	for id, e := range s.m {
		if oldestID == "" || e.cred.created.Before(oldest) {
			oldestID, oldest = id, e.cred.created
		}
	}
	if oldestID != "" {
		s.m[oldestID].cred.Destroy()
		delete(s.m, oldestID)
	}
}

func newID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
