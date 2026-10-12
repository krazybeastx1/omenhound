// Package audit records who did what, when, and why for every action
// OmenHound takes against Active Directory. Because the credential-change
// feature turns OmenHound into an AD actor (not merely an observer), this
// trail is deliberately separate from AD's own event logs.
package audit

import (
	"encoding/json"
	"io"
	"strings"
	"sync"
	"time"
)

// Event is one auditable action.
type Event struct {
	Time       time.Time         `json:"time"`
	Actor      string            `json:"actor"`
	Action     string            `json:"action"`
	Target     string            `json:"target,omitempty"`
	Result     string            `json:"result"`
	Reason     string            `json:"reason,omitempty"`
	RemoteAddr string            `json:"remote_addr,omitempty"`
	Fields     map[string]string `json:"fields,omitempty"`
}

// sensitiveKeys are redacted before an event is written, so passwords and
// credential material can never reach the audit log.
var sensitiveKeys = []string{"password", "passwd", "secret", "token", "ntlm", "hash", "credential", "apikey", "api_key", "session_key"}

// Redact returns a copy of fields with any sensitive-looking key replaced.
func Redact(fields map[string]string) map[string]string {
	if fields == nil {
		return nil
	}
	out := make(map[string]string, len(fields))
	for k, v := range fields {
		if isSensitive(k) {
			out[k] = "[REDACTED]"
			continue
		}
		out[k] = v
	}
	return out
}

func isSensitive(key string) bool {
	lk := strings.ToLower(key)
	for _, s := range sensitiveKeys {
		if strings.Contains(lk, s) {
			return true
		}
	}
	return false
}

// Logger serialises events as JSON lines to an io.Writer. It is safe for
// concurrent use.
type Logger struct {
	mu        sync.Mutex
	w         io.Writer
	events    []Event
	maxEvents int
}

// New returns a Logger writing JSON lines to w.
func New(w io.Writer) *Logger { return &Logger{w: w, maxEvents: 1000} }

// Log writes one event. Fields are redacted first.
func (l *Logger) Log(e Event) error {
	if e.Time.IsZero() {
		e.Time = time.Now().UTC()
	}
	e.Fields = Redact(e.Fields)
	b, err := json.Marshal(e)
	if err != nil {
		return err
	}
	b = append(b, '\n')
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.w != nil {
		_, err = l.w.Write(b)
	}
	// Keep in-memory ring buffer
	l.events = append(l.events, e)
	if len(l.events) > l.maxEvents {
		l.events = l.events[len(l.events)-l.maxEvents:]
	}
	return err
}

// GetEvents returns the last n events (most recent first).
func (l *Logger) GetEvents(n int) []Event {
	l.mu.Lock()
	defer l.mu.Unlock()
	if n <= 0 || n > len(l.events) {
		n = len(l.events)
	}
	out := make([]Event, n)
	// Return most recent first
	for i := 0; i < n; i++ {
		out[i] = l.events[len(l.events)-1-i]
	}
	return out
}
