package audit

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func TestRedact(t *testing.T) {
	in := map[string]string{"password": "hunter2", "user": "alice", "ntlm_hash": "deadbeef", "target": "DC01"}
	out := Redact(in)
	if out["password"] != "[REDACTED]" {
		t.Errorf("password not redacted: %q", out["password"])
	}
	if out["ntlm_hash"] != "[REDACTED]" {
		t.Errorf("hash not redacted: %q", out["ntlm_hash"])
	}
	if out["user"] != "alice" || out["target"] != "DC01" {
		t.Errorf("non-sensitive fields altered: %+v", out)
	}
}

func TestLogWritesJSONLine(t *testing.T) {
	var buf bytes.Buffer
	l := New(&buf)
	err := l.Log(Event{Actor: "api", Action: "test", Fields: map[string]string{"password": "hunter2"}})
	if err != nil {
		t.Fatalf("Log: %v", err)
	}
	line := strings.TrimSpace(buf.String())
	if strings.Contains(line, "hunter2") {
		t.Fatalf("password leaked into audit log: %s", line)
	}
	var e Event
	if err := json.Unmarshal([]byte(line), &e); err != nil {
		t.Fatalf("audit line is not valid JSON: %v (%s)", err, line)
	}
	if e.Time.IsZero() {
		t.Error("expected Time to be set")
	}
}
