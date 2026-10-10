package creds

import (
	"context"
	"testing"
	"time"
)

func TestSecretTooLongRejected(t *testing.T) {
	s := NewStore(time.Minute, 0)
	if _, _, err := s.Put("d", "u", make([]byte, maxSecretLen+1)); err == nil {
		t.Fatal("expected error for oversized secret")
	}
	if _, _, err := s.Put("d", "u", make([]byte, maxSecretLen)); err != nil {
		t.Fatalf("secret at the limit should be accepted: %v", err)
	}
}

func TestJanitorSweepsExpired(t *testing.T) {
	s := NewStore(time.Second, 0)
	now := time.Now()
	s.nowFunc = func() time.Time { return now }

	if _, _, err := s.Put("d", "u", []byte("x")); err != nil {
		t.Fatal(err)
	}
	now = now.Add(2 * time.Second) // expire it without touching the store

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go s.Janitor(ctx, time.Millisecond)

	deadline := time.After(2 * time.Second)
	for {
		s.mu.Lock()
		n := len(s.m)
		s.mu.Unlock()
		if n == 0 {
			return
		}
		select {
		case <-deadline:
			t.Fatalf("janitor did not sweep expired credential (len=%d)", n)
		case <-time.After(5 * time.Millisecond):
		}
	}
}
