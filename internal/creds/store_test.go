package creds

import (
	"testing"
	"time"
)

func TestPutGetTake(t *testing.T) {
	s := NewStore(time.Minute, 0)
	id, _, err := s.Put("corp.local", "alice", []byte("hunter2"))
	if err != nil {
		t.Fatalf("Put: %v", err)
	}
	c, err := s.Get(id)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if string(c.Reveal()) != "hunter2" {
		t.Fatalf("secret mismatch: %q", c.Reveal())
	}
	// Take removes it.
	c2, err := s.Take(id)
	if err != nil {
		t.Fatalf("Take: %v", err)
	}
	c2.Destroy()
	if _, err := s.Get(id); err == nil {
		t.Fatal("expected not found after Take")
	}
}

func TestExpiry(t *testing.T) {
	s := NewStore(10*time.Second, 0)
	now := time.Now()
	s.nowFunc = func() time.Time { return now }
	id, _, err := s.Put("d", "u", []byte("x"))
	if err != nil {
		t.Fatal(err)
	}
	now = now.Add(11 * time.Second)
	if _, err := s.Get(id); err == nil {
		t.Fatal("expected expired credential to be gone")
	}
}

func TestMaxEvictsOldest(t *testing.T) {
	s := NewStore(time.Minute, 2)
	n := time.Now()
	s.nowFunc = func() time.Time { return n }
	id1, _, _ := s.Put("d", "u1", []byte("1"))
	n = n.Add(time.Second)
	id2, _, _ := s.Put("d", "u2", []byte("2"))
	n = n.Add(time.Second)
	_, _, _ = s.Put("d", "u3", []byte("3")) // evicts id1
	if _, err := s.Get(id1); err == nil {
		t.Fatal("expected oldest credential evicted")
	}
	if _, err := s.Get(id2); err != nil {
		t.Fatalf("expected id2 to remain: %v", err)
	}
}

func TestDestroyZeroes(t *testing.T) {
	secret := []byte("topsecret")
	c := &Credential{secret: secret}
	c.Destroy()
	for i, b := range secret {
		if b != 0 {
			t.Fatalf("byte %d not zeroed", i)
		}
	}
}

func TestEmptySecretRejected(t *testing.T) {
	s := NewStore(time.Minute, 0)
	if _, _, err := s.Put("d", "u", nil); err == nil {
		t.Fatal("expected error for empty secret")
	}
}

func TestPutCopiesSecret(t *testing.T) {
	s := NewStore(time.Minute, 0)
	orig := []byte("abc")
	id, _, _ := s.Put("d", "u", orig)
	orig[0] = 'z' // caller mutates their buffer
	c, _ := s.Get(id)
	if string(c.Reveal()) != "abc" {
		t.Fatalf("store aliased caller buffer: %q", c.Reveal())
	}
}
