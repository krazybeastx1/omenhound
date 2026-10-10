package collector

import (
	"encoding/binary"
	"testing"
)

func TestFormatSID(t *testing.T) {
	b := []byte{1, 4, 0, 0, 0, 0, 0, 5}
	for _, s := range []uint32{21, 1004336348, 1177238915, 682003330} {
		var x [4]byte
		binary.LittleEndian.PutUint32(x[:], s)
		b = append(b, x[:]...)
	}
	got, err := FormatSID(b)
	if err != nil {
		t.Fatalf("FormatSID: %v", err)
	}
	want := "S-1-5-21-1004336348-1177238915-682003330"
	if got != want {
		t.Fatalf("FormatSID = %q, want %q", got, want)
	}
}

func TestFormatSIDErrors(t *testing.T) {
	if _, err := FormatSID([]byte{1, 2, 3}); err == nil {
		t.Fatal("expected error for short SID")
	}
	// claims 4 subauthorities but only supplies 1
	if _, err := FormatSID([]byte{1, 4, 0, 0, 0, 0, 0, 5, 21, 0, 0, 0}); err == nil {
		t.Fatal("expected error for truncated SID")
	}
}

func TestDomainToDN(t *testing.T) {
	cases := map[string]string{
		"corp.local":    "DC=corp,DC=local",
		"omenhound.lab": "DC=omenhound,DC=lab",
		"ad.corp.local": "DC=ad,DC=corp,DC=local",
		"":              "",
	}
	for in, want := range cases {
		if got := DomainToDN(in); got != want {
			t.Errorf("DomainToDN(%q) = %q, want %q", in, got, want)
		}
	}
}
