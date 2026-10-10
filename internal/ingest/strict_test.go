package ingest

import (
	"strings"
	"testing"
)

func TestDecodeStrictRejectsUnknownFields(t *testing.T) {
	j := `{"nodes":[{"id":"A","kind":"User"}],"edges":[],"surprise":1}`
	if _, err := DecodeStrict(strings.NewReader(j)); err == nil {
		t.Fatal("expected DecodeStrict to reject an unknown field")
	}
}

func TestDecodeLenientAllowsUnknownFields(t *testing.T) {
	j := `{"nodes":[{"id":"A","kind":"User"}],"edges":[],"surprise":1}`
	if _, err := Decode(strings.NewReader(j)); err != nil {
		t.Fatalf("lenient Decode should tolerate extra fields: %v", err)
	}
}

func TestDecodeStrictRejectsTrailingData(t *testing.T) {
	j := `{"nodes":[],"edges":[]}{"more":true}`
	if _, err := DecodeStrict(strings.NewReader(j)); err == nil {
		t.Fatal("expected DecodeStrict to reject trailing data")
	}
}
