package collector

import (
	"strings"
	"testing"
)

func TestNormalizeHash(t *testing.T) {
	ok := []struct{ in, want string }{
		{"31d6cfe0d16ae931b73c59d7e0c089c0", "31d6cfe0d16ae931b73c59d7e0c089c0"},
		{"31D6CFE0D16AE931B73C59D7E0C089C0", "31d6cfe0d16ae931b73c59d7e0c089c0"},
		// impacket's LM:NT form: the LM half is ignored.
		{"aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0", "31d6cfe0d16ae931b73c59d7e0c089c0"},
		{":31D6CFE0D16AE931B73C59D7E0C089C0", "31d6cfe0d16ae931b73c59d7e0c089c0"},
		{"  31d6cfe0d16ae931b73c59d7e0c089c0  ", "31d6cfe0d16ae931b73c59d7e0c089c0"},
	}
	for _, tc := range ok {
		got, err := NormalizeHash(tc.in)
		if err != nil {
			t.Errorf("NormalizeHash(%q) error: %v", tc.in, err)
			continue
		}
		if got != tc.want {
			t.Errorf("NormalizeHash(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}

	bad := []string{
		"",
		"31d6cfe0d16ae931b73c59d7e0c089c",   // 31 hex
		"31d6cfe0d16ae931b73c59d7e0c089c0f", // 33 hex
		"zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz",  // not hex
		"aad3b435b51404eeaad3b435b51404ee:nothexnothex", // bad NT half
	}
	for _, in := range bad {
		if _, err := NormalizeHash(in); err == nil {
			t.Errorf("NormalizeHash(%q) accepted, want error", in)
		}
	}
}

func TestEffectiveAuthMethod(t *testing.T) {
	cases := []struct {
		name string
		o    Options
		want string
	}{
		{"default is simple", Options{}, AuthSimple},
		{"hashes imply ntlm", Options{Hashes: []byte("31d6cfe0d16ae931b73c59d7e0c089c0")}, AuthNTLM},
		{"explicit ntlm", Options{AuthMethod: "ntlm"}, AuthNTLM},
		{"auto with hashes", Options{AuthMethod: "auto", Hashes: []byte("deadbeef")}, AuthNTLM},
		{"case-insensitive", Options{AuthMethod: "SIMPLE"}, AuthSimple},
		{"kerberos", Options{AuthMethod: "kerberos"}, AuthKerberos},
	}
	for _, tc := range cases {
		got, err := tc.o.EffectiveAuthMethod()
		if err != nil {
			t.Errorf("%s: %v", tc.name, err)
			continue
		}
		if got != tc.want {
			t.Errorf("%s: EffectiveAuthMethod = %q, want %q", tc.name, got, tc.want)
		}
	}
	if _, err := (Options{AuthMethod: "teleport"}).EffectiveAuthMethod(); err == nil {
		t.Error("an unknown auth method must be rejected")
	}
}

func TestSplitUserDomain(t *testing.T) {
	cases := []struct{ user, domain, wantUser, wantDomain string }{
		{`CORP\jdoe`, "corp.local", "jdoe", "CORP"},
		{`jdoe@corp.local`, "ignored.example", "jdoe", "corp.local"},
		{"jdoe", "corp.local", "jdoe", "corp.local"},
		{`CORP\jdoe`, "", "jdoe", "CORP"},
		{"  jdoe  ", " corp.local ", "jdoe", " corp.local "},
	}
	for _, tc := range cases {
		u, d := SplitUserDomain(tc.user, tc.domain)
		if u != tc.wantUser || (tc.domain != "" && d != tc.wantDomain) {
			t.Errorf("SplitUserDomain(%q,%q) = (%q,%q), want (%q,%q)", tc.user, tc.domain, u, d, tc.wantUser, tc.wantDomain)
		}
	}
}

func TestValidateOptionsAuth(t *testing.T) {
	base := Options{Server: "dc01", Domain: "corp.local", Username: "jdoe", UseLDAPS: true}

	ntlmHash := base
	ntlmHash.Hashes = []byte("31d6cfe0d16ae931b73c59d7e0c089c0")
	if err := validateOptions(ntlmHash); err != nil {
		t.Errorf("NTLM pass-the-hash over LDAPS should validate: %v", err)
	}

	simpleHash := base
	simpleHash.AuthMethod = AuthSimple
	simpleHash.Hashes = []byte("31d6cfe0d16ae931b73c59d7e0c089c0")
	if err := validateOptions(simpleHash); err == nil {
		t.Error("--hashes with simple bind must be rejected")
	}

	krb := base
	krb.AuthMethod = AuthKerberos
	err := validateOptions(krb)
	if err == nil || !strings.Contains(err.Error(), "not implemented") {
		t.Errorf("kerberos must fail loudly as not implemented, got %v", err)
	}

	unknown := base
	unknown.AuthMethod = "teleport"
	if err := validateOptions(unknown); err == nil {
		t.Error("an unknown auth method must be rejected before any network traffic")
	}

	// NTLM without TLS is still refused unless explicitly allowed.
	cleartext := Options{Server: "dc01", Domain: "corp.local", Username: "jdoe", AuthMethod: AuthNTLM}
	if err := validateOptions(cleartext); err == nil {
		t.Error("cleartext NTLM must be refused without --allow-plaintext-ldap")
	}
	cleartext.AllowPlaintextLDAP = true
	if err := validateOptions(cleartext); err != nil {
		t.Errorf("explicit cleartext opt-in should be accepted: %v", err)
	}
}
