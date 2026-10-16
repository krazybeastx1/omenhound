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
		{"aes key implies kerberos", Options{AESKey: make([]byte, 16)}, AuthKerberos},
		{"kcache implies kerberos", Options{UseKcache: true}, AuthKerberos},
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

func TestSimpleBindName(t *testing.T) {
	cases := []struct{ user, domain, want string }{
		{`htb.local\svc-alfresco`, "htb.local", "svc-alfresco@htb.local"},
		{`CORP\jdoe`, "corp.local", `CORP\jdoe`},
		{"jdoe", "corp.local", "jdoe@corp.local"},
		{"jdoe@corp.local", "corp.local", "jdoe@corp.local"},
		{"CN=jdoe,CN=Users,DC=corp,DC=local", "corp.local", "CN=jdoe,CN=Users,DC=corp,DC=local"},
		{"jdoe", "CORP", "jdoe"},
		{"  htb.local\\svc-alfresco  ", "htb.local", "svc-alfresco@htb.local"},
	}
	for _, tc := range cases {
		if got := SimpleBindName(tc.user, tc.domain); got != tc.want {
			t.Errorf("SimpleBindName(%q,%q) = %q, want %q", tc.user, tc.domain, got, tc.want)
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

	// Kerberos without a credential source is refused before any traffic.
	krb := base
	krb.AuthMethod = AuthKerberos
	err := validateOptions(krb)
	if err == nil || !strings.Contains(err.Error(), "no credentials") {
		t.Errorf("kerberos without credentials must be refused, got %v", err)
	}

	// A password satisfies the Kerberos credential requirement (the specific
	// bind still needs a real KDC, so it is exercised separately).
	krbPw := krb
	krbPw.Password = []byte("hunter2")
	if err := validateOptions(krbPw); err != nil {
		t.Errorf("kerberos with a password should validate: %v", err)
	}

	// Kerberos needs the DC hostname, not its address.
	krbIP := krbPw
	krbIP.Server = "10.0.0.5"
	if err := validateOptions(krbIP); err == nil || !strings.Contains(err.Error(), "IP address") {
		t.Errorf("kerberos against an IP --server must be refused, got %v", err)
	}

	// --use-kcache requires a ccache in the environment.
	t.Setenv("KRB5CCNAME", "")
	krbCache := base
	krbCache.AuthMethod = AuthKerberos
	krbCache.UseKcache = true
	if err := validateOptions(krbCache); err == nil || !strings.Contains(err.Error(), "KRB5CCNAME") {
		t.Errorf("--use-kcache without $KRB5CCNAME must be refused, got %v", err)
	}
	t.Setenv("KRB5CCNAME", "/tmp/krb5cc_test")
	if err := validateOptions(krbCache); err != nil {
		t.Errorf("--use-kcache with $KRB5CCNAME should validate: %v", err)
	}

	// AES key / ccache are Kerberos-only; naming another method is a mistake.
	strayAES := base
	strayAES.AuthMethod = AuthNTLM
	strayAES.AESKey = make([]byte, 16)
	if err := validateOptions(strayAES); err == nil {
		t.Error("--aes-key with --auth-method ntlm must be refused")
	}
	strayCache := base
	strayCache.AuthMethod = AuthSimple
	strayCache.UseKcache = true
	if err := validateOptions(strayCache); err == nil {
		t.Error("--use-kcache with --auth-method simple must be refused")
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
