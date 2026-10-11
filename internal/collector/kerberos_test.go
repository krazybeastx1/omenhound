package collector

import (
	"encoding/hex"
	"strings"
	"testing"

	"github.com/jfjallid/go-smb/krb5ssp"
	"github.com/jfjallid/go-smb/spnego"
)

func TestKerberosHost(t *testing.T) {
	cases := map[string]string{
		"dc01.corp.local":     "dc01.corp.local",
		"dc01.corp.local:636": "dc01.corp.local",
		"  dc01.corp.local  ": "dc01.corp.local",
		"10.0.0.5":            "10.0.0.5",
		"[fe80::1]:636":       "fe80::1",
		"":                    "",
	}
	for in, want := range cases {
		if got := kerberosHost(in); got != want {
			t.Errorf("kerberosHost(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestKerberosServicePrincipal(t *testing.T) {
	spn, err := kerberosServicePrincipal("ldap", "DC01.Corp.Local")
	if err != nil {
		t.Fatalf("kerberosServicePrincipal: %v", err)
	}
	if spn != "ldap/dc01.corp.local" {
		t.Errorf("SPN = %q, want ldap/dc01.corp.local", spn)
	}
	if _, err := kerberosServicePrincipal("cifs", "10.0.0.5"); err == nil {
		t.Error("an IP host must be rejected for an SPN")
	}
	if _, err := kerberosServicePrincipal("ldap", ""); err == nil {
		t.Error("an empty host must be rejected for an SPN")
	}
}

func TestKerberosInitiatorCredentials(t *testing.T) {
	base := Options{
		Server: "dc01.corp.local", Domain: "corp.local", Username: `CORP\jdoe`,
		AuthMethod: AuthKerberos, DCIP: "10.0.0.5",
	}

	// Password, with the realm taken from --domain (not the NetBIOS prefix of
	// the username) and the SPN from the target host.
	pw := base
	pw.Password = []byte("hunter2")
	init, err := kerberosInitiator(pw, "DC01.corp.local", "ldap")
	if err != nil {
		t.Fatalf("password initiator: %v", err)
	}
	if init.User != "jdoe" || init.Domain != "corp.local" {
		t.Errorf("principal = %s@%s, want jdoe@corp.local", init.User, init.Domain)
	}
	if init.SPN != "ldap/dc01.corp.local" {
		t.Errorf("SPN = %q, want ldap/dc01.corp.local", init.SPN)
	}
	if init.DCIP != "10.0.0.5" {
		t.Errorf("DCIP = %q, want 10.0.0.5", init.DCIP)
	}
	if init.Password != "hunter2" {
		t.Errorf("password not carried through")
	}

	// Overpass-the-hash: the hex NT hash becomes the raw 16-byte RC4 key.
	ntHex := "31d6cfe0d16ae931b73c59d7e0c089c0"
	hash := base
	hash.Password = nil
	hash.Hashes = []byte(ntHex)
	hinit, err := kerberosInitiator(hash, "dc01.corp.local", "cifs")
	if err != nil {
		t.Fatalf("hash initiator: %v", err)
	}
	want, _ := hex.DecodeString(ntHex)
	if string(hinit.Hash) != string(want) {
		t.Errorf("Hash = %x, want %x", hinit.Hash, want)
	}
	if hinit.SPN != "cifs/dc01.corp.local" {
		t.Errorf("SPN = %q, want cifs/dc01.corp.local", hinit.SPN)
	}

	// AES key.
	aes := base
	aes.Password = nil
	aes.AESKey = make([]byte, 32)
	ainit, err := kerberosInitiator(aes, "dc01.corp.local", "ldap")
	if err != nil {
		t.Fatalf("aes initiator: %v", err)
	}
	if len(ainit.AESKey) != 32 {
		t.Errorf("AESKey length = %d, want 32", len(ainit.AESKey))
	}

	// No credential source at all is a hard error.
	empty := base
	if _, err := kerberosInitiator(empty, "dc01.corp.local", "ldap"); err == nil ||
		!strings.Contains(err.Error(), "no credentials") {
		t.Errorf("missing credentials must error, got %v", err)
	}

	// An IP target cannot carry a service ticket.
	if _, err := kerberosInitiator(pw, "10.0.0.5", "ldap"); err == nil {
		t.Error("an IP target host must be rejected")
	}
}

func TestNormalizeAESKey(t *testing.T) {
	if _, err := NormalizeAESKey(strings.Repeat("ab", 16)); err != nil {
		t.Errorf("16-byte AES-128 key should validate: %v", err)
	}
	if _, err := NormalizeAESKey(strings.Repeat("cd", 32)); err != nil {
		t.Errorf("32-byte AES-256 key should validate: %v", err)
	}
	for _, bad := range []string{"", "abcd", strings.Repeat("zz", 16), strings.Repeat("ab", 20)} {
		if _, err := NormalizeAESKey(bad); err == nil {
			t.Errorf("NormalizeAESKey(%q) accepted, want error", bad)
		}
	}
}

func TestDecodeNTHash(t *testing.T) {
	raw, err := decodeNTHash([]byte("AAD3B435B51404EEAAD3B435B51404EE:31D6CFE0D16AE931B73C59D7E0C089C0"))
	if err != nil {
		t.Fatalf("decodeNTHash: %v", err)
	}
	if len(raw) != 16 {
		t.Fatalf("decoded %d bytes, want 16", len(raw))
	}
	if raw[0] != 0x31 {
		t.Errorf("first byte = %#x, want 0x31", raw[0])
	}
	if _, err := decodeNTHash([]byte("not-hex")); err == nil {
		t.Error("a non-hex NT hash must be rejected")
	}
}

func TestSmbKerberosInitiator(t *testing.T) {
	o := Options{
		Server: "dc01.corp.local", Domain: "corp.local", Username: "jdoe",
		AuthMethod: AuthKerberos, Password: []byte("hunter2"), DCIP: "10.0.0.5",
	}
	opts, err := smbOptions(o, "files01.corp.local")
	if err != nil {
		t.Fatalf("smbOptions: %v", err)
	}
	ki, ok := opts.Initiator.(*spnego.KRB5Initiator)
	if !ok {
		t.Fatalf("Initiator = %T, want *spnego.KRB5Initiator", opts.Initiator)
	}
	if ki.SPN != "cifs/files01.corp.local" {
		t.Errorf("SPN = %q, want cifs/files01.corp.local", ki.SPN)
	}

	// A non-Kerberos run still uses NTLM.
	ntlmOpts, err := smbOptions(Options{Username: "jdoe", Domain: "corp.local", Password: []byte("x")}, "files01")
	if err != nil {
		t.Fatalf("smbOptions(ntlm): %v", err)
	}
	if _, ok := ntlmOpts.Initiator.(*spnego.NTLMInitiator); !ok {
		t.Errorf("Initiator = %T, want *spnego.NTLMInitiator", ntlmOpts.Initiator)
	}
}

func TestSmbHasCredentials(t *testing.T) {
	cases := []struct {
		name string
		o    Options
		want bool
	}{
		{"password", Options{Password: []byte("x")}, true},
		{"ntlm hash", Options{Hashes: []byte("31d6cfe0d16ae931b73c59d7e0c089c0")}, true},
		{"nothing", Options{}, false},
		{"kerberos aes key", Options{AuthMethod: AuthKerberos, AESKey: make([]byte, 16)}, true},
		{"kerberos ccache", Options{AuthMethod: AuthKerberos, UseKcache: true}, true},
		{"kerberos nothing", Options{AuthMethod: AuthKerberos}, false},
	}
	for _, tc := range cases {
		if got := smbHasCredentials(tc.o); got != tc.want {
			t.Errorf("%s: smbHasCredentials = %v, want %v", tc.name, got, tc.want)
		}
	}
}

// TestKerberosBindRefusesWithoutCredentials proves bindLDAP rejects a Kerberos
// run with no credential source before it touches the (nil) connection — i.e.
// no silent fallback to a weaker bind and no traffic.
func TestKerberosBindRefusesWithoutCredentials(t *testing.T) {
	o := Options{
		Server: "dc01.corp.local", Domain: "corp.local", Username: "jdoe",
		AuthMethod: AuthKerberos, UseLDAPS: true,
	}
	err := bindLDAP(nil, o)
	if err == nil || !strings.Contains(err.Error(), "no credentials") {
		t.Fatalf("bindLDAP with no Kerberos credentials = %v, want a no-credentials error", err)
	}
}

// TestKerberosSMBInitiatorReuse covers the one-AS-REQ-for-the-whole-SMB-pass
// design: a fresh per-host initiator is built around an already-authenticated
// krb5ssp client (so no network). A zero client is enough here because SetClient
// only stores the pointer.
func TestKerberosSMBInitiatorReuse(t *testing.T) {
	kc := &krb5ssp.Client{}
	init, err := kerberosSMBInitiator("files01.corp.local", kc)
	if err != nil {
		t.Fatalf("kerberosSMBInitiator: %v", err)
	}
	if init.SPN != "cifs/files01.corp.local" {
		t.Errorf("SPN = %q, want cifs/files01.corp.local", init.SPN)
	}
	if _, err := kerberosSMBInitiator("10.0.0.5", kc); err == nil {
		t.Error("an IP SMB target must be rejected")
	}
}

// TestSmbOptionsPrefersSharedKerberosClient proves the SMB pass dials with the
// run's shared Kerberos logon (no per-host initiator, no second AS-REQ) whenever
// o.krbClient is set.
func TestSmbOptionsPrefersSharedKerberosClient(t *testing.T) {
	o := Options{
		Server: "dc01.corp.local", Domain: "corp.local", Username: "jdoe",
		AuthMethod: AuthKerberos, Password: []byte("hunter2"), krbClient: &krb5ssp.Client{},
	}
	opts, err := smbOptions(o, "files01.corp.local")
	if err != nil {
		t.Fatalf("smbOptions: %v", err)
	}
	ki, ok := opts.Initiator.(*spnego.KRB5Initiator)
	if !ok {
		t.Fatalf("Initiator = %T, want *spnego.KRB5Initiator", opts.Initiator)
	}
	if ki.SPN != "cifs/files01.corp.local" {
		t.Errorf("SPN = %q, want cifs/files01.corp.local", ki.SPN)
	}
}
