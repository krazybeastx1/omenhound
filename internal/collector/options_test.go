package collector

import "testing"

func TestValidateOptionsRefusesPlaintextLDAP(t *testing.T) {
	o := Options{Server: "dc01", Domain: "corp.local", Username: "svc"}
	if err := validateOptions(o); err == nil {
		t.Fatal("plaintext LDAP must be refused by default")
	}
	o.UseLDAPS = true
	if err := validateOptions(o); err != nil {
		t.Fatalf("LDAPS should be accepted: %v", err)
	}
	o.UseLDAPS = false
	o.AllowPlaintextLDAP = true
	if err := validateOptions(o); err != nil {
		t.Fatalf("explicit plaintext opt-in should be accepted: %v", err)
	}
}

func TestValidateOptionsRequiresFields(t *testing.T) {
	cases := map[string]Options{
		"server":   {Domain: "d", Username: "u", UseLDAPS: true},
		"domain":   {Server: "s", Username: "u", UseLDAPS: true},
		"username": {Server: "s", Domain: "d", UseLDAPS: true},
	}
	for name, o := range cases {
		if err := validateOptions(o); err == nil {
			t.Errorf("%s: expected error for missing field", name)
		}
	}
}
