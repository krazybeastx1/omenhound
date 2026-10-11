// Package collector enumerates Active Directory and produces a model.Graph.
// Collectors are pluggable: "ldap" talks to a real domain, "sample" returns a
// deterministic graph for demos and tests with no AD required.
package collector

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/krazybeastx1/omenhound/pkg/model"
)

// Options configures a collection run.
type Options struct {
	// Domain is the NetBIOS or DNS domain (e.g. "corp.local").
	Domain string
	// Server is the DC host (optionally host:port). Required for ldap.
	Server string
	// BaseDN overrides the search base; derived from Domain when empty.
	BaseDN string
	// UseLDAPS forces LDAPS (ldaps://, 636).
	UseLDAPS bool
	// InsecureSkipVerify disables TLS verification (lab use only; loudly warned).
	InsecureSkipVerify bool
	// Username/Password are the credentials used to bind. Password is []byte so
	// it can be zeroed after use.
	Username string
	Password []byte
	// AuthMethod selects the bind: "simple" (default), "ntlm", or "kerberos".
	// Empty means auto — simple bind unless Hashes is set, which selects NTLM.
	AuthMethod string
	// Hashes is the NTLM NT hash to bind with instead of a password
	// (pass-the-hash, "LMHASH:NTHASH" or a bare 32-hex NT hash). []byte so it can
	// be zeroed after use, like Password.
	Hashes []byte
	// Timeout bounds the whole run.
	Timeout time.Duration
	// IncludeSessions is a legacy shorthand for the "session" collection method;
	// it is equivalent to adding "session" to Methods.
	IncludeSessions bool
	// AllowPlaintextLDAP permits binding over unencrypted LDAP. This is refused
	// by default because it exposes credentials on the wire.
	AllowPlaintextLDAP bool
	// Methods is the resolved BloodHound.py-style collection-method plan. When
	// set, the collector refuses to run if none of the requested methods are
	// implemented, and reports the unimplemented ones as warnings.
	Methods *MethodPlan
}

// validateOptions enforces the collector's safety invariants before any network
// traffic is generated.
func validateOptions(o Options) error {
	if o.Server == "" {
		return errors.New("ldap: server is required (--server)")
	}
	if o.Domain == "" {
		return errors.New("ldap: domain is required (--domain)")
	}
	if o.Username == "" {
		return errors.New("ldap: username is required (--username)")
	}
	method, err := o.EffectiveAuthMethod()
	if err != nil {
		return err
	}
	if method == AuthSimple && len(o.Hashes) > 0 {
		return errors.New("ldap: --hashes only applies to NTLM; drop --auth-method simple or use --auth-method ntlm")
	}
	if method == AuthKerberos {
		return errKerberosNotImplemented
	}
	if !o.UseLDAPS && !o.AllowPlaintextLDAP {
		return errors.New("ldap: refusing plaintext LDAP; a simple or NTLM bind would expose credentials " +
			"on the wire. Use --ldaps, or --allow-plaintext-ldap only on an isolated lab")
	}
	return nil
}

// EffectiveTimeout returns Timeout or a sane default.
func (o Options) EffectiveTimeout() time.Duration {
	if o.Timeout <= 0 {
		return 30 * time.Second
	}
	return o.Timeout
}

// Collector produces a graph for a domain.
type Collector interface {
	Name() string
	Collect(ctx context.Context, opts Options) (*model.Graph, error)
}

// New returns a collector by name: "sample" or "ldap".
func New(name string) (Collector, error) {
	switch name {
	case "sample", "":
		return SampleCollector{}, nil
	case "ldap":
		return LDAPCollector{}, nil
	default:
		return nil, fmt.Errorf("collector: unknown collector %q (want \"sample\" or \"ldap\")", name)
	}
}
