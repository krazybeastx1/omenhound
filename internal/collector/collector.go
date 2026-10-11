// Package collector enumerates Active Directory and produces a model.Graph.
// Collectors are pluggable: "ldap" talks to a real domain, "sample" returns a
// deterministic graph for demos and tests with no AD required.
package collector

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jfjallid/go-smb/krb5ssp"
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
	// UseKcache selects Kerberos ccache authentication: the TGT is read from
	// the file named by $KRB5CCNAME instead of being requested with a
	// password, hash or AES key. Only meaningful with AuthKerberos.
	UseKcache bool
	// AESKey is a raw Kerberos AES key (16 bytes = AES-128, 32 = AES-256) used
	// to request a TGT instead of a password. Only meaningful with AuthKerberos.
	AESKey []byte
	// DCIP is the domain controller IP dialed as the KDC. When empty the
	// collector resolves Server for it. Only used by Kerberos.
	DCIP string
	// krbClient is the Kerberos logon shared by every host in the SMB pass. It
	// is filled in by the SMB pass itself — never by the CLI — so the run makes
	// one AS-REQ and then one TGS request per host, instead of a fresh AS-REQ
	// per host. Each host still gets its own initiator, so the per-connection
	// wrap sequence starts clean.
	krbClient *krb5ssp.Client
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
	if method == AuthKerberos {
		if err := validateKerberosOptions(o); err != nil {
			return err
		}
	} else {
		if len(o.AESKey) > 0 {
			return errors.New("ldap: --aes-key only applies to Kerberos; add --auth-method kerberos")
		}
		if o.UseKcache {
			return errors.New("ldap: --use-kcache only applies to Kerberos; add --auth-method kerberos")
		}
		if method == AuthSimple && len(o.Hashes) > 0 {
			return errors.New("ldap: --hashes only applies to NTLM or Kerberos; drop --auth-method simple or use --auth-method ntlm")
		}
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
