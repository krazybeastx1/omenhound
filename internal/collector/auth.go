package collector

import (
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	"github.com/go-ldap/ldap/v3"
)

// ---------------------------------------------------------------------------
// LDAP authentication
//
// Simple bind is the default. NTLM (`--auth-method ntlm`) and pass-the-hash
// (`--hashes`) use go-ldap's NTLMSSP bind, so no new dependency and no separate
// credential material: the NT hash is used in place of the password, exactly as
// BloodHound.py and impacket do.
// ---------------------------------------------------------------------------

// Authentication methods accepted by Options.AuthMethod.
const (
	AuthSimple   = "simple"
	AuthNTLM     = "ntlm"
	AuthKerberos = "kerberos"
)

// EffectiveAuthMethod resolves Options.AuthMethod, applying the one implicit rule
// BloodHound.py has: supplying hashes selects NTLM.
func (o Options) EffectiveAuthMethod() (string, error) {
	switch m := strings.ToLower(strings.TrimSpace(o.AuthMethod)); m {
	case "", "auto":
		if len(o.Hashes) > 0 {
			return AuthNTLM, nil
		}
		return AuthSimple, nil
	case AuthSimple, AuthNTLM, AuthKerberos:
		return m, nil
	default:
		return "", fmt.Errorf("ldap: unknown authentication method %q (want simple, ntlm or kerberos)", o.AuthMethod)
	}
}

// NormalizeHash validates an NT hash and returns its canonical lowercase hex
// form. OmenHound only ever uses the NT half: the NTLMSSP bind computes the
// response from the NT hash, so an LM hash would be ignored anyway.
func NormalizeHash(s string) (string, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return "", errors.New("ldap: empty NTLM hash")
	}
	// impacket/BloodHound.py accept "LMHASH:NTHASH"; the LM half is optional.
	if i := strings.IndexByte(s, ':'); i >= 0 {
		s = strings.TrimSpace(s[i+1:])
	}
	if len(s) != 32 {
		return "", fmt.Errorf("ldap: NTLM hash must be 32 hex characters (the NT hash), got %d", len(s))
	}
	if _, err := hex.DecodeString(s); err != nil {
		return "", fmt.Errorf("ldap: NTLM hash is not hex: %w", err)
	}
	return strings.ToLower(s), nil
}

// SplitUserDomain separates a bind principal into username and domain for the
// NTLMSSP bind. It accepts the forms AD tooling accepts: "DOMAIN\user",
// "user@domain", or a bare username combined with the --domain value.
func SplitUserDomain(username, domain string) (user, dom string) {
	u := strings.TrimSpace(username)
	if i := strings.IndexByte(u, '\\'); i >= 0 { // DOMAIN\user
		if d := strings.TrimSpace(u[:i]); d != "" {
			domain = d
		}
		u = strings.TrimSpace(u[i+1:])
	} else if i := strings.LastIndexByte(u, '@'); i >= 0 { // user@domain
		if d := strings.TrimSpace(u[i+1:]); d != "" {
			domain = d
		}
		u = strings.TrimSpace(u[:i])
	}
	return u, domain
}

// bindLDAP performs the configured bind on an established connection.
func bindLDAP(conn *ldap.Conn, o Options) error {
	method, err := o.EffectiveAuthMethod()
	if err != nil {
		return err
	}
	switch method {
	case AuthSimple:
		if err := conn.Bind(o.Username, string(o.Password)); err != nil {
			return fmt.Errorf("ldap: simple bind as %q: %w", o.Username, err)
		}
		return nil

	case AuthNTLM:
		user, dom := SplitUserDomain(o.Username, o.Domain)
		if len(o.Hashes) > 0 {
			nt, err := NormalizeHash(string(o.Hashes))
			if err != nil {
				return err
			}
			if err := conn.NTLMBindWithHash(dom, user, nt); err != nil {
				return fmt.Errorf("ldap: NTLM pass-the-hash bind as %s\\%s: %w", dom, user, err)
			}
			return nil
		}
		if len(o.Password) == 0 {
			// An empty password is a legitimate NTLM bind (a credential with no
			// password, e.g. a pass-the-hash-less computer account ACL grant).
			if err := conn.NTLMUnauthenticatedBind(dom, user); err != nil {
				return fmt.Errorf("ldap: NTLM bind as %s\\%s with empty password: %w", dom, user, err)
			}
			return nil
		}
		if err := conn.NTLMBind(dom, user, string(o.Password)); err != nil {
			return fmt.Errorf("ldap: NTLM bind as %s\\%s: %w", dom, user, err)
		}
		return nil

	case AuthKerberos:
		return errKerberosNotImplemented
	}
	// Unreachable: EffectiveAuthMethod only returns the constants above.
	return fmt.Errorf("ldap: unhandled authentication method %q", method)
}

// errKerberosNotImplemented is returned until the Kerberos path lands. It is an
// explicit refusal, never a silent fallback to a weaker bind.
var errKerberosNotImplemented = errors.New(
	"ldap: Kerberos authentication (-k/--kerberos) is not implemented yet; use simple bind or --auth-method ntlm")
