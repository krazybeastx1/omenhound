package collector

import (
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"

	"github.com/go-ldap/ldap/v3"
	"github.com/jfjallid/go-smb/krb5ssp"
	"github.com/jfjallid/go-smb/spnego"
	jgss "github.com/jfjallid/ldap/v3/gssapi"
)

// Kerberos authentication for the LDAP and SMB passes.
//
// One credential source drives both protocols. A spnego.KRB5Initiator
// (github.com/jfjallid/go-smb) supplies the TGT/TGS to the SMB session
// directly and, through github.com/jfjallid/ldap/v3/gssapi, to the LDAP GSSAPI
// SASL bind. Credentials may be a password, an NT hash (overpass-the-hash,
// RC4-HMAC), an AES key, or an existing ccache ($KRB5CCNAME).
//
// The GSSAPI client from the ldap/v3 fork implements exactly the four methods
// of go-ldap's GSSAPIClient interface, so it can be handed to the upstream
// conn.GSSAPIBindRequest. Reusing the go-smb initiator keeps one already
// exercised Kerberos stack rather than growing a second one.

// kerberosHost extracts the hostname from a --server/--dc value, dropping a
// trailing :port and IPv6 brackets.
func kerberosHost(server string) string {
	s := strings.TrimSpace(server)
	if s == "" {
		return ""
	}
	if h, _, err := net.SplitHostPort(s); err == nil {
		return strings.TrimSpace(h)
	}
	return strings.Trim(s, "[]")
}

// kerberosServicePrincipal builds a "<service>/<host>" SPN, rejecting an IP
// host: an Active Directory service ticket is issued for a hostname, never a
// literal address.
func kerberosServicePrincipal(service, host string) (string, error) {
	if host == "" {
		return "", errors.New("kerberos: empty target host")
	}
	if net.ParseIP(host) != nil {
		return "", fmt.Errorf("kerberos: %q is an IP address, but a service ticket needs the host's FQDN "+
			"(pass the DC hostname as --server; add it to /etc/hosts if it does not resolve)", host)
	}
	return service + "/" + strings.ToLower(host), nil
}

// kerberosInitiator builds the shared SPNEGO Kerberos initiator for one target.
// host is the DNS name the service ticket is for ("ldap" for the DC, "cifs" for
// a file server). The KDC is DCIP, or the address resolved from --server.
func kerberosInitiator(o Options, host, service string) (*spnego.KRB5Initiator, error) {
	spn, err := kerberosServicePrincipal(service, host)
	if err != nil {
		return nil, err
	}
	user, _ := SplitUserDomain(o.Username, o.Domain)
	if user == "" {
		return nil, errors.New("kerberos: a username is required (--username)")
	}
	realm := strings.TrimSpace(o.Domain)
	if realm == "" {
		return nil, errors.New("kerberos: a domain is required (--domain)")
	}
	if len(o.Password) == 0 && len(o.Hashes) == 0 && len(o.AESKey) == 0 && !o.UseKcache {
		return nil, errors.New("kerberos: no credentials — supply --password, --hashes, --aes-key, " +
			"or --use-kcache (with $KRB5CCNAME)")
	}

	init := &spnego.KRB5Initiator{
		User:        user,
		Domain:      realm,
		Password:    string(o.Password),
		Host:        host,
		SPN:         spn,
		DialTimeout: o.EffectiveTimeout(),
	}
	if o.DCIP != "" {
		init.DCIP = o.DCIP
	} else if ip := firstIPv4(kerberosHost(o.Server)); ip != "" {
		init.DCIP = ip
	}
	if len(o.Hashes) > 0 {
		raw, err := decodeNTHash(o.Hashes)
		if err != nil {
			return nil, err
		}
		init.Hash = raw
	}
	if len(o.AESKey) > 0 {
		init.AESKey = o.AESKey
	}
	return init, nil
}

// kerberosSMBInitiator wraps the run's shared Kerberos logon (one AS-REQ) in a
// fresh per-host initiator for the cifs SPN. A new initiator per host keeps the
// wrap sequence state per-connection, while the shared krb5ssp client serves the
// cached TGT and issues one TGS request per host.
func kerberosSMBInitiator(host string, kc *krb5ssp.Client) (*spnego.KRB5Initiator, error) {
	spn, err := kerberosServicePrincipal("cifs", host)
	if err != nil {
		return nil, err
	}
	init := &spnego.KRB5Initiator{SPN: spn, Host: host}
	if err := init.SetClient(kc); err != nil {
		return nil, err
	}
	return init, nil
}

// kerberosBindLDAP authenticates an established LDAP connection with a GSSAPI
// SASL bind (RFC 4752) using the shared Kerberos initiator.
func kerberosBindLDAP(conn *ldap.Conn, o Options) error {
	host := kerberosHost(o.Server)
	init, err := kerberosInitiator(o, host, "ldap")
	if err != nil {
		return err
	}
	kc, err := init.Client()
	if err != nil {
		return fmt.Errorf("ldap: kerberos init for %s: %w", host, err)
	}
	gssClient, err := jgss.NewClient(kc.Client)
	if err != nil {
		return fmt.Errorf("ldap: gssapi client: %w", err)
	}
	// Negotiate "no security layer": the LDAP traffic is protected by --ldaps,
	// and the upstream bind cannot sign/seal per message anyway.
	gssClient.SetSASLSecurity(0)
	if err := conn.GSSAPIBindRequest(gssClient, &ldap.GSSAPIBindRequest{
		ServicePrincipalName: init.SPN,
	}); err != nil {
		return fmt.Errorf("ldap: GSSAPI bind as %s: %w", o.Username, err)
	}
	return nil
}

// validateKerberosOptions rejects a Kerberos run that cannot succeed before any
// network traffic: no credential source, an IP where a hostname is required, or
// --use-kcache without a ccache in the environment.
func validateKerberosOptions(o Options) error {
	if strings.TrimSpace(o.Username) == "" {
		return errors.New("kerberos: a username is required (--username)")
	}
	host := kerberosHost(o.Server)
	if host == "" {
		return errors.New("kerberos: --server must name the domain controller")
	}
	if net.ParseIP(host) != nil {
		return fmt.Errorf("kerberos: --server %q is an IP address, but Kerberos needs the DC hostname (FQDN) "+
			"for the service ticket (add it to /etc/hosts if it does not resolve)", host)
	}
	if len(o.Password) == 0 && len(o.Hashes) == 0 && len(o.AESKey) == 0 && !o.UseKcache {
		return errors.New("kerberos: no credentials; supply --password, --hashes, --aes-key, " +
			"or --use-kcache (with $KRB5CCNAME)")
	}
	if o.UseKcache && strings.TrimSpace(os.Getenv("KRB5CCNAME")) == "" {
		return errors.New("kerberos: --use-kcache needs $KRB5CCNAME to name a credential cache file")
	}
	return nil
}

// smbHasCredentials reports whether the run carries credentials the SMB pass can
// authenticate with: NTLM/simple need a password or NT hash, Kerberos also
// accepts an AES key or a ccache.
func smbHasCredentials(o Options) bool {
	method, err := o.EffectiveAuthMethod()
	if err != nil {
		return false
	}
	if method == AuthKerberos {
		return len(o.Password) > 0 || len(o.Hashes) > 0 || len(o.AESKey) > 0 || o.UseKcache
	}
	return len(o.Password) > 0 || len(o.Hashes) > 0
}

// NormalizeAESKey validates a Kerberos AES key (hex) and returns its raw bytes.
func NormalizeAESKey(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, errors.New("kerberos: empty AES key")
	}
	b, err := hex.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("kerberos: AES key is not hex: %w", err)
	}
	switch len(b) {
	case 16, 32:
		return b, nil
	default:
		return nil, fmt.Errorf("kerberos: AES key must be 16 (AES-128) or 32 (AES-256) bytes, got %d", len(b))
	}
}

// decodeNTHash turns the hex NT hash OmenHound carries in Options.Hashes into
// the raw 16 bytes gokrb5 expects for RC4-HMAC (overpass-the-hash).
func decodeNTHash(b []byte) ([]byte, error) {
	nt, err := NormalizeHash(string(b))
	if err != nil {
		return nil, err
	}
	raw, err := hex.DecodeString(nt)
	if err != nil {
		return nil, fmt.Errorf("kerberos: NT hash is not hex: %w", err)
	}
	return raw, nil
}

// firstIPv4 resolves a host to its first IPv4 address, or returns "" when it
// neither parses as an address nor resolves. An empty result leaves the KDC to
// gokrb5's own realm-to-KDC mapping.
func firstIPv4(host string) string {
	if host == "" {
		return ""
	}
	if ip := net.ParseIP(host); ip != nil {
		return ip.String()
	}
	addrs, err := net.LookupHost(host)
	if err != nil {
		return ""
	}
	for _, a := range addrs {
		if ip := net.ParseIP(a); ip != nil && ip.To4() != nil {
			return a
		}
	}
	if len(addrs) > 0 {
		return addrs[0]
	}
	return ""
}
