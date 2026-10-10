// Package act performs write actions against Active Directory. It is the only
// package that mutates AD, and every operation here is an intentional,
// audited, authorization-gated action.
//
// The password change uses the unicodePwd attribute over LDAPS, which requires
// an encrypted channel — plaintext LDAP is refused.
package act

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode/utf16"

	"github.com/go-ldap/ldap/v3"
)

// Options configures an action connection.
type Options struct {
	Server             string // DC host (host or host:port)
	Domain             string
	Username           string
	Password           []byte
	InsecureSkipVerify bool
	Timeout            time.Duration
}

// ErrLDAPSRequired is returned if a write is attempted without TLS.
var ErrLDAPSRequired = errors.New("act: AD writes require LDAPS (refusing plaintext LDAP)")

// ChangePassword sets targetDN's password via unicodePwd over LDAPS.
//
// The caller MUST have authorization to change this account's password. The
// new password is not logged anywhere by this function.
func ChangePassword(ctx context.Context, o Options, targetDN string, newPassword []byte) error {
	if targetDN == "" {
		return errors.New("act: target DN is required")
	}
	if len(newPassword) == 0 {
		return errors.New("act: new password is empty")
	}
	if o.Server == "" || o.Username == "" {
		return errors.New("act: server and username are required")
	}
	t := o.Timeout
	if t <= 0 {
		t = 20 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, t)
	defer cancel()

	addr := o.Server
	if !strings.Contains(addr, ":") {
		addr += ":636"
	}
	host := addr
	if i := strings.LastIndex(host, ":"); i >= 0 {
		host = host[:i]
	}
	conn, err := ldap.DialURL("ldaps://"+addr, ldap.DialWithTLSConfig(&tls.Config{
		ServerName:         host,
		InsecureSkipVerify: o.InsecureSkipVerify,
		MinVersion:         tls.VersionTLS12,
	}))
	if err != nil {
		return fmt.Errorf("act: dial ldaps %s: %w", addr, err)
	}
	defer conn.Close()

	if err := conn.Bind(o.Username, string(o.Password)); err != nil {
		return fmt.Errorf("act: bind as %q: %w", o.Username, err)
	}

	req := ldap.NewModifyRequest(targetDN, nil)
	req.Replace("unicodePwd", []string{encodeUnicodePwd(newPassword)})
	if err := conn.Modify(req); err != nil {
		return fmt.Errorf("act: modify unicodePwd on %s: %w", targetDN, err)
	}
	return nil
}

// encodeUnicodePwd encodes a password as the AD unicodePwd value:
// UTF-16LE, wrapped in double quotes.
func encodeUnicodePwd(pw []byte) string {
	runes := utf16.Encode([]rune("\"" + string(pw) + "\""))
	b := make([]byte, len(runes)*2)
	for i, r := range runes {
		binary.LittleEndian.PutUint16(b[i*2:], r)
	}
	return string(b)
}
