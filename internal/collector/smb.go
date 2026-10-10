package collector

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/hirochachacha/go-smb2"
)

// ErrSessionsPlanned marks SMB session enumeration as designed-but-unbuilt.
var ErrSessionsPlanned = errors.New("collector: SMB session enumeration is planned but not implemented (see docs/ARCHITECTURE.md)")

// SMBProbe connects to host over SMB (445) and returns the share names the
// credentials can see. It is used as a lightweight access/connectivity check.
func SMBProbe(ctx context.Context, host, domain, user string, password []byte) ([]string, error) {
	d := net.Dialer{Timeout: 10 * time.Second}
	addr := host
	if !strings.Contains(addr, ":") {
		addr += ":445"
	}
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("smb: dial %s: %w", addr, err)
	}
	defer conn.Close()

	dialer := &smb2.Dialer{Initiator: &smb2.NTLMInitiator{
		User:     user,
		Password: string(password),
		Domain:   domain,
	}}
	sess, err := dialer.Dial(conn)
	if err != nil {
		return nil, fmt.Errorf("smb: negotiate/auth as %q: %w", user, err)
	}
	defer sess.Logoff()

	names, err := sess.ListSharenames()
	if err != nil {
		return nil, fmt.Errorf("smb: list shares: %w", err)
	}
	return names, nil
}

// CollectSessions is a placeholder for SMB/WinRM session (net session) and
// remote-admin enumeration, which is planned but not built.
func CollectSessions(context.Context, Options) ([]string, error) {
	return nil, ErrSessionsPlanned
}
