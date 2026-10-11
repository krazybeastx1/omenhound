package collector

import (
	"context"
	"encoding/hex"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/jfjallid/go-smb/dcerpc"
	"github.com/jfjallid/go-smb/dcerpc/mssrvs"
	"github.com/jfjallid/go-smb/dcerpc/smbtransport"
	"github.com/jfjallid/go-smb/smb"
	"github.com/jfjallid/go-smb/spnego"
)

// SMB/DCE-RPC plumbing for the SMB collection methods (session, localadmin,
// rdp, dcom, psremote, loggedon).
//
// BloodHound.py does this with impacket's DCE/RPC clients over SMB named pipes.
// OmenHound uses github.com/jfjallid/go-smb, which implements the same SMB2 +
// MS-RPC stack (srvsvc / samr / wkssvc / lsarpc), so the calls, their levels and
// the result filtering mirror BloodHound.py's.

// smbPort is the only SMB port OmenHound uses. BloodHound.py (through impacket)
// also falls back to NetBIOS session service on 139; github.com/jfjallid/go-smb
// speaks only direct SMB-over-TCP (445), so that fallback is not attempted.
const smbPort = 445

const (
	// smbDialTimeout bounds the TCP + SMB negotiation to one host.
	smbDialTimeout = 10 * time.Second
	// smbHostTimeout bounds all RPC work against a single host, so one
	// unresponsive machine cannot stall the whole run.
	smbHostTimeout = 30 * time.Second
)

// smbOptions builds the client options for one host from the collection
// credentials. Kerberos passes a KRB5Initiator (the service ticket is requested
// for cifs/<host>); otherwise the NTLM initiator is used, with pass-the-hash
// handed the raw NT hash, which is what the library's HMAC key derivation
// expects.
func smbOptions(o Options, host string) (smb.Options, error) {
	method, err := o.EffectiveAuthMethod()
	if err != nil {
		return smb.Options{}, err
	}
	opts := smb.Options{
		Host:        host,
		Port:        smbPort,
		DialTimeout: smbDialTimeout,
	}
	if method == AuthKerberos {
		var init *spnego.KRB5Initiator
		if o.krbClient != nil {
			// Reuse the run's Kerberos logon: only a TGS request per host.
			init, err = kerberosSMBInitiator(host, o.krbClient)
		} else {
			init, err = kerberosInitiator(o, host, "cifs")
		}
		if err != nil {
			return smb.Options{}, err
		}
		opts.Initiator = init
		return opts, nil
	}
	init, err := smbNTLMInitiator(o)
	if err != nil {
		return smb.Options{}, err
	}
	opts.Initiator = init
	return opts, nil
}

// smbNTLMInitiator builds the NTLMSSP initiator for the SMB session. Pass-the-hash
// is passed to the initiator as the raw NT hash, which is what the library's HMAC
// key derivation expects.
func smbNTLMInitiator(o Options) (*spnego.NTLMInitiator, error) {
	user, dom := SplitUserDomain(o.Username, o.Domain)
	init := &spnego.NTLMInitiator{
		User:     user,
		Domain:   dom,
		Password: string(o.Password),
	}
	if len(o.Hashes) > 0 {
		nt, err := NormalizeHash(string(o.Hashes))
		if err != nil {
			return nil, err
		}
		raw, err := hex.DecodeString(nt)
		if err != nil {
			return nil, err
		}
		init.Hash = raw
		init.Password = ""
	}
	return init, nil
}

// smbHost is one authenticated SMB session with the IPC$ tree connected, which
// is all that is needed to open service named pipes on it.
type smbHost struct {
	conn *smb.Connection
}

// dialHost connects and authenticates to host. It performs a cheap TCP probe
// first (like BloodHound.py's tcp_ping) so that a dead host costs a connect
// attempt rather than a full SMB negotiation.
func dialHost(ctx context.Context, o Options, host string) (*smbHost, error) {
	if host == "" {
		return nil, fmt.Errorf("smb: empty host")
	}
	if !smbHasCredentials(o) {
		return nil, fmt.Errorf("smb: no password or hash available for SMB authentication")
	}
	addr := net.JoinHostPort(host, fmt.Sprint(smbPort))
	if !tcpProbe(ctx, addr) {
		return nil, fmt.Errorf("smb: %s is not reachable", addr)
	}
	opts, err := smbOptions(o, host)
	if err != nil {
		return nil, err
	}
	conn, err := smb.NewConnection(opts)
	if err != nil {
		return nil, fmt.Errorf("smb: dial %s: %w", addr, err)
	}
	if err := conn.TreeConnect("IPC$"); err != nil {
		conn.Close()
		return nil, fmt.Errorf("smb: TreeConnect IPC$ on %s: %w", addr, err)
	}
	return &smbHost{conn: conn}, nil
}

func tcpProbe(ctx context.Context, addr string) bool {
	d := net.Dialer{Timeout: 2 * time.Second}
	c, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return false
	}
	c.Close()
	return true
}

func (h *smbHost) close() {
	if h == nil || h.conn == nil {
		return
	}
	h.conn.TreeDisconnect("IPC$")
	h.conn.Close()
}

// rpc opens a named pipe, binds the given DCE/RPC interface over it and returns
// the binding plus a cleanup function. This mirrors BloodHound.py's
// dce_rpc_connect: the RPC bind carries no separate authentication, because the
// SMB session is already authenticated and every call is signed by SMB.
func (h *smbHost) rpc(pipe, uuid string, major, minor uint16) (*dcerpc.ServiceBind, func(), error) {
	const share = "IPC$"
	f, err := h.conn.OpenFile(share, pipe)
	if err != nil {
		return nil, nil, fmt.Errorf("smb: open pipe %s: %w", pipe, err)
	}
	cleanup := func() { f.CloseFile() }
	tr, err := smbtransport.NewSMBTransport(f)
	if err != nil {
		cleanup()
		return nil, nil, fmt.Errorf("smb: transport %s: %w", pipe, err)
	}
	bind, err := dcerpc.Bind(tr, uuid, major, minor, dcerpc.MSRPCUuidNdr)
	if err != nil {
		cleanup()
		return nil, nil, fmt.Errorf("smb: bind %s: %w", pipe, err)
	}
	return bind, cleanup, nil
}

// SMBProbe connects to host over SMB and returns the share names the
// credentials can see. It is used as a lightweight access/connectivity check.
func SMBProbe(ctx context.Context, host, domain, user string, password []byte) ([]string, error) {
	o := Options{Domain: domain, Username: user, Password: password}
	ctx, cancel := context.WithTimeout(ctx, smbHostTimeout)
	defer cancel()

	h, err := dialHost(ctx, o, host)
	if err != nil {
		return nil, err
	}
	defer h.close()

	bind, cleanup, err := h.rpc(mssrvs.MSRPCSrvSvcPipe, mssrvs.MSRPCUuidSrvSvc, mssrvs.MSRPCSrvSvcMajorVersion, mssrvs.MSRPCSrvSvcMinorVersion)
	if err != nil {
		return nil, err
	}
	defer cleanup()

	shares, err := mssrvs.NewRPCCon(bind).NetShareEnumAll(host)
	if err != nil {
		return nil, fmt.Errorf("smb: NetShareEnumAll: %w", err)
	}
	names := make([]string, 0, len(shares))
	for _, s := range shares {
		names = append(names, s.Name)
	}
	return names, nil
}

// stripNUL removes the trailing NUL that NDR varying strings can carry.
func stripNUL(s string) string {
	return strings.TrimRight(s, "\x00")
}
