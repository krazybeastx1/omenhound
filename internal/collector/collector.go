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

// ErrNotImplemented is returned by collection paths that are planned but not yet
// available (e.g. SMB session enumeration).
var ErrNotImplemented = errors.New("collector: not implemented yet")

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
	// Timeout bounds the whole run.
	Timeout time.Duration
	// IncludeSessions requests session collection (requires SMB; ldap-only
	// collectors ignore it with a warning).
	IncludeSessions bool
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
