package collector

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"
)

// MethodPlan records a resolved BloodHound.py-style collection-method request.
// OmenHound implements a subset of methods today; everything requested but not
// implemented is listed in Skipped so the operator gets an explicit, honest
// "not implemented — skipped" report rather than a silent partial collection.
type MethodPlan struct {
	Requested   []string
	Implemented []string
	Skipped     []string
}

// bloodhoundMethods is the full BloodHound.py method vocabulary.
var bloodhoundMethods = []string{
	"group", "localadmin", "session", "trusts", "objectprops", "acl",
	"container", "dcom", "rdp", "psremote", "loggedon",
}

// implementedMethodList is the ordered list of methods OmenHound's LDAP
// collector can perform. It is exported to operators in error/warning text, so
// it has a single source of truth here.
var implementedMethodList = []string{"group", "objectprops", "acl", "trusts", "container"}

// implementedMethods is the lookup form of implementedMethodList.
var implementedMethods = func() map[string]bool {
	m := make(map[string]bool, len(implementedMethodList))
	for _, k := range implementedMethodList {
		m[k] = true
	}
	return m
}()

// methodRequested reports whether an implemented method was requested. A nil
// plan means the default profile (group + objectprops), which never includes acl.
func methodRequested(m *MethodPlan, name string) bool {
	if m == nil {
		return false
	}
	for _, x := range m.Implemented {
		if x == name {
			return true
		}
	}
	return false
}

// PlanMethods resolves a comma-separated -c/--collectionmethod value. An empty
// value defaults to OmenHound's native set: group + objectprops.
func PlanMethods(input string) (MethodPlan, error) {
	input = strings.TrimSpace(input)
	var requested []string
	switch strings.ToLower(input) {
	case "":
		requested = []string{"group", "objectprops"}
	case "all":
		requested = append(requested, bloodhoundMethods...)
	case "default":
		requested = []string{"group", "localadmin", "session", "trusts"}
	case "dc", "dconly":
		requested = []string{"group", "trusts", "objectprops", "acl", "container"}
	default:
		for _, part := range strings.Split(strings.ToLower(input), ",") {
			part = strings.TrimSpace(part)
			if part == "" {
				continue
			}
			if !isKnownMethod(part) {
				return MethodPlan{}, fmt.Errorf("collector: unknown collection method %q (known: %s, all, default, dc)",
					part, strings.Join(bloodhoundMethods, ", "))
			}
			requested = append(requested, part)
		}
		if len(requested) == 0 {
			return MethodPlan{}, errors.New("collector: no collection methods given")
		}
	}

	plan := MethodPlan{Requested: dedupe(requested)}
	seenImpl := map[string]bool{}
	for _, m := range plan.Requested {
		if implementedMethods[m] {
			if !seenImpl[m] {
				plan.Implemented = append(plan.Implemented, m)
				seenImpl[m] = true
			}
			continue
		}
		plan.Skipped = append(plan.Skipped, m)
	}
	return plan, nil
}

func isKnownMethod(m string) bool {
	for _, k := range bloodhoundMethods {
		if k == m {
			return true
		}
	}
	return false
}

func dedupe(in []string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(in))
	for _, s := range in {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

// ResolveDC discovers a domain controller for domain by querying LDAP SRV
// records (_ldap._tcp.dc._msdcs.<domain>) against the supplied nameserver
// (host or host:port, default 53). It returns the SRV target hostname.
func ResolveDC(ctx context.Context, nameserver, domain string) (string, error) {
	if nameserver == "" {
		return "", errors.New("dns: nameserver is required")
	}
	if domain == "" {
		return "", errors.New("dns: domain is required")
	}
	ns := nameserver
	if _, _, err := net.SplitHostPort(ns); err != nil {
		ns = net.JoinHostPort(ns, "53")
	}
	r := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			d := net.Dialer{Timeout: 5 * time.Second}
			return d.DialContext(ctx, "udp", ns)
		},
	}
	var lastErr error
	for _, name := range []string{"dc._msdcs." + domain, domain} {
		_, addrs, err := r.LookupSRV(ctx, "ldap", "tcp", name)
		if err != nil {
			lastErr = err
			continue
		}
		if len(addrs) == 0 {
			continue
		}
		return strings.TrimSuffix(addrs[0].Target, "."), nil
	}
	if lastErr == nil {
		lastErr = errors.New("no SRV records")
	}
	return "", fmt.Errorf("dns: could not discover a DC for %q via %s: %w", domain, nameserver, lastErr)
}
