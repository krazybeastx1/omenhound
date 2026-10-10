package collector

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/go-ldap/ldap/v3"

	"github.com/krazybeastx1/omenhound/pkg/model"
)

// LDAPCollector enumerates users, groups, computers, their group membership,
// and (with -c acl) object security descriptors over LDAP/LDAPS. Session, trust,
// and container collection are planned (see docs/ARCHITECTURE.md).
type LDAPCollector struct{}

// Name implements Collector.
func (LDAPCollector) Name() string { return "ldap" }

// userAccountControl flag: ACCOUNTDISABLE (0x0002).
const uacAccountDisable = 0x0002

// Search bounds: a page size for paged searches, a hard cap on entries per
// search (guards against pathological/looping directories), and a per-search
// server-side time limit in seconds.
const (
	ldapPageSize      = 500
	ldapMaxEntries    = 500_000
	ldapSearchTimeLim = 60
)

// Collect implements Collector.
func (LDAPCollector) Collect(ctx context.Context, o Options) (*model.Graph, error) {
	if err := validateOptions(o); err != nil {
		return nil, err
	}
	if o.Methods != nil && len(o.Methods.Implemented) == 0 {
		return nil, fmt.Errorf("ldap: none of the requested collection methods are implemented "+
			"(requested: %s; implemented: %s)", strings.Join(o.Methods.Requested, ","),
			strings.Join(implementedMethodList, ", "))
	}
	ctx, cancel := context.WithTimeout(ctx, o.EffectiveTimeout())
	defer cancel()

	conn, err := dialLDAP(o)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	if err := conn.Bind(o.Username, string(o.Password)); err != nil {
		return nil, fmt.Errorf("ldap: bind as %q: %w", o.Username, err)
	}

	g := &model.Graph{Meta: model.Meta{Collector: "ldap", Domain: o.Domain, StartedAt: time.Now().UTC()}}
	if o.Methods != nil {
		for _, m := range o.Methods.Skipped {
			g.Meta.Warnings = append(g.Meta.Warnings, fmt.Sprintf("collection method %q is not implemented — skipped", m))
		}
	}
	if o.IncludeSessions {
		g.Meta.Warnings = append(g.Meta.Warnings, "session collection requires SMB and is not implemented by the LDAP collector — skipped")
	}
	baseDN := o.BaseDN
	if baseDN == "" {
		baseDN = DomainToDN(o.Domain)
	}

	dnIndex := map[string]string{}        // DN -> node ID
	memberOf := map[string][]string{}     // node ID -> group DNs
	groupMembers := map[string][]string{} // group node ID -> member DNs

	// Domain object.
	if ent, err := searchBase(conn, baseDN, []string{"objectSid", "name"}); err == nil && ent != nil {
		if sid := sidOf(ent); sid != "" {
			g.AddNode(model.Node{ID: sid, Kind: model.KindDomain, Name: ent.GetAttributeValue("name"), Domain: o.Domain, DN: baseDN})
			dnIndex[baseDN] = sid
		}
	}

	// Users.
	if err := eachEntry(conn, baseDN, "(&(objectCategory=person)(objectClass=user))",
		[]string{"sAMAccountName", "objectSid", "distinguishedName", "name", "memberOf", "userAccountControl", "adminCount"},
		func(e *ldap.Entry) {
			id := sidOf(e)
			if id == "" {
				return
			}
			uac := int64(0)
			if v := e.GetAttributeValue("userAccountControl"); v != "" {
				fmt.Sscanf(v, "%d", &uac)
			}
			props := map[string]string{"enabled": boolStr(uac&uacAccountDisable == 0)}
			if e.GetAttributeValue("adminCount") == "1" {
				props["admincount"] = "true"
			}
			g.AddNode(model.Node{ID: id, Kind: model.KindUser, Name: e.GetAttributeValue("name"), SAMAccountName: e.GetAttributeValue("sAMAccountName"), Domain: o.Domain, DN: e.DN, Props: props})
			dnIndex[e.DN] = id
			memberOf[id] = e.GetAttributeValues("memberOf")
		}); err != nil {
		return nil, err
	}

	// Computers.
	if err := eachEntry(conn, baseDN, "(objectClass=computer)",
		[]string{"sAMAccountName", "objectSid", "distinguishedName", "name", "memberOf", "operatingSystem"},
		func(e *ldap.Entry) {
			id := sidOf(e)
			if id == "" {
				return
			}
			g.AddNode(model.Node{ID: id, Kind: model.KindComputer, Name: e.GetAttributeValue("name"), SAMAccountName: e.GetAttributeValue("sAMAccountName"), Domain: o.Domain, DN: e.DN,
				Props: map[string]string{"os": e.GetAttributeValue("operatingSystem")}})
			dnIndex[e.DN] = id
			memberOf[id] = e.GetAttributeValues("memberOf")
		}); err != nil {
		return nil, err
	}

	// Groups.
	if err := eachEntry(conn, baseDN, "(objectClass=group)",
		[]string{"sAMAccountName", "objectSid", "distinguishedName", "name", "member", "adminCount"},
		func(e *ldap.Entry) {
			id := sidOf(e)
			if id == "" {
				return
			}
			props := map[string]string{}
			if e.GetAttributeValue("adminCount") == "1" {
				props["admincount"] = "true"
			}
			g.AddNode(model.Node{ID: id, Kind: model.KindGroup, Name: e.GetAttributeValue("name"), SAMAccountName: e.GetAttributeValue("sAMAccountName"), Domain: o.Domain, DN: e.DN, Props: props})
			dnIndex[e.DN] = id
			groupMembers[id] = e.GetAttributeValues("member")
		}); err != nil {
		return nil, err
	}

	// Second pass: resolve memberships now that every DN is indexed.
	for id, dns := range memberOf {
		for _, dn := range dns {
			if gid, ok := dnIndex[dn]; ok {
				g.AddEdge(model.Edge{Source: id, Target: gid, Kind: model.EdgeMemberOf})
			}
		}
	}
	for gid, dns := range groupMembers {
		for _, dn := range dns {
			if mid, ok := dnIndex[dn]; ok {
				g.AddEdge(model.Edge{Source: mid, Target: gid, Kind: model.EdgeMemberOf})
			}
		}
	}

	// ACL collection (`-c acl`). It re-reads the objects it needs with the
	// security-descriptor control rather than burdening the passes above, and
	// creates any node (OU/GPO/container) the base passes did not.
	if methodRequested(o.Methods, "acl") {
		if err := collectACL(conn, o, g, dnIndex, baseDN); err != nil {
			return nil, err
		}
	}

	g.Meta.FinishedAt = time.Now().UTC()
	return g, nil
}

func dialLDAP(o Options) (*ldap.Conn, error) {
	scheme, port := "ldap", "389"
	if o.UseLDAPS {
		scheme, port = "ldaps", "636"
	}
	addr := o.Server
	if !strings.Contains(addr, ":") {
		addr += ":" + port
	}
	url := scheme + "://" + addr
	opts := []ldap.DialOpt{ldap.DialWithDialer(&net.Dialer{Timeout: o.EffectiveTimeout()})}
	if o.UseLDAPS {
		host := addr
		if i := strings.LastIndex(host, ":"); i >= 0 {
			host = host[:i]
		}
		opts = append(opts, ldap.DialWithTLSConfig(&tls.Config{
			ServerName:         host,
			InsecureSkipVerify: o.InsecureSkipVerify,
			MinVersion:         tls.VersionTLS12,
		}))
	}
	return ldap.DialURL(url, opts...)
}

func searchBase(conn *ldap.Conn, baseDN string, attrs []string) (*ldap.Entry, error) {
	req := ldap.NewSearchRequest(baseDN, ldap.ScopeBaseObject, ldap.NeverDerefAliases, 1, 0, false, "(objectClass=*)", attrs, nil)
	res, err := conn.Search(req)
	if err != nil {
		return nil, err
	}
	if len(res.Entries) == 0 {
		return nil, nil
	}
	return res.Entries[0], nil
}

func eachEntry(conn *ldap.Conn, baseDN, filter string, attrs []string, fn func(*ldap.Entry)) error {
	return eachEntryWithControls(conn, baseDN, filter, attrs, ldap.ScopeWholeSubtree, nil, fn)
}

// eachEntryWithControls is eachEntry with an explicit scope and extra controls
// (used by the ACL collector to request nTSecurityDescriptor).
func eachEntryWithControls(conn *ldap.Conn, baseDN, filter string, attrs []string, scope int, ctrls []ldap.Control, fn func(*ldap.Entry)) error {
	req := ldap.NewSearchRequest(baseDN, scope, ldap.NeverDerefAliases, 0, ldapSearchTimeLim, false, filter, attrs, ctrls)
	res, err := conn.SearchWithPaging(req, ldapPageSize)
	if err != nil {
		return fmt.Errorf("ldap: search %q: %w", filter, err)
	}
	if len(res.Entries) > ldapMaxEntries {
		return fmt.Errorf("ldap: search %q returned %d entries (limit %d)", filter, len(res.Entries), ldapMaxEntries)
	}
	for _, e := range res.Entries {
		fn(e)
	}
	return nil
}

func sidOf(e *ldap.Entry) string {
	raw := e.GetRawAttributeValue("objectSid")
	if len(raw) == 0 {
		return ""
	}
	sid, err := FormatSID(raw)
	if err != nil {
		return ""
	}
	return sid
}
