package collector

import (
	"fmt"
	"sort"
	"strings"

	"github.com/go-ldap/ldap/v3"

	"github.com/krazybeastx1/omenhound/pkg/model"
)

// ---------------------------------------------------------------------------
// ACL collection over LDAP
//
// nTSecurityDescriptor is read with the LDAP_SERVER_SD_FLAGS control, parsed by
// security_descriptor.go, and mapped to edges by adacl.go.
// ---------------------------------------------------------------------------

// oidSDFlags is LDAP_SERVER_SD_FLAGS_OID, which selects which parts of a
// security descriptor the server returns ([MS-ADTS] 3.1.1.3.4.1.12).
const oidSDFlags = "1.2.840.113556.1.4.801"

// Security-information bits for the SD-flags control.
const (
	sdFlagOwner = 0x01
	sdFlagDACL  = 0x04
)

// sdFlagsControl returns the LDAP_SERVER_SD_FLAGS control asking for the owner
// and the DACL. The control value is BER: SEQUENCE { INTEGER bits }.
func sdFlagsControl() ldap.Control {
	return ldap.NewControlString(oidSDFlags, true, string([]byte{0x30, 0x03, 0x02, 0x01, sdFlagOwner | sdFlagDACL}))
}

// wellKnownPrincipals names the built-in trustees an ACE commonly references.
// They are materialised as nodes so the graph stays referentially closed and an
// operator sees "Authenticated Users" instead of a bare SID.
var wellKnownPrincipals = map[string]struct {
	Name string
	Kind model.Kind
}{
	"S-1-0-0":      {"Nobody", model.KindBase},
	"S-1-1-0":      {"Everyone", model.KindGroup},
	"S-1-2-0":      {"Local", model.KindBase},
	"S-1-3-0":      {"Creator Owner", model.KindBase},
	"S-1-3-1":      {"Creator Group", model.KindBase},
	"S-1-5-2":      {"Network", model.KindBase},
	"S-1-5-4":      {"Interactive", model.KindBase},
	"S-1-5-7":      {"Anonymous", model.KindBase},
	"S-1-5-9":      {"Enterprise Domain Controllers", model.KindGroup},
	"S-1-5-10":     {"Self", model.KindBase},
	"S-1-5-11":     {"Authenticated Users", model.KindGroup},
	"S-1-5-18":     {"Local System", model.KindBase},
	"S-1-5-19":     {"Local Service", model.KindBase},
	"S-1-5-20":     {"Network Service", model.KindBase},
	"S-1-5-32-544": {"Administrators", model.KindGroup},
	"S-1-5-32-545": {"Users", model.KindGroup},
	"S-1-5-32-546": {"Guests", model.KindGroup},
	"S-1-5-32-547": {"Power Users", model.KindGroup},
	"S-1-5-32-548": {"Account Operators", model.KindGroup},
	"S-1-5-32-549": {"Server Operators", model.KindGroup},
	"S-1-5-32-550": {"Print Operators", model.KindGroup},
	"S-1-5-32-551": {"Backup Operators", model.KindGroup},
	"S-1-5-32-552": {"Replicators", model.KindGroup},
	"S-1-5-32-554": {"Pre-Windows 2000 Compatible Access", model.KindGroup},
	"S-1-5-32-555": {"Remote Desktop Users", model.KindGroup},
	"S-1-5-32-556": {"Network Configuration Operators", model.KindGroup},
	"S-1-5-32-557": {"Incoming Forest Trust Builders", model.KindGroup},
	"S-1-5-32-558": {"Performance Monitor Users", model.KindGroup},
	"S-1-5-32-559": {"Performance Log Users", model.KindGroup},
	"S-1-5-32-560": {"Windows Authorization Access Group", model.KindGroup},
	"S-1-5-32-562": {"Distributed COM Users", model.KindGroup},
	"S-1-5-32-569": {"Cryptographic Operators", model.KindGroup},
	"S-1-5-32-573": {"Event Log Readers", model.KindGroup},
	"S-1-5-32-574": {"Certificate Service DCOM Access", model.KindGroup},
	"S-1-5-32-575": {"RDS Remote Access Servers", model.KindGroup},
	"S-1-5-32-576": {"RDS Endpoint Servers", model.KindGroup},
	"S-1-5-32-577": {"RDS Management Servers", model.KindGroup},
	"S-1-5-32-578": {"Hyper-V Administrators", model.KindGroup},
	"S-1-5-32-579": {"Access Control Assistance Operators", model.KindGroup},
	"S-1-5-32-580": {"Remote Management Users", model.KindGroup},
}

// aclTarget is one object category the ACL pass reads.
type aclTarget struct {
	kind   model.Kind
	filter string
	scope  int
	attrs  []string
}

// collectACL reads nTSecurityDescriptor for every object class BloodHound
// reports ACL edges for and adds the resulting edges and any missing nodes.
//
// Unlike the group/objectprops passes it is fully self-sufficient: `-c acl`
// alone produces the ACL edges, creating the target nodes it needs.
func collectACL(conn *ldap.Conn, o Options, g *model.Graph, dnIndex map[string]string, baseDN string) error {
	schemaDN := "CN=Schema,CN=Configuration," + baseDN
	classGUIDs, err := fetchSchemaGUIDs(conn, schemaDN)
	if err != nil {
		g.Meta.Warnings = append(g.Meta.Warnings, fmt.Sprintf(
			"acl: schema at %s could not be read (%v) — inherited ACEs were not filtered by target class and ACL edges may over-approximate",
			schemaDN, err))
		classGUIDs = map[string]GUID{}
	}

	base := []string{"nTSecurityDescriptor", "objectSid", "objectGUID", "distinguishedName", "name", "sAMAccountName"}
	computerAttrs := []string{
		"nTSecurityDescriptor", "objectSid", "objectGUID", "distinguishedName", "name", "sAMAccountName",
		"operatingSystem", "ms-mcs-admpwdexpirationtime", "msLaps-PasswordExpirationTime",
	}
	// The domain head is read first so that if the container search also matches
	// it, the Domain node is the one that wins.
	targets := []aclTarget{
		{model.KindDomain, "(objectClass=*)", ldap.ScopeBaseObject, base},
		{model.KindUser, "(&(objectCategory=person)(objectClass=user))", ldap.ScopeWholeSubtree, base},
		{model.KindGroup, "(objectClass=group)", ldap.ScopeWholeSubtree, base},
		{model.KindComputer, "(objectClass=computer)", ldap.ScopeWholeSubtree, computerAttrs},
		{model.KindOU, "(objectClass=organizationalUnit)", ldap.ScopeWholeSubtree, base},
		{model.KindGPO, "(objectClass=groupPolicyContainer)", ldap.ScopeWholeSubtree, base},
		{model.KindContainer, "(objectClass=container)", ldap.ScopeWholeSubtree, base},
	}

	known := g.NodeIndex()
	// upsert adds a node, or merges props into an existing one.
	upsert := func(n model.Node) {
		if cur, ok := known[n.ID]; ok {
			if len(n.Props) > 0 {
				if cur.Props == nil {
					cur.Props = map[string]string{}
				}
				for k, v := range n.Props {
					cur.Props[k] = v
				}
				g.AddNode(cur)
				known[n.ID] = cur
			}
			return
		}
		g.AddNode(n)
		known[n.ID] = n
	}
	ensurePrincipal := func(sid string) {
		if sid == "" {
			return
		}
		if _, ok := known[sid]; ok {
			return
		}
		n := model.Node{ID: sid, Kind: model.KindBase, Name: sid, Domain: o.Domain,
			Props: map[string]string{"placeholder": "true"}}
		if wk, ok := wellKnownPrincipals[sid]; ok {
			n.Name = wk.Name
			n.Kind = wk.Kind
			n.Props = map[string]string{"wellknown": "true"}
		}
		g.AddNode(n)
		known[sid] = n
	}

	var (
		seenDN              = map[string]bool{}
		noSD                int
		badSD               int
		unknownACETypes     = map[uint8]int{}
		inheritedUnfiltered int
	)

	for _, t := range targets {
		t := t
		err := eachEntryWithControls(conn, baseDN, t.filter, t.attrs, t.scope, []ldap.Control{sdFlagsControl()},
			func(e *ldap.Entry) {
				if seenDN[e.DN] {
					return
				}
				seenDN[e.DN] = true

				id := sidOf(e)
				if id == "" {
					id = guidOf(e)
				}
				if id == "" {
					return
				}
				if _, ok := dnIndex[e.DN]; !ok {
					dnIndex[e.DN] = id
				}

				props := map[string]string{}
				hasLAPS := false
				if t.kind == model.KindComputer {
					hasLAPS = computerHasLAPS(e)
					props["haslaps"] = boolStr(hasLAPS)
					if os := attr(e, "operatingSystem"); os != "" {
						props["os"] = os
					}
				}
				upsert(model.Node{
					ID: id, Kind: t.kind, Name: attr(e, "name"),
					SAMAccountName: attr(e, "sAMAccountName"),
					Domain:         o.Domain, DN: e.DN, Props: props,
				})

				raw := rawAttr(e, "nTSecurityDescriptor")
				if len(raw) == 0 {
					noSD++
					return
				}
				sd, perr := ParseSecurityDescriptor(raw)
				if perr != nil {
					badSD++
					return
				}
				if sd.DACLProtected {
					upsert(model.Node{ID: id, Props: map[string]string{"isaclprotected": "true"}})
				}
				rels, st := aclRelations(t.kind, sd, classGUIDs, hasLAPS)
				for typ, n := range st.UnknownACETypes {
					unknownACETypes[typ] += n
				}
				inheritedUnfiltered += st.InheritedUnfiltered
				for _, r := range rels {
					ensurePrincipal(r.SID)
					var eprops map[string]string
					if r.Inherited {
						eprops = map[string]string{"inherited": "true"}
					}
					g.AddEdge(model.Edge{Source: r.SID, Target: id, Kind: r.Kind, Props: eprops})
				}
			})
		if err != nil {
			return err
		}
	}

	if noSD > 0 {
		g.Meta.Warnings = append(g.Meta.Warnings, fmt.Sprintf(
			"acl: %d object(s) returned no nTSecurityDescriptor (usually missing READ_CONTROL) — their ACL edges are absent", noSD))
	}
	if badSD > 0 {
		g.Meta.Warnings = append(g.Meta.Warnings, fmt.Sprintf(
			"acl: %d security descriptor(s) could not be parsed and were skipped", badSD))
	}
	if len(unknownACETypes) > 0 {
		g.Meta.Warnings = append(g.Meta.Warnings, fmt.Sprintf(
			"acl: skipped %d ACE(s) of unsupported types (%s); only allow and allow-object ACEs are mapped",
			totalACECount(unknownACETypes), formatACETypes(unknownACETypes)))
	}
	if inheritedUnfiltered > 0 {
		g.Meta.Warnings = append(g.Meta.Warnings, fmt.Sprintf(
			"acl: %d inherited ACE(s) were applied without class filtering (schema unavailable) — edges may over-approximate",
			inheritedUnfiltered))
	}
	return nil
}

// fetchSchemaGUIDs reads schemaIDGUID + name from the schema naming context and
// returns lowercased schema name -> GUID. This is how BloodHound.py resolves the
// class and attribute GUIDs an ACE can reference.
func fetchSchemaGUIDs(conn *ldap.Conn, schemaDN string) (map[string]GUID, error) {
	out := map[string]GUID{}
	err := eachEntryWithControls(conn, schemaDN, "(schemaIDGUID=*)", []string{"name", "schemaIDGUID"},
		ldap.ScopeWholeSubtree, nil, func(e *ldap.Entry) {
			raw := rawAttr(e, "schemaIDGUID")
			if len(raw) != 16 {
				return
			}
			name := strings.ToLower(strings.TrimSpace(attr(e, "name")))
			if name == "" {
				return
			}
			var g GUID
			copy(g[:], raw)
			if _, ok := out[name]; !ok {
				out[name] = g
			}
		})
	if err != nil {
		return nil, err
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("schema search returned no schemaIDGUID entries")
	}
	return out, nil
}

// guidOf returns an entry's objectGUID in canonical form, or "" when absent.
func guidOf(e *ldap.Entry) string {
	raw := rawAttr(e, "objectGUID")
	if len(raw) != 16 {
		return ""
	}
	var g GUID
	copy(g[:], raw)
	return g.String()
}

// attr and rawAttr read an attribute case-insensitively. AD echoes attribute
// names under its own capitalisation (which can differ from the request — e.g.
// "msLAPS-PasswordExpirationTime"), and go-ldap's plain Entry getters match case
// exactly, so the ACL pass looks up attributes through these helpers.
func attr(e *ldap.Entry, name string) string {
	return e.GetEqualFoldAttributeValue(name)
}

func rawAttr(e *ldap.Entry, name string) []byte {
	return e.GetEqualFoldRawAttributeValue(name)
}

// computerHasLAPS reports whether LAPS is deployed on a computer, matching
// BloodHound.py: either the legacy or the Windows LAPS expiration attribute is
// present on the object.
func computerHasLAPS(e *ldap.Entry) bool {
	return attr(e, "ms-mcs-admpwdexpirationtime") != "" ||
		attr(e, "msLaps-PasswordExpirationTime") != ""
}

func totalACECount(m map[uint8]int) int {
	total := 0
	for _, n := range m {
		total += n
	}
	return total
}

func formatACETypes(m map[uint8]int) string {
	types := make([]int, 0, len(m))
	for t := range m {
		types = append(types, int(t))
	}
	sort.Ints(types)
	parts := make([]string, 0, len(types))
	for _, t := range types {
		parts = append(parts, fmt.Sprintf("0x%02x×%d", t, m[uint8(t)]))
	}
	return strings.Join(parts, ", ")
}
