package collector

import (
	"fmt"
	"strings"

	"github.com/go-ldap/ldap/v3"

	"github.com/krazybeastx1/omenhound/pkg/model"
)

// ---------------------------------------------------------------------------
// OU / GPO / container collection (-c container)
//
// This mirrors BloodHound.py's do_container_collection (enumerate_gpos,
// enumerate_ous, enumerate_containers in bloodhound/enumeration/memberships.py)
// and produces the two relationships that make up BloodHound's container model:
//
//	OU / Container / Domain --Contains--> direct child object
//	GPO                     --GPLink---> OU / Domain
//
// OUs, GPOs and containers have no SID, so they are keyed by objectGUID in
// canonical BloodHound form (uppercase, no braces). GPO links are read from each
// container's gPLink attribute ([MS-GPOL] 2.2.1.1.1).
// ---------------------------------------------------------------------------

// childObjectFilter is BloodHound.py's get_childobjects filter: the object
// classes that appear as children of a container, one level down.
const childObjectFilter = "(|(objectClass=container)(objectClass=organizationalUnit)(sAMAccountType=805306369)(objectClass=group)(&(objectCategory=person)(objectClass=user)))"

// gplink is one entry of a gPLink attribute: a GPO's DN plus its option flags.
type gplink struct {
	dn     string
	option int
}

// parseGPLink parses an AD gPLink value. The attribute is a concatenation of
// "[LDAP://<gpo dn>;<options>]" segments, where the options are 0 = enabled,
// 1 = disabled, 2 = enabled and enforced, 3 = disabled and enforced
// ([MS-GPOL] 2.2.1.1.1). Malformed segments are skipped rather than fatal.
func parseGPLink(linkstr string) []gplink {
	var out []gplink
	for _, seg := range strings.Split(linkstr, "LDAP://")[1:] {
		seg = strings.TrimRight(seg, "][ ")
		parts := strings.SplitN(seg, ";", 2)
		if len(parts) != 2 {
			continue
		}
		dn := strings.TrimSpace(parts[0])
		if dn == "" {
			continue
		}
		opt := 0
		if _, err := fmt.Sscanf(strings.TrimSpace(parts[1]), "%d", &opt); err != nil {
			continue
		}
		out = append(out, gplink{dn: dn, option: opt})
	}
	return out
}

// isFilteredContainer reports whether a container object should be skipped
// entirely, matching BloodHound.py's is_filtered_container: the DomainUpdates
// container and the per-policy User/Machine containers are noise.
func isFilteredContainer(dn string) bool {
	u := strings.ToUpper(dn)
	if strings.Contains(u, "CN=DOMAINUPDATES,CN=SYSTEM,DC=") {
		return true
	}
	if strings.Contains(u, "CN=POLICIES,CN=SYSTEM,DC=") &&
		(strings.HasPrefix(u, "CN=USER") || strings.HasPrefix(u, "CN=MACHINE")) {
		return true
	}
	return false
}

// isFilteredContainerChild reports whether a child object is part of a container
// BloodHound.py refuses to walk (CN=System and the leftover Program Data
// container).
func isFilteredContainerChild(dn string) bool {
	u := strings.ToUpper(dn)
	return strings.Contains(u, "CN=PROGRAM DATA,DC=") || strings.Contains(u, "CN=SYSTEM,DC=")
}

// gpoIDFromDN extracts the GPO GUID from a GPO distinguished name of the form
// CN={<guid>},CN=Policies,CN=System,DC=... and returns its canonical node ID.
func gpoIDFromDN(dn string) (string, bool) {
	open := strings.IndexByte(dn, '{')
	if open < 0 {
		return "", false
	}
	closeIdx := strings.IndexByte(dn[open:], '}')
	if closeIdx < 0 {
		return "", false
	}
	g, err := ParseGUID(dn[open : open+closeIdx+1])
	if err != nil {
		return "", false
	}
	return strings.ToUpper(g.String()), true
}

// collectContainers enumerates GPOs, OUs and containers and wires up Containment
// and GPO-link edges. It only runs for -c container; -c acl still creates the
// OU/GPO/container nodes it needs on its own.
func collectContainers(conn *ldap.Conn, o Options, g *model.Graph, dnIndex map[string]string, baseDN string) error {
	index := g.NodeIndex()

	// AD distinguishes DNs case-insensitively; gPLink values use whatever case
	// the DC stored, so the DN index is consulted case-insensitively.
	byDN := map[string]string{}
	remember := func(dn, id string) {
		dn = strings.TrimSpace(dn)
		if dn == "" || id == "" {
			return
		}
		byDN[strings.ToUpper(dn)] = id
		if dnIndex != nil {
			if _, ok := dnIndex[dn]; !ok {
				dnIndex[dn] = id
			}
		}
	}
	for dn, id := range dnIndex {
		byDN[strings.ToUpper(dn)] = id
	}

	var (
		gpos           int
		ous            int
		containers     int
		disabledLinks  int
		unresolvedGPOs int
		childErrors    int
		perr           error
	)

	// --- GPOs, first: gPLink values resolve against them. --------------------
	if perr = eachEntry(conn, baseDN, "(objectCategory=groupPolicyContainer)",
		[]string{"objectGUID", "distinguishedName", "displayName", "name", "gPCFileSysPath"},
		func(e *ldap.Entry) {
			id := guidOf(e)
			if id == "" {
				return
			}
			gpos++
			remember(e.DN, id)
			props := map[string]string{"highvalue": "false"}
			if p := strings.ToUpper(attr(e, "gPCFileSysPath")); p != "" {
				props["gpcpath"] = p
			}
			upsertNode(g, index, model.Node{
				ID: id, Kind: model.KindGPO, Domain: o.Domain, DN: e.DN,
				Name:  firstNonEmptyStr(attr(e, "displayName"), attr(e, "name")),
				Props: props,
			})
		}); perr != nil {
		return perr
	}

	// --- Child containment and GPO links, generic over the parent. -----------
	childAttrs := []string{"objectSid", "objectGUID", "objectClass", "distinguishedName", "name", "sAMAccountName", "sAMAccountType"}

	// addChildren records a parent's direct children as Contains edges and makes
	// sure each child has a node. skipFiltered drops the CN=System / Program Data
	// subtrees that BloodHound.py ignores for containers and the domain head.
	addChildren := func(parentDN, parentID string, skipFiltered bool) error {
		if parentID == "" {
			return nil
		}
		return eachEntryWithControls(conn, parentDN, childObjectFilter, childAttrs, ldap.ScopeSingleLevel, nil,
			func(c *ldap.Entry) {
				if skipFiltered && isFilteredContainerChild(c.DN) {
					return
				}
				cid := sidOf(c)
				if cid == "" {
					cid = guidOf(c)
				}
				if cid == "" {
					return
				}
				upsertNode(g, index, model.Node{
					ID: cid, Kind: objectKindFromClasses(attrs(c, "objectClass"), attr(c, "sAMAccountType")),
					Name: attr(c, "name"), Domain: o.Domain, DN: c.DN,
					SAMAccountName: attr(c, "sAMAccountName"),
				})
				remember(c.DN, cid)
				g.AddEdge(model.Edge{Source: parentID, Target: cid, Kind: model.EdgeContains})
			})
	}

	// addLinks records a container's GPO links as GPO -> container edges.
	addLinks := func(e *ldap.Entry, parentID string) {
		for _, l := range parseGPLink(attr(e, "gPLink")) {
			if l.option != 0 && l.option != 2 {
				disabledLinks++ // disabled link (option 1/3): BloodHound.py omits it
				continue
			}
			gid := byDN[strings.ToUpper(l.dn)]
			if gid == "" {
				// The GPO object itself was not enumerated (deleted, unreadable,
				// or in a filtered container). The link still exists, and its DN
				// carries the GPO GUID, so keep the edge with a placeholder node.
				gu, ok := gpoIDFromDN(l.dn)
				if !ok {
					unresolvedGPOs++
					continue
				}
				gid = gu
				upsertNode(g, index, model.Node{ID: gid, Kind: model.KindGPO, Domain: o.Domain, Name: gid})
				unresolvedGPOs++
			}
			var props map[string]string
			if l.option == 2 {
				props = map[string]string{"enforced": "true"}
			}
			g.AddEdge(model.Edge{Source: gid, Target: parentID, Kind: model.EdgeGPLink, Props: props})
		}
	}

	// --- OUs -----------------------------------------------------------------
	// BloodHound.py does not filter OU children, and reads the OU's own gPLink.
	if perr = eachEntry(conn, baseDN, "(objectCategory=organizationalUnit)",
		[]string{"objectGUID", "distinguishedName", "name", "gPLink", "gPOptions"},
		func(e *ldap.Entry) {
			id := guidOf(e)
			if id == "" {
				return
			}
			ous++
			remember(e.DN, id)
			upsertNode(g, index, model.Node{
				ID: id, Kind: model.KindOU, Name: attr(e, "name"), Domain: o.Domain, DN: e.DN,
				Props: map[string]string{
					"highvalue":         "false",
					"blocksinheritance": boolStr(strings.TrimSpace(attr(e, "gPOptions")) == "1"),
				},
			})
			if err := addChildren(e.DN, id, false); err != nil {
				childErrors++
			}
			addLinks(e, id)
		}); perr != nil {
		return perr
	}

	// --- Containers ----------------------------------------------------------
	if perr = eachEntry(conn, baseDN, "(&(objectCategory=container)(objectClass=container))",
		[]string{"objectGUID", "distinguishedName", "name"},
		func(e *ldap.Entry) {
			if isFilteredContainer(e.DN) {
				return
			}
			id := guidOf(e)
			if id == "" {
				return
			}
			containers++
			remember(e.DN, id)
			upsertNode(g, index, model.Node{
				ID: id, Kind: model.KindContainer, Name: attr(e, "name"), Domain: o.Domain, DN: e.DN,
				Props: map[string]string{"highvalue": "false"},
			})
			if err := addChildren(e.DN, id, true); err != nil {
				childErrors++
			}
		}); perr != nil {
		return perr
	}

	// --- The domain head's own children --------------------------------------
	if domainID := dnIndex[baseDN]; domainID != "" {
		if err := addChildren(baseDN, domainID, true); err != nil {
			childErrors++
		}
	}

	// Housekeeping: a container search that returns nothing at all is worth
	// saying out loud, because the graph would then look like the domain has no
	// OUs even though the method was requested.
	if ous == 0 && containers == 0 && gpos == 0 {
		g.Meta.Warnings = append(g.Meta.Warnings,
			"container: no OUs, GPOs or containers were returned; verify the bind account can read the domain naming context")
	}
	if disabledLinks > 0 {
		g.Meta.Warnings = append(g.Meta.Warnings, fmt.Sprintf(
			"container: %d disabled GPO link(s) were omitted (matching BloodHound); the GPO applies nowhere", disabledLinks))
	}
	if unresolvedGPOs > 0 {
		g.Meta.Warnings = append(g.Meta.Warnings, fmt.Sprintf(
			"container: %d GPO link(s) referenced a GPO that was not enumerated; the GUID was taken from the link DN", unresolvedGPOs))
	}
	if childErrors > 0 {
		g.Meta.Warnings = append(g.Meta.Warnings, fmt.Sprintf(
			"container: %d child search(es) failed; those containers have no Contains edges", childErrors))
	}
	return nil
}

// firstNonEmptyStr returns the first non-empty value.
func firstNonEmptyStr(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}
