package collector

import (
	"strings"

	"github.com/go-ldap/ldap/v3"

	"github.com/krazybeastx1/omenhound/pkg/model"
)

// samAccountTypeComputer is SAM_MACHINE_ACCOUNT, the sAMAccountType value of a
// computer object. BloodHound.py's child-object search matches computers by this
// value rather than by objectClass.
const samAccountTypeComputer = "805306369"

// upsertNode adds n to g, or merges it into the node that already has the same
// ID, and returns the stored node.
//
// The collectors overlap heavily: an OU is also an ACL target, a computer is a
// child of its OU, and the same object can be reached by several passes. Merging
// makes node creation order-independent and never drops a property another pass
// recorded. Identity fields (name, DN, SAM account name, domain, kind) only fill
// blanks, so the first writer wins on identity while properties accumulate.
//
// index is the live ID -> Node map for g (model.Graph.NodeIndex) and is mutated
// in place; it must come from the same graph.
func upsertNode(g *model.Graph, index map[string]model.Node, n model.Node) model.Node {
	cur, ok := index[n.ID]
	if !ok {
		g.AddNode(n)
		index[n.ID] = n
		return n
	}
	if len(n.Props) > 0 {
		if cur.Props == nil {
			cur.Props = make(map[string]string, len(n.Props))
		}
		for k, v := range n.Props {
			cur.Props[k] = v
		}
	}
	if cur.Name == "" {
		cur.Name = n.Name
	}
	if cur.Domain == "" {
		cur.Domain = n.Domain
	}
	if cur.DN == "" {
		cur.DN = n.DN
	}
	if cur.SAMAccountName == "" {
		cur.SAMAccountName = n.SAMAccountName
	}
	// Upgrade only a placeholder kind; never replace a specific one.
	if cur.Kind == "" || (cur.Kind == model.KindBase && n.Kind != model.KindBase) {
		cur.Kind = n.Kind
	}
	g.AddNode(cur)
	index[n.ID] = cur
	return cur
}

// attrs reads a multi-valued attribute case-insensitively, for the same reason
// as attr/rawAttr: AD echoes attribute names under its own capitalisation.
func attrs(e *ldap.Entry, name string) []string {
	return e.GetEqualFoldAttributeValues(name)
}

// objectKindFromClasses derives a node kind from an entry's objectClass values,
// preferring the most specific class. It is the equivalent of BloodHound.py's
// ADUtils.resolve_ad_entry type mapping for the classes a child search returns.
func objectKindFromClasses(classes []string, samAccountType string) model.Kind {
	has := func(want string) bool {
		for _, c := range classes {
			if strings.EqualFold(strings.TrimSpace(c), want) {
				return true
			}
		}
		return false
	}
	switch {
	case has("organizationalUnit"):
		return model.KindOU
	case has("container"):
		return model.KindContainer
	case has("group"):
		return model.KindGroup
	case has("computer"):
		return model.KindComputer
	case has("user"):
		return model.KindUser
	case strings.TrimSpace(samAccountType) == samAccountTypeComputer:
		return model.KindComputer
	}
	return model.KindBase
}
