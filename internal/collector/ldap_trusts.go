package collector

import (
	"fmt"
	"strings"

	"github.com/go-ldap/ldap/v3"

	"github.com/krazybeastx1/omenhound/pkg/model"
)

// ---------------------------------------------------------------------------
// Domain trust collection (-c trusts)
//
// trustedDomain objects live under CN=System in the domain naming context. Each
// one describes how *this* domain relates to another, and BloodHound expresses
// that as TrustedBy edges between Domain nodes:
//
//	(trusted domain) --TrustedBy--> (trusting domain)
//
// which is exactly the direction BloodHound.py's output and OmenHound's importer
// use, so a direct collection and an imported collection produce the same graph.
// ---------------------------------------------------------------------------

// trustDirection bits ([MS-ADTS] 6.1.6.7.9).
const (
	trustDirectionInbound  = 0x01 // the other domain trusts this one
	trustDirectionOutbound = 0x02 // this domain trusts the other one
)

// trustAttributes flags (ldapdomaindump / [MS-ADTS] 6.1.6.7.9).
const (
	trustNonTransitive     = 0x00000001
	trustQuarantined       = 0x00000004
	trustForestTransitive  = 0x00000008
	trustCrossOrganization = 0x00000010
	trustWithinForest      = 0x00000020
	trustTreatAsExternal   = 0x00000040
)

// BloodHound trust types, as BloodHound.py's ADDomainTrust.bh_trust_type.
const (
	trustTypeParentChild = 0
	trustTypeCrossLink   = 1
	trustTypeForest      = 2
	trustTypeExternal    = 3
	trustTypeUnknown     = 4
)

// classifyTrust maps a trustAttributes bitmask to BloodHound's (type,
// transitive, sidFilteringEnabled) triple. It is a faithful port of
// ADDomainTrust.to_output in bloodhound/ad/trusts.py.
func classifyTrust(flags int) (int, bool, bool) {
	switch {
	case flags&trustWithinForest != 0:
		// Parent/child or tree-root trust inside the forest. SID filtering is on
		// only for quarantined (i.e. selectively authenticated) trusts.
		return trustTypeParentChild, true, flags&trustQuarantined != 0
	case flags&trustForestTransitive != 0:
		// Forest trust: SID filtering is off unless TREAT_AS_EXTERNAL is set.
		return trustTypeForest, true, flags&trustTreatAsExternal == 0
	case flags&trustTreatAsExternal != 0 || flags&trustCrossOrganization != 0:
		return trustTypeExternal, false, true
	default:
		return trustTypeUnknown, flags&trustNonTransitive == 0, true
	}
}

// collectTrusts reads trustedDomain objects and adds a Domain node plus
// TrustedBy edge(s) for each, following the direction bits.
func collectTrusts(conn *ldap.Conn, o Options, g *model.Graph, dnIndex map[string]string, baseDN string) error {
	index := g.NodeIndex()
	domainID := ""
	if dnIndex != nil {
		domainID = dnIndex[baseDN]
	}
	if domainID == "" {
		g.Meta.Warnings = append(g.Meta.Warnings,
			"trusts: the domain object was not collected, so trust edges were skipped")
		return nil
	}

	var (
		trusts   int
		noTarget int
		noEdge   int
	)
	err := eachEntry(conn, baseDN, "(objectClass=trustedDomain)",
		[]string{"name", "flatName", "securityIdentifier", "trustAttributes", "trustDirection"},
		func(e *ldap.Entry) {
			trusts++
			name := strings.ToUpper(strings.TrimSpace(attr(e, "name")))
			sid := ""
			if raw := rawAttr(e, "securityIdentifier"); len(raw) > 0 {
				if s, err := FormatSID(raw); err == nil {
					sid = s
				}
			}
			// A trust with no resolvable target SID is still a real trust; key it
			// by its name, exactly as the importer does for BloodHound.py output.
			other := sid
			if other == "" {
				if name == "" {
					noTarget++
					return
				}
				other = "TRUST\\" + name
			}
			upsertNode(g, index, model.Node{
				ID: other, Kind: model.KindDomain, Name: firstNonEmptyStr(name, other),
			})

			direction := 0
			fmt.Sscanf(strings.TrimSpace(attr(e, "trustDirection")), "%d", &direction)
			if direction&trustDirectionInbound == 0 && direction&trustDirectionOutbound == 0 {
				// Direction 0 (or unparseable) means the relation cannot be
				// expressed as an edge, but the trust object was there.
				noEdge++
				return
			}

			// The relationship's own attributes ride along on the edge so the
			// abuse engine and UI can see them; CE's TrustedBy edges carry no
			// properties, so a re-export drops them again.
			flags := 0
			fmt.Sscanf(strings.TrimSpace(attr(e, "trustAttributes")), "%d", &flags)
			tt, transitive, sidFiltering := classifyTrust(flags)
			props := map[string]string{
				"trusttype":           fmt.Sprintf("%d", tt),
				"transitive":          boolStr(transitive),
				"sidfilteringenabled": boolStr(sidFiltering),
			}
			if direction&trustDirectionInbound != 0 {
				// The other domain trusts this one: this domain is trusted by it.
				g.AddEdge(model.Edge{Source: domainID, Target: other, Kind: model.EdgeTrustedBy, Props: props})
			}
			if direction&trustDirectionOutbound != 0 {
				g.AddEdge(model.Edge{Source: other, Target: domainID, Kind: model.EdgeTrustedBy, Props: props})
			}
		})
	if err != nil {
		return err
	}

	if trusts == 0 {
		g.Meta.Warnings = append(g.Meta.Warnings,
			"trusts: no trustedDomain objects were returned; the domain is either standalone or the bind account cannot read CN=System")
	}
	if noTarget > 0 {
		g.Meta.Warnings = append(g.Meta.Warnings, fmt.Sprintf(
			"trusts: %d trust(s) had neither a target SID nor a name and were skipped", noTarget))
	}
	if noEdge > 0 {
		g.Meta.Warnings = append(g.Meta.Warnings, fmt.Sprintf(
			"trusts: %d trust(s) had no usable trustDirection and produced no edge", noEdge))
	}
	return nil
}
