package analytics

import (
	"github.com/krazybeastx1/omenhound/pkg/model"
)

// Categories group the queries in the UI.
const (
	catCredentials = "Credentials"
	catDelegation  = "Delegation"
	catRemote      = "Remote access"
	catProtected   = "Protected objects"
)

// definitions is every canned query, in display order. Each Cypher mirrors the
// equivalent BloodHound CE query so the same question runs against a
// CE-populated Neo4j graph.
var definitions = []definition{
	// ---- Credentials ----
	{
		Query: Query{
			ID:          "kerberoastable",
			Title:       "Kerberoastable users",
			Category:    catCredentials,
			Description: "Enabled users with a service principal name (SPN). Their Kerberos TGS tickets can be requested and cracked offline.",
			Cypher:      "MATCH (u:User) WHERE NOT u.name STARTS WITH 'KRBTGT' AND (u.hasspn = true OR u.serviceprincipalname IS NOT NULL) RETURN u",
		},
		match:         matchKerberoastable,
		requiresProps: []string{"hasspn", "serviceprincipalname"},
	},
	{
		Query: Query{
			ID:          "asreproastable",
			Title:       "AS-REP roastable users",
			Category:    catCredentials,
			Description: "Users that do not require Kerberos pre-authentication. An AS-REP can be requested without valid credentials and cracked offline.",
			Cypher:      "MATCH (u:User {dontreqpreauth:true}) RETURN u",
		},
		match:         matchASREP,
		requiresProps: []string{"dontreqpreauth"},
	},
	{
		Query: Query{
			ID:          "dcsync",
			Title:       "DCSync-capable principals",
			Category:    catCredentials,
			Description: "Principals with directory replication rights (GetChanges / GetChangesAll / DCSync) over a domain; they can replicate credential hashes.",
			Cypher:      "MATCH (n)-[:GetChanges|GetChangesAll|GetChangesInFilteredSet|DCSync]->(d:Domain) RETURN n, d",
		},
		match: matchDCSync,
		requiresEdges: []model.EdgeKind{
			model.EdgeDCSync, model.EdgeGetChanges, model.EdgeGetChangesAll, model.EdgeGetChangesInFilteredSet,
		},
	},
	{
		Query: Query{
			ID:          "laps-readable",
			Title:       "LAPS password readers",
			Category:    catCredentials,
			Description: "Principals that can read a computer's LAPS-managed local administrator password (ReadLAPSPassword).",
			Cypher:      "MATCH (n)-[:ReadLAPSPassword]->(c:Computer) RETURN n, c",
		},
		match:         matchLAPS,
		requiresEdges: []model.EdgeKind{model.EdgeReadLAPSPassword},
	},
	{
		Query: Query{
			ID:          "password-never-expires",
			Title:       "Passwords that never expire",
			Category:    catCredentials,
			Description: "Users whose password is configured never to expire.",
			Cypher:      "MATCH (u:User {pwdneverexpires:true}) RETURN u",
		},
		match:         matchPwdNeverExpires,
		requiresProps: []string{"pwdneverexpires"},
	},

	// ---- Delegation ----
	{
		Query: Query{
			ID:          "unconstrained-delegation",
			Title:       "Unconstrained delegation",
			Category:    catDelegation,
			Description: "Users or computers trusted for unconstrained Kerberos delegation. Any TGT cached on such a host (e.g. a Domain Admin's) can be captured.",
			Cypher:      "MATCH (n) WHERE n.unconstraineddelegation = true AND (n:User OR n:Computer) RETURN n",
		},
		match:         matchUnconstrained,
		requiresProps: []string{"unconstraineddelegation"},
	},
	{
		Query: Query{
			ID:          "constrained-delegation",
			Title:       "Constrained delegation",
			Category:    catDelegation,
			Description: "Principals allowed to delegate to specific services (AllowedToDelegate).",
			Cypher:      "MATCH (n)-[:AllowedToDelegate]->(t) RETURN n, t",
		},
		match:         matchAllowedToDelegate,
		requiresEdges: []model.EdgeKind{model.EdgeAllowedToDelegate},
	},
	{
		Query: Query{
			ID:          "rbcd",
			Title:       "Resource-based constrained delegation",
			Category:    catDelegation,
			Description: "Principals that can configure resource-based constrained delegation against a target (AllowedToAct).",
			Cypher:      "MATCH (n)-[:AllowedToAct]->(t) RETURN n, t",
		},
		match:         matchAllowedToAct,
		requiresEdges: []model.EdgeKind{model.EdgeAllowedToAct},
	},

	// ---- Remote access ----
	{
		Query: Query{
			ID:          "adminto",
			Title:       "Local administrators on hosts",
			Category:    catRemote,
			Description: "Identities that are local administrators of one or more computers (AdminTo).",
			Cypher:      "MATCH (n)-[:AdminTo]->(c:Computer) RETURN n, c",
		},
		match:         matchAdminTo,
		requiresEdges: []model.EdgeKind{model.EdgeAdminTo},
	},
	{
		Query: Query{
			ID:          "has-session",
			Title:       "Observed sessions",
			Category:    catRemote,
			Description: "Identities observed with a session on a computer (HasSession). A credential may be recoverable from a host the identity logged on to.",
			Cypher:      "MATCH (n)-[:HasSession]->(c:Computer) RETURN n, c",
		},
		match:         matchHasSession,
		requiresEdges: []model.EdgeKind{model.EdgeHasSession},
	},

	// ---- Protected objects ----
	{
		Query: Query{
			ID:          "high-value-targets",
			Title:       "High-value targets",
			Category:    catProtected,
			Description: "Nodes marked high value (highvalue=true) — the usual goals of an attack path.",
			Cypher:      "MATCH (n {highvalue:true}) RETURN n",
		},
		match:         matchHighValue,
		requiresProps: []string{"highvalue"},
	},
	{
		Query: Query{
			ID:          "admincount",
			Title:       "AdminSDHolder-protected objects",
			Category:    catProtected,
			Description: "Users and groups with adminCount set — currently or formerly protected by AdminSDHolder, a strong privileged-account signal.",
			Cypher:      "MATCH (n) WHERE n.admincount = true AND (n:User OR n:Group) RETURN n",
		},
		match:         matchAdminCount,
		requiresProps: []string{"admincount"},
	},
	{
		Query: Query{
			ID:          "sensitive-users",
			Title:       "Sensitive users",
			Category:    catProtected,
			Description: "Users flagged sensitive — accounts that cannot be delegated and are often ACL-protected.",
			Cypher:      "MATCH (u:User {sensitive:true}) RETURN u",
		},
		match:         matchSensitive,
		requiresProps: []string{"sensitive"},
	},
	{
		Query: Query{
			ID:          "owned",
			Title:       "Owned principals",
			Category:    catProtected,
			Description: "Nodes marked owned in the dataset (owned=true) — the sources an operator has already compromised.",
			Cypher:      "MATCH (n {owned:true}) RETURN n",
		},
		match:         matchOwned,
		requiresProps: []string{"owned"},
	},
}

func matchKerberoastable(d *dataset) []Finding {
	var out []Finding
	for _, n := range collect(d, model.KindUser) {
		if isKrbtgt(n) {
			continue
		}
		var ev []string
		if hasTrue(n, "hasspn") {
			ev = append(ev, "hasspn=true")
		}
		if v, ok := nonEmptyProp(n, "serviceprincipalname"); ok {
			ev = append(ev, "serviceprincipalname="+v)
		}
		if len(ev) == 0 {
			continue
		}
		out = append(out, Finding{
			Node:     n,
			Reason:   "Has a service principal name (SPN); a Kerberos service ticket can be requested and cracked offline.",
			Evidence: ev,
		})
	}
	return out
}

func matchASREP(d *dataset) []Finding {
	var out []Finding
	for _, n := range collect(d, model.KindUser) {
		if hasTrue(n, "dontreqpreauth") {
			out = append(out, Finding{
				Node:     n,
				Reason:   "Does not require Kerberos pre-authentication; an AS-REP can be requested and cracked offline.",
				Evidence: []string{"dontreqpreauth=true"},
			})
		}
	}
	return out
}

func matchDCSync(d *dataset) []Finding {
	return outEdgeFindings(d, map[model.EdgeKind]bool{
		model.EdgeDCSync:                  true,
		model.EdgeGetChanges:              true,
		model.EdgeGetChangesAll:           true,
		model.EdgeGetChangesInFilteredSet: true,
	}, model.KindDomain, "Holds directory replication rights; can replicate credential hashes from the domain.")
}

func matchLAPS(d *dataset) []Finding {
	return outEdgeFindings(d, map[model.EdgeKind]bool{model.EdgeReadLAPSPassword: true},
		model.KindComputer, "Can read the LAPS-managed local administrator password of the listed host(s).")
}

func matchPwdNeverExpires(d *dataset) []Finding {
	var out []Finding
	for _, n := range collect(d, model.KindUser) {
		if hasTrue(n, "pwdneverexpires") {
			out = append(out, Finding{Node: n, Reason: "Password is configured never to expire.", Evidence: []string{"pwdneverexpires=true"}})
		}
	}
	return out
}

func matchUnconstrained(d *dataset) []Finding {
	var out []Finding
	for _, n := range collect(d, model.KindUser, model.KindComputer) {
		if hasTrue(n, "unconstraineddelegation") {
			out = append(out, Finding{
				Node:     n,
				Reason:   "Trusted for unconstrained Kerberos delegation; cached TGTs presented to it can be captured.",
				Evidence: []string{"unconstraineddelegation=true"},
			})
		}
	}
	return out
}

func matchAllowedToDelegate(d *dataset) []Finding {
	return outEdgeFindings(d, map[model.EdgeKind]bool{model.EdgeAllowedToDelegate: true}, "",
		"Allowed to delegate Kerberos authentication to the listed service(s).")
}

func matchAllowedToAct(d *dataset) []Finding {
	return outEdgeFindings(d, map[model.EdgeKind]bool{model.EdgeAllowedToAct: true}, "",
		"Can configure resource-based constrained delegation (RBCD) against the listed target(s).")
}

func matchAdminTo(d *dataset) []Finding {
	return outEdgeFindings(d, map[model.EdgeKind]bool{model.EdgeAdminTo: true}, model.KindComputer,
		"Is a local administrator of the listed host(s).")
}

func matchHasSession(d *dataset) []Finding {
	return outEdgeFindings(d, map[model.EdgeKind]bool{model.EdgeHasSession: true}, model.KindComputer,
		"Was observed with a session on the listed host(s); a credential may be recoverable from that host.")
}

func matchHighValue(d *dataset) []Finding {
	var out []Finding
	for _, n := range d.nodes {
		if hasTrue(n, "highvalue") {
			out = append(out, Finding{Node: n, Reason: "Marked as a high-value target.", Evidence: []string{"highvalue=true"}})
		}
	}
	return out
}

func matchAdminCount(d *dataset) []Finding {
	var out []Finding
	for _, n := range collect(d, model.KindUser, model.KindGroup) {
		if hasTrue(n, "admincount") {
			out = append(out, Finding{
				Node:     n,
				Reason:   "Has adminCount set — currently or formerly protected by AdminSDHolder.",
				Evidence: []string{"admincount=true"},
			})
		}
	}
	return out
}

func matchSensitive(d *dataset) []Finding {
	var out []Finding
	for _, n := range collect(d, model.KindUser) {
		if hasTrue(n, "sensitive") {
			out = append(out, Finding{Node: n, Reason: "Account is flagged sensitive and cannot be delegated.", Evidence: []string{"sensitive=true"}})
		}
	}
	return out
}

func matchOwned(d *dataset) []Finding {
	var out []Finding
	for _, n := range d.nodes {
		if hasTrue(n, "owned") {
			out = append(out, Finding{Node: n, Reason: "Marked as owned in the dataset.", Evidence: []string{"owned=true"}})
		}
	}
	return out
}
