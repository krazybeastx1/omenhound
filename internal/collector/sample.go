package collector

import (
	"context"
	"time"

	"github.com/krazybeastx1/omenhound/pkg/model"
)

// SampleCollector returns a fixed, realistic-looking AD graph. It requires no
// domain and is used by `omenhound serve --collector sample`, tests, and demos.
type SampleCollector struct{}

// Name implements Collector.
func (SampleCollector) Name() string { return "sample" }

// Collect implements Collector.
func (SampleCollector) Collect(_ context.Context, _ Options) (*model.Graph, error) {
	const (
		dom   = "omenhound.lab"
		domID = "S-1-5-21-1004336348-1177238915-682003330"
	)
	now := time.Now().UTC()
	g := &model.Graph{Meta: model.Meta{Collector: "sample", Domain: dom, StartedAt: now, FinishedAt: now}}

	g.AddNode(model.Node{ID: domID, Kind: model.KindDomain, Name: "OMENHOUND", Domain: dom, DN: "DC=omenhound,DC=lab"})

	user := func(sid, sam, name, dn string, admin bool, enabled bool) {
		props := map[string]string{"enabled": boolStr(enabled)}
		if admin {
			props["admincount"] = "true"
			props["highvalue"] = "true"
		}
		g.AddNode(model.Node{ID: sid, Kind: model.KindUser, Name: name, SAMAccountName: sam, Domain: dom, DN: dn, Props: props})
	}
	group := func(sid, sam, name, dn string, admin bool) {
		props := map[string]string{}
		if admin {
			props["admincount"] = "true"
			props["highvalue"] = "true"
		}
		g.AddNode(model.Node{ID: sid, Kind: model.KindGroup, Name: name, SAMAccountName: sam, Domain: dom, DN: dn, Props: props})
	}
	comp := func(sid, sam, name, dn, os string) {
		g.AddNode(model.Node{ID: sid, Kind: model.KindComputer, Name: name, SAMAccountName: sam, Domain: dom, DN: dn, Props: map[string]string{"os": os}})
	}

	p := domID + "-"
	group(p+"512", "Domain Admins", "Domain Admins", "CN=Domain Admins,CN=Users,DC=omenhound,DC=lab", true)
	group(p+"513", "Domain Users", "Domain Users", "CN=Domain Users,CN=Users,DC=omenhound,DC=lab", false)
	group(p+"1101", "IT Admins", "IT Admins", "CN=IT Admins,OU=Groups,DC=omenhound,DC=lab", false)
	group(p+"1102", "SQL Admins", "SQL Admins", "CN=SQL Admins,OU=Groups,DC=omenhound,DC=lab", false)

	user(p+"500", "Administrator", "Administrator", "CN=Administrator,CN=Users,DC=omenhound,DC=lab", true, true)
	user(p+"1103", "jdoe", "John Doe", "CN=John Doe,OU=Users,DC=omenhound,DC=lab", false, true)
	user(p+"1104", "alice", "Alice Smith", "CN=Alice Smith,OU=Users,DC=omenhound,DC=lab", false, true)
	user(p+"1105", "svc_sql", "SQL Service", "CN=SQL Service,OU=Service Accounts,DC=omenhound,DC=lab", false, true)

	comp(p+"1000", "DC01$", "DC01", "CN=DC01,OU=Domain Controllers,DC=omenhound,DC=lab", "Windows Server 2022")
	comp(p+"1001", "WEB01$", "WEB01", "CN=WEB01,OU=Servers,DC=omenhound,DC=lab", "Windows Server 2019")
	comp(p+"1002", "SQL01$", "SQL01", "CN=SQL01,OU=Servers,DC=omenhound,DC=lab", "Windows Server 2022")
	comp(p+"1003", "WS01$", "WS01", "CN=WS01,OU=Workstations,DC=omenhound,DC=lab", "Windows 11")

	memberOf := func(member, group string) {
		g.AddEdge(model.Edge{Source: member, Target: group, Kind: model.EdgeMemberOf})
	}
	memberOf(p+"500", p+"512")   // Administrator -> Domain Admins
	memberOf(p+"1103", p+"513")  // jdoe -> Domain Users
	memberOf(p+"1104", p+"1101") // alice -> IT Admins
	memberOf(p+"1105", p+"1102") // svc_sql -> SQL Admins
	memberOf(p+"1101", p+"512")  // IT Admins -> Domain Admins (nested)

	g.AddEdge(model.Edge{Source: p + "512", Target: p + "1000", Kind: model.EdgeAdminTo})
	g.AddEdge(model.Edge{Source: p + "1101", Target: p + "1001", Kind: model.EdgeAdminTo})
	g.AddEdge(model.Edge{Source: p + "1102", Target: p + "1002", Kind: model.EdgeAdminTo})
	g.AddEdge(model.Edge{Source: p + "1002", Target: p + "1001", Kind: model.EdgeAdminTo})

	// Weak ACLs that open a path: jdoe can GenericAll WS01; WS01 can GenericWrite SQL01.
	g.AddEdge(model.Edge{Source: p + "1103", Target: p + "1003", Kind: model.EdgeGenericAll})
	g.AddEdge(model.Edge{Source: p + "1003", Target: p + "1002", Kind: model.EdgeGenericWrite})
	g.AddEdge(model.Edge{Source: p + "1104", Target: p + "1001", Kind: model.EdgeHasSession})

	// The prize: svc_sql can DCSync the domain.
	g.AddEdge(model.Edge{Source: p + "1105", Target: domID, Kind: model.EdgeDCSync})
	g.AddEdge(model.Edge{Source: domID, Target: p + "1000", Kind: model.EdgeContains})

	return g, nil
}

func boolStr(b bool) string {
	if b {
		return "true"
	}
	return "false"
}
