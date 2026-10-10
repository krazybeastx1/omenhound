// Package model defines OmenHound's graph data model.
//
// The node and edge kinds intentionally mirror BloodHound CE's schema so that
// existing BloodHound Cypher queries and attack-path logic keep working against
// an OmenHound-populated Neo4j graph. Node IDs are AD SIDs (or objectGUID when a
// SID is unavailable) to give every entity a stable, domain-unique identity.
package model

import "time"

// Kind is the type of a graph node. Values match BloodHound CE labels.
type Kind string

const (
	KindUser      Kind = "User"
	KindGroup     Kind = "Group"
	KindComputer  Kind = "Computer"
	KindDomain    Kind = "Domain"
	KindOU        Kind = "OU"
	KindGPO       Kind = "GPO"
	KindContainer Kind = "Container"
	KindTrust     Kind = "Trust"
)

// EdgeKind is an AD relationship. Values match BloodHound CE edge names and are
// the keys the abuse-command renderer uses.
type EdgeKind string

const (
	EdgeGenericAll          EdgeKind = "GenericAll"
	EdgeGenericWrite        EdgeKind = "GenericWrite"
	EdgeWriteDacl           EdgeKind = "WriteDacl"
	EdgeWriteOwner          EdgeKind = "WriteOwner"
	EdgeForceChangePassword EdgeKind = "ForceChangePassword"
	EdgeAddMember           EdgeKind = "AddMember"
	EdgeAddSelf             EdgeKind = "AddSelf"
	EdgeOwns                EdgeKind = "Owns"
	EdgeAllowedToDelegate   EdgeKind = "AllowedToDelegate"
	EdgeAllowedToAct        EdgeKind = "AllowedToAct"
	EdgeAdminTo             EdgeKind = "AdminTo"
	EdgeCanPSRemote         EdgeKind = "CanPSRemote"
	EdgeExecuteDCOM         EdgeKind = "ExecuteDCOM"
	EdgeHasSession          EdgeKind = "HasSession"
	EdgeMemberOf            EdgeKind = "MemberOf"
	EdgeDCSync              EdgeKind = "DCSync"
	EdgeGetChanges          EdgeKind = "GetChanges"
	EdgeGetChangesAll       EdgeKind = "GetChangesAll"
	EdgeReadLAPSPassword    EdgeKind = "ReadLAPSPassword"
	EdgeReadGMSAPassword    EdgeKind = "ReadGMSAPassword"
	EdgeContains            EdgeKind = "Contains"
	EdgeGPLink              EdgeKind = "GPLink"
	EdgeTrustedBy           EdgeKind = "TrustedBy"
)

// Node is a single AD entity. Props carries collector-specific attributes
// (e.g. "enabled", "admincount", "pwdlastset") without needing schema changes.
type Node struct {
	ID             string            `json:"id"`
	Kind           Kind              `json:"kind"`
	Name           string            `json:"name"`
	Domain         string            `json:"domain,omitempty"`
	SAMAccountName string            `json:"sam_account_name,omitempty"`
	DN             string            `json:"distinguished_name,omitempty"`
	Props          map[string]string `json:"props,omitempty"`
}

// Edge is a directed relationship between two nodes (Source -> Target).
type Edge struct {
	Source string            `json:"source"`
	Target string            `json:"target"`
	Kind   EdgeKind          `json:"kind"`
	Props  map[string]string `json:"props,omitempty"`
}

// Meta describes a collection run.
type Meta struct {
	Collector  string    `json:"collector"`
	Version    string    `json:"version"`
	Domain     string    `json:"domain,omitempty"`
	StartedAt  time.Time `json:"started_at"`
	FinishedAt time.Time `json:"finished_at"`
}

// Graph is a full collection result. It is the on-the-wire format between the
// collector and the ingestion API, and the export format for `omenhound export`.
type Graph struct {
	Nodes []Node `json:"nodes"`
	Edges []Edge `json:"edges"`
	Meta  Meta   `json:"meta"`
}

// AddNode appends a node if its ID is not already present.
func (g *Graph) AddNode(n Node) {
	for i := range g.Nodes {
		if g.Nodes[i].ID == n.ID {
			g.Nodes[i] = n
			return
		}
	}
	g.Nodes = append(g.Nodes, n)
}

// AddEdge appends an edge, deduplicating on (Source, Target, Kind).
func (g *Graph) AddEdge(e Edge) {
	for i := range g.Edges {
		if g.Edges[i].Source == e.Source && g.Edges[i].Target == e.Target && g.Edges[i].Kind == e.Kind {
			return
		}
	}
	g.Edges = append(g.Edges, e)
}

// NodeIndex returns a map of node ID -> Node for fast lookup.
func (g *Graph) NodeIndex() map[string]Node {
	m := make(map[string]Node, len(g.Nodes))
	for _, n := range g.Nodes {
		m[n.ID] = n
	}
	return m
}
