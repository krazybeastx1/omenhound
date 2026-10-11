// Package graph is OmenHound's persistence layer. The Store interface abstracts
// the graph database so the collector and API never depend on a specific
// backend. Two implementations ship: an in-memory store (tests, demos) and a
// Neo4j store (production, BloodHound CE compatible).
package graph

import (
	"context"
	"errors"

	"github.com/krazybeastx1/omenhound/pkg/model"
)

// ErrNotImplemented is returned by optional operations a backend does not support.
var ErrNotImplemented = errors.New("graph: not implemented")

// Stats summarises a populated graph.
type Stats struct {
	Nodes int `json:"nodes"`
	Edges int `json:"edges"`
}

// Store is the graph persistence contract.
type Store interface {
	// UpsertNodes inserts or updates nodes by ID.
	UpsertNodes(ctx context.Context, nodes []model.Node) error
	// UpsertEdges inserts relationships, deduplicating on (source,target,kind).
	UpsertEdges(ctx context.Context, edges []model.Edge) error
	// DeleteNode removes a node and its relationships.
	DeleteNode(ctx context.Context, id string) error
	// DeleteEdge removes a single relationship.
	DeleteEdge(ctx context.Context, source, target string, kind model.EdgeKind) error
	// GetNode returns one node by ID. The bool is false when absent.
	GetNode(ctx context.Context, id string) (model.Node, bool, error)
	// Neighbors returns outgoing edges from id.
	Neighbors(ctx context.Context, id string) ([]model.Edge, error)
	// Incoming returns incoming edges to id.
	Incoming(ctx context.Context, id string) ([]model.Edge, error)
	// AllNodes returns every node (used for serving the UI/export).
	AllNodes(ctx context.Context) ([]model.Node, error)
	// AllEdges returns every edge.
	AllEdges(ctx context.Context) ([]model.Edge, error)
	// Stats returns node/edge counts.
	Stats(ctx context.Context) (Stats, error)
	// SearchNodes returns nodes matching query, optionally filtered by kind/domain.
	SearchNodes(ctx context.Context, q string, kind model.Kind, domain string, limit, offset int) ([]model.Node, int, error)
	// Domains returns all distinct domains present in the graph.
	Domains(ctx context.Context) ([]string, error)
	// ShortestPaths returns a limited set of shortest paths from source to target.
	ShortestPaths(ctx context.Context, req ShortestPathRequest) (ShortestPathResult, error)
	// Close releases backend resources.
	Close(ctx context.Context) error
}

// Direction indicates graph traversal direction for relationships.
type Direction int

const (
	// Outgoing traverses edges in their stored direction (source -> target).
	Outgoing Direction = iota
	// Incoming traverses edges against their stored direction.
	Incoming
	// Undirected traverses relationships in both directions.
	Undirected
)

// ShortestPathRequest defines constraints for path searches.
type ShortestPathRequest struct {
	SourceID                    string
	TargetID                    string
	MaxDepth                    int
	MaxPaths                    int
	Direction                   Direction
	IncludeNodeTypes            []model.Kind
	ExcludeNodeTypes            []model.Kind
	IncludeRelationshipTypes    []model.EdgeKind
	ExcludeRelationshipTypes    []model.EdgeKind
	RequiredIntermediateNodeIDs []string
}

// Path is an ordered sequence of nodes and edges forming a path.
type Path struct {
	Nodes         []model.Node `json:"nodes"`
	Relationships []model.Edge `json:"relationships"`
	Length        int          `json:"length"`
}

// ShortestPathResult is the result set for a shortest-path query.
type ShortestPathResult struct {
	Paths     []Path `json:"paths"`
	Truncated bool   `json:"truncated"`
}
