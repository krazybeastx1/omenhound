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
	// Close releases backend resources.
	Close(ctx context.Context) error
}
