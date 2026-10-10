// Package ingest validates a collected graph and writes it to a graph Store.
package ingest

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"github.com/krazybeastx1/omenhound/internal/graph"
	"github.com/krazybeastx1/omenhound/pkg/model"
)

// Limits bound untrusted input so a malicious or broken payload cannot exhaust
// memory. They are deliberately generous for real AD graphs.
const (
	MaxNodes = 5_000_000
	MaxEdges = 20_000_000
	MaxBytes = 512 << 20 // 512 MiB
)

// Result reports what an ingestion wrote.
type Result struct {
	Nodes int         `json:"nodes"`
	Edges int         `json:"edges"`
	Stats graph.Stats `json:"stats"`
}

// knownKinds / knownEdges validate input without importing backend internals.
var knownKinds = map[model.Kind]bool{
	model.KindUser: true, model.KindGroup: true, model.KindComputer: true, model.KindDomain: true,
	model.KindOU: true, model.KindGPO: true, model.KindContainer: true, model.KindTrust: true,
}

var knownEdges = map[model.EdgeKind]bool{
	model.EdgeGenericAll: true, model.EdgeGenericWrite: true, model.EdgeWriteDacl: true, model.EdgeWriteOwner: true,
	model.EdgeForceChangePassword: true, model.EdgeAddMember: true, model.EdgeAddSelf: true, model.EdgeOwns: true,
	model.EdgeAllowedToDelegate: true, model.EdgeAllowedToAct: true, model.EdgeAdminTo: true, model.EdgeCanPSRemote: true,
	model.EdgeExecuteDCOM: true, model.EdgeHasSession: true, model.EdgeMemberOf: true, model.EdgeDCSync: true,
	model.EdgeGetChanges: true, model.EdgeGetChangesAll: true, model.EdgeReadLAPSPassword: true, model.EdgeReadGMSAPassword: true,
	model.EdgeContains: true, model.EdgeGPLink: true, model.EdgeTrustedBy: true,
}

// Validate checks size, referential integrity, and vocabulary.
func Validate(g *model.Graph) error {
	if g == nil {
		return errors.New("ingest: nil graph")
	}
	if len(g.Nodes) > MaxNodes {
		return fmt.Errorf("ingest: too many nodes (%d > %d)", len(g.Nodes), MaxNodes)
	}
	if len(g.Edges) > MaxEdges {
		return fmt.Errorf("ingest: too many edges (%d > %d)", len(g.Edges), MaxEdges)
	}
	ids := make(map[string]struct{}, len(g.Nodes))
	for i, n := range g.Nodes {
		if n.ID == "" {
			return fmt.Errorf("ingest: node[%d] has empty id", i)
		}
		if !knownKinds[n.Kind] {
			return fmt.Errorf("ingest: node %q has unknown kind %q", n.ID, n.Kind)
		}
		ids[n.ID] = struct{}{}
	}
	for i, e := range g.Edges {
		if !knownEdges[e.Kind] {
			return fmt.Errorf("ingest: edge[%d] has unknown kind %q", i, e.Kind)
		}
		if _, ok := ids[e.Source]; !ok {
			return fmt.Errorf("ingest: edge[%d] source %q not in nodes", i, e.Source)
		}
		if _, ok := ids[e.Target]; !ok {
			return fmt.Errorf("ingest: edge[%d] target %q not in nodes", i, e.Target)
		}
	}
	return nil
}

// Decode reads a JSON model.Graph from r, bounded by MaxBytes.
func Decode(r io.Reader) (*model.Graph, error) {
	lr := io.LimitReader(r, MaxBytes+1)
	data, err := io.ReadAll(lr)
	if err != nil {
		return nil, fmt.Errorf("ingest: read: %w", err)
	}
	if len(data) > MaxBytes {
		return nil, fmt.Errorf("ingest: payload exceeds %d bytes", MaxBytes)
	}
	var g model.Graph
	if err := json.Unmarshal(data, &g); err != nil {
		return nil, fmt.Errorf("ingest: decode json: %w", err)
	}
	return &g, nil
}

// Write validates then upserts a graph into the store.
func Write(ctx context.Context, st graph.Store, g *model.Graph) (Result, error) {
	if err := Validate(g); err != nil {
		return Result{}, err
	}
	if err := st.UpsertNodes(ctx, g.Nodes); err != nil {
		return Result{}, fmt.Errorf("ingest: upsert nodes: %w", err)
	}
	if err := st.UpsertEdges(ctx, g.Edges); err != nil {
		return Result{}, fmt.Errorf("ingest: upsert edges: %w", err)
	}
	stats, err := st.Stats(ctx)
	if err != nil {
		return Result{}, fmt.Errorf("ingest: stats: %w", err)
	}
	return Result{Nodes: len(g.Nodes), Edges: len(g.Edges), Stats: stats}, nil
}
