// Package ingest validates a collected graph and writes it to a graph Store.
package ingest

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"

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
	model.KindBase: true,
}

var knownEdges = map[model.EdgeKind]bool{
	model.EdgeGenericAll: true, model.EdgeGenericWrite: true, model.EdgeWriteDacl: true, model.EdgeWriteOwner: true,
	model.EdgeForceChangePassword: true, model.EdgeAddMember: true, model.EdgeAddSelf: true, model.EdgeOwns: true,
	model.EdgeAllowedToDelegate: true, model.EdgeAllowedToAct: true, model.EdgeAdminTo: true, model.EdgeCanPSRemote: true,
	model.EdgeExecuteDCOM: true, model.EdgeHasSession: true, model.EdgeMemberOf: true, model.EdgeDCSync: true,
	model.EdgeGetChanges: true, model.EdgeGetChangesAll: true, model.EdgeReadLAPSPassword: true, model.EdgeReadGMSAPassword: true,
	model.EdgeContains: true, model.EdgeGPLink: true, model.EdgeTrustedBy: true,
	model.EdgeCanRDP: true, model.EdgeAllExtendedRights: true, model.EdgeAddKeyCredentialLink: true,
	model.EdgeAddAllowedToAct: true, model.EdgeWriteSPN: true, model.EdgeWriteAccountRestrictions: true,
	model.EdgeWriteGPLink: true, model.EdgeGetChangesInFilteredSet: true,
	model.EdgeWriteAltSecurityIdentities: true, model.EdgeDumpSMSAPassword: true,
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

// Decode reads a JSON model.Graph from r, bounded by MaxBytes. Unknown fields
// are tolerated so third-party/BloodHound-derived payloads import cleanly.
func Decode(r io.Reader) (*model.Graph, error) { return decode(r, false) }

// DecodeStrict is like Decode but rejects unknown JSON fields. Use it for
// untrusted HTTP bodies, where extra fields usually signal a malformed client.
func DecodeStrict(r io.Reader) (*model.Graph, error) { return decode(r, true) }

func decode(r io.Reader, strict bool) (*model.Graph, error) {
	data, err := io.ReadAll(io.LimitReader(r, MaxBytes+1))
	if err != nil {
		return nil, fmt.Errorf("ingest: read: %w", err)
	}
	if len(data) > MaxBytes {
		return nil, fmt.Errorf("ingest: payload exceeds %d bytes", MaxBytes)
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	if strict {
		dec.DisallowUnknownFields()
	}
	var g model.Graph
	if err := dec.Decode(&g); err != nil {
		return nil, fmt.Errorf("ingest: decode json: %w", err)
	}
	if dec.More() {
		return nil, errors.New("ingest: trailing data after JSON object")
	}
	return &g, nil
}

// Mode controls how an ingestion combines with data already in the store.
type Mode string

const (
	// ModeMerge upserts the incoming graph into whatever is already there.
	// It is the default and preserves the historical behaviour.
	ModeMerge Mode = "merge"
	// ModeReplace clears the store first, so the server ends up holding only
	// the newly ingested graph. This is what "focus on one ingestion" means.
	ModeReplace Mode = "replace"
)

// ParseMode maps a request value onto a Mode. An empty value means merge.
// Unknown values are rejected rather than coerced, so a typo can never trigger
// the destructive replace path by accident.
func ParseMode(s string) (Mode, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "", string(ModeMerge):
		return ModeMerge, nil
	case string(ModeReplace):
		return ModeReplace, nil
	default:
		return "", fmt.Errorf("ingest: unknown mode %q (want merge or replace)", s)
	}
}

// Write validates then upserts a graph into the store (merge mode).
func Write(ctx context.Context, st graph.Store, g *model.Graph) (Result, error) {
	return WriteMode(ctx, st, g, ModeMerge)
}

// WriteMode validates then writes a graph into the store under the given mode.
//
// Validation happens before any mutation, so a malformed payload never clears
// existing data. In replace mode Clear runs first; if the subsequent write
// fails the store is left empty rather than half-written — the caller sees the
// error and can re-ingest, and nothing is silently merged.
func WriteMode(ctx context.Context, st graph.Store, g *model.Graph, mode Mode) (Result, error) {
	if mode == "" {
		mode = ModeMerge
	}
	if err := Validate(g); err != nil {
		return Result{}, err
	}
	if mode == ModeReplace {
		if err := st.Clear(ctx); err != nil {
			return Result{}, fmt.Errorf("ingest: clear: %w", err)
		}
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
