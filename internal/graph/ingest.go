package graph

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"sort"
	"strings"
	"time"

	"github.com/krazybeastx1/omenhound/pkg/model"
)

// Ingestion provenance is kept *outside* the canonical node/edge model. A node
// or edge may be contributed by several ingestion batches, and a batch may span
// several domains; the provenance index records, for every entity, which batches
// have touched it. That is what lets a batch or domain deletion remove only the
// records it is safe to remove and preserve everything else.
//
// The canonical identity of an AD object stays its ID (SID/objectGUID). A batch
// is never a substitute for identity: two batches that update the same SID touch
// the same canonical node.

var (
	// ErrBatchNotFound is returned when a batch id is unknown.
	ErrBatchNotFound = errors.New("graph: ingestion batch not found")
	// ErrDomainNotFound is returned when a domain has no stored nodes or batches.
	ErrDomainNotFound = errors.New("graph: domain not found")
	// ErrStalePreview is returned when the graph changed between a deletion
	// preview and the confirmed deletion.
	ErrStalePreview = errors.New("graph: the deletion preview is stale; reload the preview and confirm again")
)

// IngestScope is the domain constraint applied to one ingestion.
type IngestScope struct {
	// Domain is the selected domain. Empty means "every domain present in the
	// uploaded file" (the historical, unscoped behaviour).
	Domain string `json:"domain"`
	// StampUnknown assigns Domain to entities that carry no domain of their own.
	StampUnknown bool `json:"stamp_unknown"`
	// OnMismatch is "reject" (default) or "skip": what to do with entities that
	// belong to a different domain than the selected one.
	OnMismatch string `json:"on_mismatch"`
}

// IngestBatch records one import and its outcome.
type IngestBatch struct {
	ID        string    `json:"id"`
	Source    string    `json:"source"`
	Mode      string    `json:"mode"`
	Domain    string    `json:"domain"`
	Domains   []string  `json:"domains"`
	Status    string    `json:"status"` // completed | partial | failed
	CreatedAt time.Time `json:"created_at"`

	NodesCreated  int `json:"nodes_created"`
	NodesUpdated  int `json:"nodes_updated"`
	EdgesCreated  int `json:"edges_created"`
	EdgesUpdated  int `json:"edges_updated"`
	NodesSkipped  int `json:"nodes_skipped"`
	EdgesSkipped  int `json:"edges_skipped"`
	MismatchNodes int `json:"mismatch_nodes"`

	Errors []string `json:"errors,omitempty"`
}

// BatchCounts is the created/updated split for one applied batch.
type BatchCounts struct {
	NodesCreated int
	NodesUpdated int
	EdgesCreated int
	EdgesUpdated int
}

// NodeSummary / EdgeSummary are lightweight preview rows.
type NodeSummary struct {
	ID     string `json:"id"`
	Kind   string `json:"kind"`
	Name   string `json:"name"`
	Domain string `json:"domain,omitempty"`
}

// EdgeSummary is a lightweight relationship preview row.
type EdgeSummary struct {
	Source string `json:"source"`
	Target string `json:"target"`
	Kind   string `json:"kind"`
}

// DeletionPreview is the server-computed impact of a scoped deletion. The
// frontend shows it and echoes Token back so the delete endpoint can revalidate
// that the graph has not changed underneath the operator.
type DeletionPreview struct {
	Scope  string       `json:"scope"`  // "batch" | "domain" | "records"
	Target string       `json:"target"` // batch id or domain
	Batch  *IngestBatch `json:"batch,omitempty"`
	Domain string       `json:"domain,omitempty"`

	DeleteNodes   int `json:"delete_nodes"`
	DeleteEdges   int `json:"delete_edges"`
	PreserveNodes int `json:"preserved_nodes"`
	PreserveEdges int `json:"preserved_edges"`
	SharedNodes   int `json:"shared_nodes"`
	SharedEdges   int `json:"shared_edges"`
	LegacyNodes   int `json:"legacy_nodes"`
	OtherDomain   int `json:"other_domain_nodes"`

	SampleDeleteNodes []NodeSummary `json:"sample_delete_nodes,omitempty"`
	SampleDeleteEdges []EdgeSummary `json:"sample_delete_edges,omitempty"`
	Warnings          []string      `json:"warnings,omitempty"`

	Token string `json:"token"`
}

// DeletionResult reports exactly what a confirmed deletion removed.
type DeletionResult struct {
	Scope          string   `json:"scope"`
	Target         string   `json:"target"`
	DeletedNodes   int      `json:"deleted_nodes"`
	DeletedEdges   int      `json:"deleted_edges"`
	PreservedNodes int      `json:"preserved_nodes"`
	PreservedEdges int      `json:"preserved_edges"`
	BatchRemoved   bool     `json:"batch_removed"`
	Warnings       []string `json:"warnings,omitempty"`
}

// IngestManager is the optional persistence contract for batch provenance and
// scoped deletion. Stores that do not implement it still support plain
// ingestion; the API reports that provenance is unavailable rather than
// pretending a deletion is reversible.
type IngestManager interface {
	// ApplyBatch upserts nodes/edges and records them against batch. It fills
	// the created/updated counters on the batch and stores the batch metadata.
	ApplyBatch(ctx context.Context, batch *IngestBatch, nodes []model.Node, edges []model.Edge) (BatchCounts, error)
	// ListBatches returns batches, newest first.
	ListBatches(ctx context.Context) ([]IngestBatch, error)
	// GetBatch returns one batch by id.
	GetBatch(ctx context.Context, id string) (IngestBatch, bool, error)

	// PreviewDeleteBatch computes what deleting a batch would remove.
	PreviewDeleteBatch(ctx context.Context, id string) (DeletionPreview, error)
	// DeleteBatch removes the records attributable solely to a batch. token must
	// match the preview's token or ErrStalePreview is returned.
	DeleteBatch(ctx context.Context, id, token string) (DeletionResult, error)

	// PreviewDeleteDomain computes what deleting a domain's imported data removes.
	PreviewDeleteDomain(ctx context.Context, domain string) (DeletionPreview, error)
	// DeleteDomain removes a domain's imported data, preserving shared records.
	DeleteDomain(ctx context.Context, domain, token string) (DeletionResult, error)

	// PreviewDeleteRecords computes the deletable subset of the given records
	// within a batch/domain scope.
	PreviewDeleteRecords(ctx context.Context, scope, target string, nodeIDs, edgeKeys []string) (DeletionPreview, error)
	// DeleteRecords removes the deletable subset of the given records.
	DeleteRecords(ctx context.Context, scope, target string, nodeIDs, edgeKeys []string, token string) (DeletionResult, error)
}

// DomainCounter is implemented by stores that can summarise per-domain node and
// edge counts for the ingestion-management view.
type DomainCounter interface {
	DomainCounts(ctx context.Context) (map[string]Stats, error)
}

// EntityProvenance attributes one node or edge to the ingestion sources and
// batches that contributed it. Sources are the collector labels recorded on an
// ingestion batch (e.g. "ldap" for a native OmenHound collect, "bloodhound-import"
// for an imported BloodHound dataset); Batches are the opaque batch ids. Both
// slices are sorted and deduplicated.
type EntityProvenance struct {
	Sources []string `json:"sources,omitempty"`
	Batches []string `json:"batches,omitempty"`
}

// Provenance is implemented by stores that can attribute each entity to the
// ingestion source(s) that contributed it. It lets the API and the UI separate
// datasets that share SIDs — for example a native OmenHound collect and an
// imported BloodHound collection of the same domain, which merge by identity.
type Provenance interface {
	// NodeProvenance returns node ID -> contributing sources/batches.
	NodeProvenance(ctx context.Context) (map[string]EntityProvenance, error)
	// EdgeProvenance returns "source|kind|target" -> contributing sources/batches.
	EdgeProvenance(ctx context.Context) (map[string]EntityProvenance, error)
}

// PublicEdgeKey is the documented, UI-facing edge key "source|kind|target". It
// matches the frontend's edgeKey() helper and is the key format returned by
// Provenance.EdgeProvenance. Neither a SID nor an edge kind contains "|".
func PublicEdgeKey(e model.Edge) string {
	return e.Source + "|" + string(e.Kind) + "|" + e.Target
}

// planToken fingerprints a deletion scope so a confirmed deletion can prove the
// graph has not changed since the preview was generated.
func planToken(scope, target string, nodes, edges []string) string {
	h := sha256.New()
	h.Write([]byte(scope))
	h.Write([]byte{0})
	h.Write([]byte(strings.ToLower(target)))
	h.Write([]byte{0})
	for _, id := range nodes {
		h.Write([]byte(id))
		h.Write([]byte{0})
	}
	h.Write([]byte{1})
	for _, k := range edges {
		h.Write([]byte(k))
		h.Write([]byte{0})
	}
	return hex.EncodeToString(h.Sum(nil))[:32]
}

func sortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
