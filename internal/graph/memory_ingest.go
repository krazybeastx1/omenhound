package graph

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/krazybeastx1/omenhound/pkg/model"
)

// This file implements IngestManager on the in-memory store. It owns the
// provenance index (which batch/domain contributed which entity) and the
// scoped-deletion planner that uses it. Every exported method takes the store
// lock, so a preview and a confirmed deletion can never interleave with an
// ingestion.

// ApplyBatch implements IngestManager.
func (m *Memory) ApplyBatch(_ context.Context, batch *IngestBatch, nodes []model.Node, edges []model.Edge) (BatchCounts, error) {
	if batch == nil || strings.TrimSpace(batch.ID) == "" {
		return BatchCounts{}, errors.New("graph: batch requires an id")
	}
	m.mu.Lock()
	defer m.mu.Unlock()

	var c BatchCounts
	for _, n := range nodes {
		if n.ID == "" {
			continue
		}
		if _, exists := m.nodes[n.ID]; exists {
			c.NodesUpdated++
		} else {
			c.NodesCreated++
		}
		m.nodes[n.ID] = n
		if m.nodeProv[n.ID] == nil {
			m.nodeProv[n.ID] = make(map[string]struct{})
		}
		m.nodeProv[n.ID][batch.ID] = struct{}{}
	}
	for _, e := range edges {
		if e.Source == "" || e.Target == "" || e.Kind == "" {
			continue
		}
		k := edgeKey(e)
		if _, exists := m.edges[k]; exists {
			c.EdgesUpdated++
		} else {
			c.EdgesCreated++
		}
		m.putEdgeLocked(e, k)
		if m.edgeProv[k] == nil {
			m.edgeProv[k] = make(map[string]struct{})
		}
		m.edgeProv[k][batch.ID] = struct{}{}
	}

	batch.NodesCreated = c.NodesCreated
	batch.NodesUpdated = c.NodesUpdated
	batch.EdgesCreated = c.EdgesCreated
	batch.EdgesUpdated = c.EdgesUpdated
	if batch.CreatedAt.IsZero() {
		batch.CreatedAt = time.Now().UTC()
	}
	if batch.Status == "" {
		batch.Status = "completed"
	}
	m.batches[batch.ID] = *batch
	return c, nil
}

// putEdgeLocked inserts an edge into the edge map and both adjacency maps.
func (m *Memory) putEdgeLocked(e model.Edge, k string) {
	m.edges[k] = e
	if m.out[e.Source] == nil {
		m.out[e.Source] = make(map[string]model.Edge)
	}
	m.out[e.Source][k] = e
	if m.in[e.Target] == nil {
		m.in[e.Target] = make(map[string]model.Edge)
	}
	m.in[e.Target][k] = e
}

// removeEdgeLocked deletes an edge and its adjacency/provenance entries.
func (m *Memory) removeEdgeLocked(k string) {
	e, ok := m.edges[k]
	if !ok {
		return
	}
	delete(m.edges, k)
	delete(m.out[e.Source], k)
	delete(m.in[e.Target], k)
	delete(m.edgeProv, k)
}

// removeNodeLocked deletes a node, every incident relationship and the node's
// provenance entry.
func (m *Memory) removeNodeLocked(id string) {
	delete(m.nodes, id)
	for k := range m.out[id] {
		m.removeEdgeLocked(k)
	}
	for k := range m.in[id] {
		m.removeEdgeLocked(k)
	}
	delete(m.out, id)
	delete(m.in, id)
	delete(m.nodeProv, id)
}

// ListBatches implements IngestManager (newest first).
func (m *Memory) ListBatches(context.Context) ([]IngestBatch, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]IngestBatch, 0, len(m.batches))
	for _, b := range m.batches {
		out = append(out, b)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].CreatedAt.Equal(out[j].CreatedAt) {
			return out[i].ID > out[j].ID
		}
		return out[i].CreatedAt.After(out[j].CreatedAt)
	})
	return out, nil
}

// GetBatch implements IngestManager.
func (m *Memory) GetBatch(_ context.Context, id string) (IngestBatch, bool, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	b, ok := m.batches[id]
	return b, ok, nil
}

// delPlan is the computed deletion scope for one preview/delete.
type delPlan struct {
	scope       string
	target      string
	deleteNodes map[string]struct{}
	deleteEdges map[string]struct{}
	warnings    []string
}

func (p delPlan) nodeIDs() []string { return sortedKeys(p.deleteNodes) }
func (p delPlan) edgeKeys() []string {
	return sortedKeys(p.deleteEdges)
}

// batchPlanLocked computes which records deleting a batch can safely remove:
// records the batch created that no other batch also touched. Records shared
// with another import are preserved.
func (m *Memory) batchPlanLocked(id string) (delPlan, error) {
	if _, ok := m.batches[id]; !ok {
		return delPlan{}, ErrBatchNotFound
	}
	p := delPlan{scope: "batch", target: id, deleteNodes: map[string]struct{}{}, deleteEdges: map[string]struct{}{}}
	inBatch := func(set map[string]struct{}) bool { _, ok := set[id]; return ok }

	for nodeID, set := range m.nodeProv {
		if !inBatch(set) {
			continue
		}
		if len(set) > 1 {
			continue // shared with another batch -> preserved
		}
		if _, exists := m.nodes[nodeID]; exists {
			p.deleteNodes[nodeID] = struct{}{}
		}
	}
	// Relationships created solely by this batch whose endpoints both survive.
	for ek, set := range m.edgeProv {
		if !inBatch(set) || len(set) > 1 {
			continue
		}
		e, ok := m.edges[ek]
		if !ok {
			continue
		}
		if _, gone := p.deleteNodes[e.Source]; gone {
			continue
		}
		if _, gone := p.deleteNodes[e.Target]; gone {
			continue
		}
		p.deleteEdges[ek] = struct{}{}
	}
	m.absorbIncidentLocked(&p, id)
	return p, nil
}

// domainPlanLocked computes which records deleting one domain can safely remove.
// It deletes nodes whose Domain matches, unless a batch scoped to a *different*
// domain also contributed the node (a shared object). Relationships with a
// deleted endpoint are removed; the rest are preserved.
func (m *Memory) domainPlanLocked(domain string) (delPlan, error) {
	d := strings.TrimSpace(domain)
	if d == "" {
		return delPlan{}, errors.New("graph: domain is required")
	}
	p := delPlan{scope: "domain", target: d, deleteNodes: map[string]struct{}{}, deleteEdges: map[string]struct{}{}}
	found := false
	for id, n := range m.nodes {
		if !strings.EqualFold(strings.TrimSpace(n.Domain), d) {
			continue
		}
		found = true
		shared := false
		for bid := range m.nodeProv[id] {
			if b, ok := m.batches[bid]; ok && b.Domain != "" && !strings.EqualFold(b.Domain, d) {
				shared = true
				break
			}
		}
		if shared {
			continue
		}
		p.deleteNodes[id] = struct{}{}
	}
	if !found {
		for _, b := range m.batches {
			if strings.EqualFold(b.Domain, d) {
				found = true
				break
			}
		}
	}
	if !found {
		return delPlan{}, ErrDomainNotFound
	}
	m.absorbIncidentLocked(&p, "")
	return p, nil
}

// absorbIncidentLocked adds every relationship incident to a to-be-deleted node.
// Some of those relationships may be shared with other imports; because the
// canonical model forbids dangling edges they must be removed anyway, so the
// plan records an honest warning instead of pretending they were preserved.
func (m *Memory) absorbIncidentLocked(p *delPlan, batchID string) {
	forced := 0
	add := func(ek string) {
		if _, done := p.deleteEdges[ek]; done {
			return
		}
		p.deleteEdges[ek] = struct{}{}
		if batchID != "" {
			if set := m.edgeProv[ek]; len(set) > 1 {
				if _, mine := set[batchID]; mine {
					forced++
				}
			}
		}
	}
	for nodeID := range p.deleteNodes {
		for ek := range m.out[nodeID] {
			add(ek)
		}
		for ek := range m.in[nodeID] {
			add(ek)
		}
	}
	if forced > 0 {
		p.warnings = append(p.warnings, fmt.Sprintf("%d relationship(s) were also referenced by other imports but are removed because one endpoint belongs to this scope.", forced))
	}
}

// recordPlan previews deletion of an explicit record selection within a scope.
func (m *Memory) recordPlanLocked(scope, target string, nodeIDs, edgeKeys []string) (delPlan, error) {
	var base delPlan
	var err error
	switch strings.ToLower(scope) {
	case "batch":
		base, err = m.batchPlanLocked(target)
	case "domain":
		base, err = m.domainPlanLocked(target)
	default:
		return delPlan{}, fmt.Errorf("graph: unknown deletion scope %q (want batch or domain)", scope)
	}
	if err != nil {
		return delPlan{}, err
	}
	p := delPlan{scope: "records", target: target, deleteNodes: map[string]struct{}{}, deleteEdges: map[string]struct{}{}}
	for _, id := range nodeIDs {
		if _, ok := base.deleteNodes[id]; ok {
			p.deleteNodes[id] = struct{}{}
		}
	}
	for _, ek := range edgeKeys {
		if _, ok := base.deleteEdges[ek]; ok {
			p.deleteEdges[ek] = struct{}{}
		}
	}
	p.warnings = append(p.warnings, "Only records the backend classifies as solely owned by the scope can be deleted; the rest are skipped.")
	return p, nil
}

// buildPreviewLocked summarises a deletion plan into an operator-facing preview
// (counts, a small sample and a revalidation token).
func (m *Memory) buildPreviewLocked(p delPlan) DeletionPreview {
	prev := DeletionPreview{
		Scope:       p.scope,
		Target:      p.target,
		DeleteNodes: len(p.deleteNodes),
		DeleteEdges: len(p.deleteEdges),
		Warnings:    p.warnings,
	}
	prev.PreserveNodes = len(m.nodes) - prev.DeleteNodes
	prev.PreserveEdges = len(m.edges) - prev.DeleteEdges

	batchScoped := p.scope == "batch" || (p.scope == "records" && m.hasBatchLocked(p.target))
	domainScoped := p.scope == "domain" || (p.scope == "records" && !m.hasBatchLocked(p.target))

	switch {
	case batchScoped:
		for id, set := range m.nodeProv {
			if _, exists := m.nodes[id]; !exists {
				continue
			}
			if _, mine := set[p.target]; mine && len(set) > 1 {
				prev.SharedNodes++
			}
		}
		for ek, set := range m.edgeProv {
			if _, exists := m.edges[ek]; !exists {
				continue
			}
			if _, mine := set[p.target]; mine && len(set) > 1 {
				if _, del := p.deleteEdges[ek]; !del {
					prev.SharedEdges++
				}
			}
		}
	case domainScoped:
		for id, n := range m.nodes {
			d := strings.TrimSpace(n.Domain)
			if d == "" || !strings.EqualFold(d, p.target) {
				prev.OtherDomain++
				continue
			}
			if _, del := p.deleteNodes[id]; del {
				continue
			}
			prev.SharedNodes++ // in-domain but preserved because a foreign batch owns it
		}
		for _, e := range m.edges {
			if _, del := p.deleteEdges[edgeKey(e)]; del {
				continue
			}
			if strings.EqualFold(strings.TrimSpace(nodeDomain(m, e.Source)), p.target) ||
				strings.EqualFold(strings.TrimSpace(nodeDomain(m, e.Target)), p.target) {
				prev.SharedEdges++
			}
		}
	}

	for id := range m.nodes {
		if len(m.nodeProv[id]) == 0 {
			if domainScoped {
				if !strings.EqualFold(strings.TrimSpace(m.nodes[id].Domain), p.target) {
					continue
				}
			}
			prev.LegacyNodes++
		}
	}

	// A small, deterministic sample so the operator can sanity-check the scope.
	const sampleN = 8
	for _, id := range p.nodeIDs() {
		if len(prev.SampleDeleteNodes) >= sampleN {
			break
		}
		if n, ok := m.nodes[id]; ok {
			prev.SampleDeleteNodes = append(prev.SampleDeleteNodes, NodeSummary{ID: n.ID, Kind: string(n.Kind), Name: n.Name, Domain: n.Domain})
		}
	}
	for _, ek := range p.edgeKeys() {
		if len(prev.SampleDeleteEdges) >= sampleN {
			break
		}
		if e, ok := m.edges[ek]; ok {
			prev.SampleDeleteEdges = append(prev.SampleDeleteEdges, EdgeSummary{Source: e.Source, Target: e.Target, Kind: string(e.Kind)})
		}
	}

	if prev.LegacyNodes > 0 {
		prev.Warnings = append(prev.Warnings, fmt.Sprintf("%d record(s) have no ingestion provenance; they are attributed by their stored domain attribute.", prev.LegacyNodes))
	}
	if domainScoped && prev.OtherDomain > 0 {
		prev.Warnings = append(prev.Warnings, "Records belonging to other domains are preserved.")
	}
	prev.Token = planToken(p.scope, p.target, p.nodeIDs(), p.edgeKeys())
	return prev
}

func (m *Memory) hasBatchLocked(id string) bool {
	_, ok := m.batches[id]
	return ok
}

func nodeDomain(m *Memory, id string) string {
	if n, ok := m.nodes[id]; ok {
		return n.Domain
	}
	return ""
}

// PreviewDeleteBatch implements IngestManager.
func (m *Memory) PreviewDeleteBatch(_ context.Context, id string) (DeletionPreview, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	p, err := m.batchPlanLocked(id)
	if err != nil {
		return DeletionPreview{}, err
	}
	prev := m.buildPreviewLocked(p)
	if b, ok := m.batches[id]; ok {
		bb := b
		prev.Batch = &bb
		prev.Domain = b.Domain
	}
	return prev, nil
}

// DeleteBatch implements IngestManager.
func (m *Memory) DeleteBatch(_ context.Context, id, token string) (DeletionResult, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	p, err := m.batchPlanLocked(id)
	if err != nil {
		return DeletionResult{}, err
	}
	if want := planToken(p.scope, p.target, p.nodeIDs(), p.edgeKeys()); token != "" && token != want {
		return DeletionResult{}, ErrStalePreview
	}
	nodeIDs, edgeKeys := p.nodeIDs(), p.edgeKeys()
	for _, ek := range edgeKeys {
		m.removeEdgeLocked(ek)
	}
	for _, id := range nodeIDs {
		m.removeNodeLocked(id)
	}
	delete(m.batches, id)
	return DeletionResult{
		Scope: "batch", Target: id,
		DeletedNodes: len(nodeIDs), DeletedEdges: len(edgeKeys),
		PreservedNodes: len(m.nodes), PreservedEdges: len(m.edges),
		BatchRemoved: true, Warnings: p.warnings,
	}, nil
}

// PreviewDeleteDomain implements IngestManager.
func (m *Memory) PreviewDeleteDomain(_ context.Context, domain string) (DeletionPreview, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	p, err := m.domainPlanLocked(domain)
	if err != nil {
		return DeletionPreview{}, err
	}
	prev := m.buildPreviewLocked(p)
	prev.Domain = p.target
	return prev, nil
}

// DeleteDomain implements IngestManager. Batch history is retained; only the
// records are removed.
func (m *Memory) DeleteDomain(_ context.Context, domain, token string) (DeletionResult, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	p, err := m.domainPlanLocked(domain)
	if err != nil {
		return DeletionResult{}, err
	}
	if want := planToken(p.scope, p.target, p.nodeIDs(), p.edgeKeys()); token != "" && token != want {
		return DeletionResult{}, ErrStalePreview
	}
	nodeIDs, edgeKeys := p.nodeIDs(), p.edgeKeys()
	for _, ek := range edgeKeys {
		m.removeEdgeLocked(ek)
	}
	for _, id := range nodeIDs {
		m.removeNodeLocked(id)
	}
	return DeletionResult{
		Scope: "domain", Target: domain,
		DeletedNodes: len(nodeIDs), DeletedEdges: len(edgeKeys),
		PreservedNodes: len(m.nodes), PreservedEdges: len(m.edges),
		Warnings: p.warnings,
	}, nil
}

// PreviewDeleteRecords implements IngestManager.
func (m *Memory) PreviewDeleteRecords(_ context.Context, scope, target string, nodeIDs, edgeKeys []string) (DeletionPreview, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	p, err := m.recordPlanLocked(scope, target, nodeIDs, edgeKeys)
	if err != nil {
		return DeletionPreview{}, err
	}
	prev := m.buildPreviewLocked(p)
	prev.Scope = "records"
	return prev, nil
}

// DeleteRecords implements IngestManager.
func (m *Memory) DeleteRecords(_ context.Context, scope, target string, nodeIDs, edgeKeys []string, token string) (DeletionResult, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	p, err := m.recordPlanLocked(scope, target, nodeIDs, edgeKeys)
	if err != nil {
		return DeletionResult{}, err
	}
	if want := planToken(p.scope, p.target, p.nodeIDs(), p.edgeKeys()); token != "" && token != want {
		return DeletionResult{}, ErrStalePreview
	}
	nIDs, eKeys := p.nodeIDs(), p.edgeKeys()
	for _, ek := range eKeys {
		m.removeEdgeLocked(ek)
	}
	for _, id := range nIDs {
		m.removeNodeLocked(id)
	}
	return DeletionResult{
		Scope: "records", Target: target,
		DeletedNodes: len(nIDs), DeletedEdges: len(eKeys),
		PreservedNodes: len(m.nodes), PreservedEdges: len(m.edges),
		Warnings: p.warnings,
	}, nil
}

// DomainCounts summarises per-domain node/edge counts for the management view.
func (m *Memory) DomainCounts(_ context.Context) (map[string]Stats, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := map[string]Stats{}
	domainOf := func(id string) string {
		if n, ok := m.nodes[id]; ok {
			return strings.TrimSpace(n.Domain)
		}
		return ""
	}
	for _, n := range m.nodes {
		d := strings.TrimSpace(n.Domain)
		if d == "" {
			continue
		}
		s := out[d]
		s.Nodes++
		out[d] = s
	}
	for _, e := range m.edges {
		ds := domainOf(e.Source)
		if ds == "" || !strings.EqualFold(ds, domainOf(e.Target)) {
			continue
		}
		s := out[ds]
		s.Edges++
		out[ds] = s
	}
	return out, nil
}
