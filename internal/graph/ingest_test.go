package graph

import (
	"context"
	"errors"
	"testing"

	"github.com/krazybeastx1/omenhound/pkg/model"
)

func node(id, domain string) model.Node {
	return model.Node{ID: id, Kind: model.KindUser, Name: id, Domain: domain}
}

func edge(src, dst string, k model.EdgeKind) model.Edge {
	return model.Edge{Source: src, Target: dst, Kind: k}
}

func mkBatch(id, domain string) *IngestBatch {
	return &IngestBatch{ID: id, Source: id + ".json", Mode: "merge", Domain: domain, Status: "completed"}
}

func statsOrFail(t *testing.T, m *Memory) Stats {
	t.Helper()
	s, err := m.Stats(context.Background())
	if err != nil {
		t.Fatalf("stats: %v", err)
	}
	return s
}

func TestApplyBatchCountsCreatedAndUpdated(t *testing.T) {
	ctx := context.Background()
	m := NewMemory()
	c, err := m.ApplyBatch(ctx, mkBatch("b1", "corp.local"),
		[]model.Node{node("u1", "corp.local"), node("u2", "corp.local")},
		[]model.Edge{edge("u1", "u2", model.EdgeMemberOf)})
	if err != nil {
		t.Fatalf("apply: %v", err)
	}
	if c.NodesCreated != 2 || c.EdgesCreated != 1 || c.NodesUpdated != 0 {
		t.Fatalf("unexpected counts %+v", c)
	}
	// Re-applying updates the same canonical entities, it does not duplicate.
	c2, err := m.ApplyBatch(ctx, mkBatch("b2", "corp.local"),
		[]model.Node{node("u1", "corp.local")}, nil)
	if err != nil {
		t.Fatalf("apply2: %v", err)
	}
	if c2.NodesUpdated != 1 || c2.NodesCreated != 0 {
		t.Fatalf("expected update, got %+v", c2)
	}
	if s := statsOrFail(t, m); s.Nodes != 2 || s.Edges != 1 {
		t.Fatalf("unexpected stats %+v", s)
	}
}

func TestDeleteBatchRemovesSoleOwnedAndPreservesShared(t *testing.T) {
	ctx := context.Background()
	m := NewMemory()
	// b1 creates u1,u2 and the edge. b2 also touches u2 (shared) and adds u3.
	if _, err := m.ApplyBatch(ctx, mkBatch("b1", "corp.local"),
		[]model.Node{node("u1", "corp.local"), node("u2", "corp.local")},
		[]model.Edge{edge("u1", "u2", model.EdgeMemberOf)}); err != nil {
		t.Fatal(err)
	}
	if _, err := m.ApplyBatch(ctx, mkBatch("b2", "corp.local"),
		[]model.Node{node("u2", "corp.local"), node("u3", "corp.local")}, nil); err != nil {
		t.Fatal(err)
	}

	prev, err := m.PreviewDeleteBatch(ctx, "b1")
	if err != nil {
		t.Fatalf("preview: %v", err)
	}
	if prev.DeleteNodes != 1 { // only u1 is solely owned by b1
		t.Fatalf("expected 1 deletable node, got %d (%+v)", prev.DeleteNodes, prev)
	}
	if prev.SharedNodes != 1 { // u2 shared with b2
		t.Fatalf("expected 1 shared node, got %d", prev.SharedNodes)
	}
	if prev.Token == "" {
		t.Fatal("expected a revalidation token")
	}

	res, err := m.DeleteBatch(ctx, "b1", prev.Token)
	if err != nil {
		t.Fatalf("delete: %v", err)
	}
	if res.DeletedNodes != 1 {
		t.Fatalf("expected 1 deleted node, got %d", res.DeletedNodes)
	}
	// u2 and u3 survive; the u1-u2 edge is gone with u1.
	if s := statsOrFail(t, m); s.Nodes != 2 || s.Edges != 0 {
		t.Fatalf("unexpected stats after delete %+v", s)
	}
	if _, ok, _ := m.GetNode(ctx, "u2"); !ok {
		t.Fatal("shared node u2 must be preserved")
	}
	if _, ok, _ := m.GetBatch(ctx, "b1"); ok {
		t.Fatal("batch b1 should be removed from history")
	}
}

func TestDeleteBatchRejectsStaleToken(t *testing.T) {
	ctx := context.Background()
	m := NewMemory()
	if _, err := m.ApplyBatch(ctx, mkBatch("b1", "corp.local"), []model.Node{node("u1", "corp.local")}, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := m.DeleteBatch(ctx, "b1", "deadbeef"); !errors.Is(err, ErrStalePreview) {
		t.Fatalf("expected ErrStalePreview, got %v", err)
	}
	if s := statsOrFail(t, m); s.Nodes != 1 {
		t.Fatalf("stale delete must not mutate the store, got %+v", s)
	}
}

func TestDeleteBatchUnknown(t *testing.T) {
	m := NewMemory()
	if _, err := m.PreviewDeleteBatch(context.Background(), "nope"); !errors.Is(err, ErrBatchNotFound) {
		t.Fatalf("expected ErrBatchNotFound, got %v", err)
	}
}

func TestDeleteDomainPreservesOtherDomains(t *testing.T) {
	ctx := context.Background()
	m := NewMemory()
	if _, err := m.ApplyBatch(ctx, mkBatch("b-corp", "corp.local"),
		[]model.Node{node("u1", "corp.local"), node("u2", "corp.local")},
		[]model.Edge{edge("u1", "u2", model.EdgeMemberOf)}); err != nil {
		t.Fatal(err)
	}
	if _, err := m.ApplyBatch(ctx, mkBatch("b-eng", "eng.local"),
		[]model.Node{node("e1", "eng.local"), node("e2", "eng.local")},
		[]model.Edge{edge("e1", "e2", model.EdgeMemberOf)}); err != nil {
		t.Fatal(err)
	}

	prev, err := m.PreviewDeleteDomain(ctx, "corp.local")
	if err != nil {
		t.Fatalf("preview: %v", err)
	}
	if prev.DeleteNodes != 2 || prev.DeleteEdges != 1 {
		t.Fatalf("expected 2 nodes / 1 edge, got %+v", prev)
	}
	if prev.OtherDomain != 2 {
		t.Fatalf("expected 2 other-domain preserved, got %d", prev.OtherDomain)
	}

	res, err := m.DeleteDomain(ctx, "corp.local", prev.Token)
	if err != nil {
		t.Fatalf("delete: %v", err)
	}
	if res.DeletedNodes != 2 || res.DeletedEdges != 1 {
		t.Fatalf("unexpected result %+v", res)
	}
	// eng.local is untouched.
	if s := statsOrFail(t, m); s.Nodes != 2 || s.Edges != 1 {
		t.Fatalf("eng.local should be intact, got %+v", s)
	}
	domains, _ := m.Domains(ctx)
	if len(domains) != 1 || domains[0] != "eng.local" {
		t.Fatalf("expected only eng.local, got %v", domains)
	}
}

func TestDeleteDomainSharedNodePreserved(t *testing.T) {
	ctx := context.Background()
	m := NewMemory()
	// A multi-domain batch contributes u1 (corp) and e1 (eng). A foreign-scoped
	// batch (eng) also touches the corp node: a deliberate cross-domain object.
	if _, err := m.ApplyBatch(ctx, mkBatch("multi", ""),
		[]model.Node{node("u1", "corp.local"), node("e1", "eng.local")}, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := m.ApplyBatch(ctx, mkBatch("eng-only", "eng.local"),
		[]model.Node{node("u1", "corp.local")}, nil); err != nil {
		t.Fatal(err)
	}
	prev, err := m.PreviewDeleteDomain(ctx, "corp.local")
	if err != nil {
		t.Fatalf("preview: %v", err)
	}
	if prev.DeleteNodes != 0 || prev.SharedNodes != 1 {
		t.Fatalf("shared corp node must be preserved: %+v", prev)
	}
	if _, err := m.DeleteDomain(ctx, "corp.local", prev.Token); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if _, ok, _ := m.GetNode(ctx, "u1"); !ok {
		t.Fatal("shared node must survive domain deletion")
	}
}

func TestDeleteDomainUnknown(t *testing.T) {
	m := NewMemory()
	if _, err := m.PreviewDeleteDomain(context.Background(), "ghost.local"); !errors.Is(err, ErrDomainNotFound) {
		t.Fatalf("expected ErrDomainNotFound, got %v", err)
	}
}

func TestLegacyRecordsPreservedOnBatchDelete(t *testing.T) {
	ctx := context.Background()
	m := NewMemory()
	// Legacy rows written directly (no provenance), as pre-migration data would be.
	if err := m.UpsertNodes(ctx, []model.Node{node("old1", "corp.local")}); err != nil {
		t.Fatal(err)
	}
	if _, err := m.ApplyBatch(ctx, mkBatch("b1", "corp.local"), []model.Node{node("u1", "corp.local")}, nil); err != nil {
		t.Fatal(err)
	}
	prev, err := m.PreviewDeleteBatch(ctx, "b1")
	if err != nil {
		t.Fatal(err)
	}
	if prev.LegacyNodes != 1 {
		t.Fatalf("expected 1 legacy node reported, got %d", prev.LegacyNodes)
	}
	if _, err := m.DeleteBatch(ctx, "b1", prev.Token); err != nil {
		t.Fatal(err)
	}
	if _, ok, _ := m.GetNode(ctx, "old1"); !ok {
		t.Fatal("legacy record must be preserved on batch deletion")
	}
}

func TestDeleteRecordsSubsetRespectsScope(t *testing.T) {
	ctx := context.Background()
	m := NewMemory()
	if _, err := m.ApplyBatch(ctx, mkBatch("b1", "corp.local"),
		[]model.Node{node("u1", "corp.local"), node("u2", "corp.local")}, nil); err != nil {
		t.Fatal(err)
	}
	// Only u1 is inside b1's plan; u2 is also solely owned by b1.
	prev, err := m.PreviewDeleteRecords(ctx, "batch", "b1", []string{"u1", "u2"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if prev.DeleteNodes != 2 {
		t.Fatalf("both nodes belong to b1, got %d", prev.DeleteNodes)
	}
	// The token commits to a specific selection, so preview the exact subset.
	sub, err := m.PreviewDeleteRecords(ctx, "batch", "b1", []string{"u1"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	res, err := m.DeleteRecords(ctx, "batch", "b1", []string{"u1"}, nil, sub.Token)
	if err != nil {
		t.Fatalf("delete records: %v", err)
	}
	if res.DeletedNodes != 1 {
		t.Fatalf("expected 1 deleted, got %+v", res)
	}
	if _, ok, _ := m.GetNode(ctx, "u2"); !ok {
		t.Fatal("u2 must survive a subset deletion")
	}
}

func TestClearResetsProvenance(t *testing.T) {
	ctx := context.Background()
	m := NewMemory()
	if _, err := m.ApplyBatch(ctx, mkBatch("b1", "corp.local"), []model.Node{node("u1", "corp.local")}, nil); err != nil {
		t.Fatal(err)
	}
	if err := m.Clear(ctx); err != nil {
		t.Fatal(err)
	}
	batches, _ := m.ListBatches(ctx)
	if len(batches) != 0 {
		t.Fatalf("expected batches cleared, got %v", batches)
	}
	if s := statsOrFail(t, m); s.Nodes != 0 {
		t.Fatalf("expected empty store, got %+v", s)
	}
	if np, _ := m.NodeProvenance(ctx); len(np) != 0 {
		t.Fatalf("expected node provenance cleared, got %v", np)
	}
	if ep, _ := m.EdgeProvenance(ctx); len(ep) != 0 {
		t.Fatalf("expected edge provenance cleared, got %v", ep)
	}
}

func TestProvenanceAttributesSourcesPerEntity(t *testing.T) {
	ctx := context.Background()
	m := NewMemory()
	// Two datasets of the same domain: one native collect ("ldap"), one
	// imported BloodHound dataset ("bloodhound-import"). They share u1.
	b1 := &IngestBatch{ID: "b1", Source: "ldap", Mode: "merge", Domain: "corp.local", Status: "completed"}
	b2 := &IngestBatch{ID: "b2", Source: "bloodhound-import", Mode: "merge", Domain: "corp.local", Status: "completed"}
	if _, err := m.ApplyBatch(ctx, b1,
		[]model.Node{node("u1", "corp.local"), node("u2", "corp.local")},
		[]model.Edge{edge("u1", "u2", model.EdgeMemberOf)}); err != nil {
		t.Fatal(err)
	}
	if _, err := m.ApplyBatch(ctx, b2,
		[]model.Node{node("u1", "corp.local"), node("u3", "corp.local")},
		[]model.Edge{edge("u1", "u3", model.EdgeGenericAll)}); err != nil {
		t.Fatal(err)
	}

	np, err := m.NodeProvenance(ctx)
	if err != nil {
		t.Fatal(err)
	}
	// u1 is shared: both sources, both batches.
	if got := np["u1"].Sources; len(got) != 2 || got[0] != "bloodhound-import" || got[1] != "ldap" {
		t.Fatalf("u1 sources = %v, want [bloodhound-import ldap]", got)
	}
	if got := np["u1"].Batches; len(got) != 2 || got[0] != "b1" || got[1] != "b2" {
		t.Fatalf("u1 batches = %v, want [b1 b2]", got)
	}
	// u2 is solely from the native collect.
	if got := np["u2"].Sources; len(got) != 1 || got[0] != "ldap" {
		t.Fatalf("u2 sources = %v, want [ldap]", got)
	}

	ep, err := m.EdgeProvenance(ctx)
	if err != nil {
		t.Fatal(err)
	}
	key := PublicEdgeKey(edge("u1", "u2", model.EdgeMemberOf))
	want := "u1|MemberOf|u2"
	if key != want {
		t.Fatalf("PublicEdgeKey = %q, want %q", key, want)
	}
	if got := ep[want].Sources; len(got) != 1 || got[0] != "ldap" {
		t.Fatalf("edge sources = %v, want [ldap]", got)
	}
}
