package graph

import (
	"context"
	"testing"

	"github.com/krazybeastx1/omenhound/pkg/model"
)

func TestMemoryGetNode(t *testing.T) {
	ctx := context.Background()
	m := NewMemory()
	_ = m.UpsertNodes(ctx, []model.Node{{ID: "A", Kind: model.KindUser, Name: "alice"}})

	n, ok, err := m.GetNode(ctx, "A")
	if err != nil || !ok || n.Name != "alice" {
		t.Fatalf("GetNode = %+v ok=%v err=%v", n, ok, err)
	}
	if _, ok, _ := m.GetNode(ctx, "MISSING"); ok {
		t.Fatal("expected absent node to report ok=false")
	}
}

// TestAdjacencyClearedOnDeleteNode guards the O(degree) adjacency index: after
// deleting a node, no dangling edge may remain in the reverse/forward index.
func TestAdjacencyClearedOnDeleteNode(t *testing.T) {
	ctx := context.Background()
	m := NewMemory()
	_ = m.UpsertNodes(ctx, []model.Node{
		{ID: "A", Kind: model.KindUser}, {ID: "B", Kind: model.KindGroup},
		{ID: "C", Kind: model.KindGroup}, {ID: "D", Kind: model.KindUser},
	})
	_ = m.UpsertEdges(ctx, []model.Edge{
		{Source: "A", Target: "B", Kind: model.EdgeMemberOf},
		{Source: "A", Target: "C", Kind: model.EdgeGenericAll},
		{Source: "D", Target: "A", Kind: model.EdgeAdminTo},
	})

	if err := m.DeleteNode(ctx, "A"); err != nil {
		t.Fatal(err)
	}
	if out, _ := m.Neighbors(ctx, "A"); len(out) != 0 {
		t.Fatalf("Neighbors(A) = %+v, want none", out)
	}
	if in, _ := m.Incoming(ctx, "A"); len(in) != 0 {
		t.Fatalf("Incoming(A) = %+v, want none", in)
	}
	// B and C must no longer see the removed inbound edge either.
	if in, _ := m.Incoming(ctx, "B"); len(in) != 0 {
		t.Fatalf("Incoming(B) = %+v, want none after source deleted", in)
	}
	if out, _ := m.Neighbors(ctx, "D"); len(out) != 0 {
		t.Fatalf("Neighbors(D) = %+v, want none after target deleted", out)
	}
	st, _ := m.Stats(ctx)
	if st.Nodes != 3 || st.Edges != 0 {
		t.Fatalf("stats = %+v, want 3/0", st)
	}
}

func TestDeleteEdgeUpdatesAdjacency(t *testing.T) {
	ctx := context.Background()
	m := NewMemory()
	_ = m.UpsertNodes(ctx, []model.Node{{ID: "A", Kind: model.KindUser}, {ID: "B", Kind: model.KindGroup}})
	_ = m.UpsertEdges(ctx, []model.Edge{{Source: "A", Target: "B", Kind: model.EdgeMemberOf}})

	if err := m.DeleteEdge(ctx, "A", "B", model.EdgeMemberOf); err != nil {
		t.Fatal(err)
	}
	if out, _ := m.Neighbors(ctx, "A"); len(out) != 0 {
		t.Fatalf("Neighbors(A) = %+v after DeleteEdge", out)
	}
	if in, _ := m.Incoming(ctx, "B"); len(in) != 0 {
		t.Fatalf("Incoming(B) = %+v after DeleteEdge", in)
	}
}
