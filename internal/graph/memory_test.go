package graph

import (
	"context"
	"testing"

	"github.com/krazybeastx1/omenhound/pkg/model"
)

func TestMemoryCRUD(t *testing.T) {
	ctx := context.Background()
	m := NewMemory()
	nodes := []model.Node{
		{ID: "A", Kind: model.KindUser, Name: "alice"},
		{ID: "B", Kind: model.KindGroup, Name: "Admins"},
	}
	if err := m.UpsertNodes(ctx, nodes); err != nil {
		t.Fatal(err)
	}
	if err := m.UpsertEdges(ctx, []model.Edge{{Source: "A", Target: "B", Kind: model.EdgeMemberOf}}); err != nil {
		t.Fatal(err)
	}
	// dedupe
	if err := m.UpsertEdges(ctx, []model.Edge{{Source: "A", Target: "B", Kind: model.EdgeMemberOf}}); err != nil {
		t.Fatal(err)
	}

	st, _ := m.Stats(ctx)
	if st.Nodes != 2 || st.Edges != 1 {
		t.Fatalf("stats = %+v, want 2/1", st)
	}

	out, _ := m.Neighbors(ctx, "A")
	if len(out) != 1 || out[0].Target != "B" {
		t.Fatalf("neighbors(A) = %+v", out)
	}
	in, _ := m.Incoming(ctx, "B")
	if len(in) != 1 || in[0].Source != "A" {
		t.Fatalf("incoming(B) = %+v", in)
	}

	if err := m.DeleteNode(ctx, "A"); err != nil {
		t.Fatal(err)
	}
	st, _ = m.Stats(ctx)
	if st.Nodes != 1 || st.Edges != 0 {
		t.Fatalf("after delete stats = %+v, want 1/0", st)
	}
}

func TestMemoryDeleteEdge(t *testing.T) {
	ctx := context.Background()
	m := NewMemory()
	_ = m.UpsertNodes(ctx, []model.Node{{ID: "A", Kind: model.KindUser}, {ID: "B", Kind: model.KindGroup}})
	_ = m.UpsertEdges(ctx, []model.Edge{{Source: "A", Target: "B", Kind: model.EdgeMemberOf}})
	if err := m.DeleteEdge(ctx, "A", "B", model.EdgeMemberOf); err != nil {
		t.Fatal(err)
	}
	st, _ := m.Stats(ctx)
	if st.Edges != 0 {
		t.Fatalf("edges = %d, want 0", st.Edges)
	}
}
