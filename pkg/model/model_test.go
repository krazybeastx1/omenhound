package model

import "testing"

func TestGraphAddNodeUpsertsInPlace(t *testing.T) {
	var g Graph
	g.AddNode(Node{ID: "A", Kind: KindUser, Name: "first"})
	g.AddNode(Node{ID: "A", Kind: KindUser, Name: "second"})
	if len(g.Nodes) != 1 {
		t.Fatalf("expected 1 node, got %d", len(g.Nodes))
	}
	if g.Nodes[0].Name != "second" {
		t.Fatalf("re-add should update in place, got %q", g.Nodes[0].Name)
	}
}

func TestGraphAddEdgeDeduplicates(t *testing.T) {
	var g Graph
	g.AddNode(Node{ID: "A"})
	g.AddNode(Node{ID: "B"})
	g.AddEdge(Edge{Source: "A", Target: "B", Kind: EdgeMemberOf})
	g.AddEdge(Edge{Source: "A", Target: "B", Kind: EdgeMemberOf})
	g.AddEdge(Edge{Source: "A", Target: "B", Kind: EdgeGenericAll}) // different kind is distinct
	if len(g.Edges) != 2 {
		t.Fatalf("expected 2 edges, got %d", len(g.Edges))
	}
}

// TestGraphIndexRebuiltLazily ensures a Graph whose slices were populated
// directly (e.g. from JSON) still dedupes correctly once AddNode/AddEdge run.
func TestGraphIndexRebuiltLazily(t *testing.T) {
	g := &Graph{Nodes: []Node{{ID: "X", Name: "preset"}}}
	g.AddNode(Node{ID: "X", Name: "updated"})
	if len(g.Nodes) != 1 || g.Nodes[0].Name != "updated" {
		t.Fatalf("lazy index failed: %+v", g.Nodes)
	}

	g2 := &Graph{Edges: []Edge{{Source: "A", Target: "B", Kind: EdgeMemberOf}}}
	g2.AddEdge(Edge{Source: "A", Target: "B", Kind: EdgeMemberOf})
	if len(g2.Edges) != 1 {
		t.Fatalf("lazy edge index failed: %+v", g2.Edges)
	}
}

func TestNodeIndex(t *testing.T) {
	g := &Graph{Nodes: []Node{{ID: "A", Name: "a"}, {ID: "B", Name: "b"}}}
	idx := g.NodeIndex()
	if len(idx) != 2 || idx["B"].Name != "b" {
		t.Fatalf("NodeIndex = %+v", idx)
	}
}
