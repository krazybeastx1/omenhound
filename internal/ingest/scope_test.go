package ingest

import (
	"context"
	"strings"
	"testing"

	"github.com/krazybeastx1/omenhound/internal/graph"
	"github.com/krazybeastx1/omenhound/pkg/model"
)

func user(id, domain string) model.Node {
	return model.Node{ID: id, Kind: model.KindUser, Name: id, Domain: domain}
}

func graphOf(nodes []model.Node, edges []model.Edge) *model.Graph {
	return &model.Graph{Nodes: nodes, Edges: edges}
}

func TestPlanScopedUnscopedKeepsEverything(t *testing.T) {
	g := graphOf(
		[]model.Node{user("a", "corp.local"), user("b", "eng.local")},
		[]model.Edge{{Source: "a", Target: "b", Kind: model.EdgeMemberOf}},
	)
	prev, planned, err := PlanScoped(g, Scope{})
	if err != nil {
		t.Fatalf("plan: %v", err)
	}
	if prev.Nodes != 2 || prev.Edges != 1 {
		t.Fatalf("expected 2 nodes / 1 edge, got %+v", prev)
	}
	if len(prev.Domains) != 2 {
		t.Fatalf("expected two domains, got %v", prev.Domains)
	}
	if prev.CrossDomainEdge != 1 {
		t.Fatalf("expected 1 cross-domain edge, got %d", prev.CrossDomainEdge)
	}
	if len(planned.Nodes) != 2 {
		t.Fatalf("unscoped plan must keep everything")
	}
	// The plan must not mutate the input graph.
	if g.Nodes[0].Domain != "corp.local" {
		t.Fatal("PlanScoped mutated the input")
	}
}

func TestPlanScopedRejectsMismatchedDomain(t *testing.T) {
	g := graphOf([]model.Node{user("a", "corp.local"), user("b", "eng.local")}, nil)
	_, _, err := PlanScoped(g, Scope{Domain: "corp.local"})
	if err == nil {
		t.Fatal("expected a domain mismatch error")
	}
	if !strings.Contains(err.Error(), "eng.local") {
		t.Fatalf("error should name the offending domain: %v", err)
	}
}

func TestPlanScopedSkipDropsMismatchAndItsEdges(t *testing.T) {
	g := graphOf(
		[]model.Node{user("a", "corp.local"), user("b", "eng.local"), user("c", "corp.local")},
		[]model.Edge{
			{Source: "a", Target: "c", Kind: model.EdgeMemberOf},
			{Source: "a", Target: "b", Kind: model.EdgeMemberOf},
		},
	)
	prev, planned, err := PlanScoped(g, Scope{Domain: "corp.local", OnMismatch: "skip"})
	if err != nil {
		t.Fatalf("plan: %v", err)
	}
	if prev.SkippedNodes != 1 || prev.SkippedEdges != 1 {
		t.Fatalf("expected 1 skipped node / 1 skipped edge, got %+v", prev)
	}
	if len(planned.Nodes) != 2 || len(planned.Edges) != 1 {
		t.Fatalf("planned graph wrong: %d nodes %d edges", len(planned.Nodes), len(planned.Edges))
	}
	for _, n := range planned.Nodes {
		if n.Domain != "corp.local" {
			t.Fatalf("unexpected domain in planned graph: %q", n.Domain)
		}
	}
}

func TestPlanScopedStampsUnknownDomains(t *testing.T) {
	g := graphOf([]model.Node{user("a", "corp.local"), user("b", "")}, nil)
	prev, planned, err := PlanScoped(g, Scope{Domain: "corp.local", StampUnknown: true})
	if err != nil {
		t.Fatalf("plan: %v", err)
	}
	if prev.StampedNodes != 1 {
		t.Fatalf("expected 1 stamped node, got %+v", prev)
	}
	for _, n := range planned.Nodes {
		if n.Domain != "corp.local" {
			t.Fatalf("node %s not stamped: %q", n.ID, n.Domain)
		}
	}
}

func TestPlanScopedUnknownDomainRejectedByDefault(t *testing.T) {
	g := graphOf([]model.Node{user("b", "")}, nil)
	if _, _, err := PlanScoped(g, Scope{Domain: "corp.local"}); err == nil {
		t.Fatal("expected empty-domain node to be rejected unless stamping is enabled")
	}
}

func TestWriteScopedRecordsProvenanceAndScopesDeletion(t *testing.T) {
	ctx := context.Background()
	st := graph.NewMemory()
	sc := Scope{Domain: "corp.local"}

	if _, err := WriteScoped(ctx, st, graphOf(
		[]model.Node{user("c1", "corp.local"), user("c2", "corp.local")},
		[]model.Edge{{Source: "c1", Target: "c2", Kind: model.EdgeMemberOf}},
	), sc, ModeMerge, "corp.json"); err != nil {
		t.Fatalf("write corp: %v", err)
	}
	res, err := WriteScoped(ctx, st, graphOf(
		[]model.Node{user("e1", "eng.local"), user("e2", "eng.local")},
		nil,
	), Scope{Domain: "eng.local"}, ModeMerge, "eng.json")
	if err != nil {
		t.Fatalf("write eng: %v", err)
	}
	if !res.Tracked || res.Batch == nil || res.Batch.Domain != "eng.local" {
		t.Fatalf("expected a tracked batch for eng.local, got %+v", res)
	}

	batches, _ := st.ListBatches(ctx)
	if len(batches) != 2 {
		t.Fatalf("expected 2 batches, got %d", len(batches))
	}

	// Deleting corp.local must leave eng.local intact.
	prev, err := st.PreviewDeleteDomain(ctx, "corp.local")
	if err != nil {
		t.Fatalf("preview: %v", err)
	}
	if prev.DeleteNodes != 2 || prev.DeleteEdges != 1 {
		t.Fatalf("unexpected preview %+v", prev)
	}
	if _, err := st.DeleteDomain(ctx, "corp.local", prev.Token); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if stats, _ := st.Stats(ctx); stats.Nodes != 2 || stats.Edges != 0 {
		t.Fatalf("eng.local should survive: %+v", stats)
	}
}

func TestWriteScopedDomainReplaceKeepsOtherDomains(t *testing.T) {
	ctx := context.Background()
	st := graph.NewMemory()
	if _, err := WriteScoped(ctx, st, graphOf([]model.Node{user("c1", "corp.local")}, nil), Scope{Domain: "corp.local"}, ModeMerge, "corp.json"); err != nil {
		t.Fatal(err)
	}
	if _, err := WriteScoped(ctx, st, graphOf([]model.Node{user("e1", "eng.local")}, nil), Scope{Domain: "eng.local"}, ModeMerge, "eng.json"); err != nil {
		t.Fatal(err)
	}
	// Replace corp.local with a fresh corp dataset; eng.local must be untouched.
	if _, err := WriteScoped(ctx, st, graphOf([]model.Node{user("c2", "corp.local")}, nil), Scope{Domain: "corp.local"}, ModeReplace, "corp2.json"); err != nil {
		t.Fatalf("replace: %v", err)
	}
	if _, ok, _ := st.GetNode(ctx, "e1"); !ok {
		t.Fatal("domain-scoped replace must not delete other domains")
	}
	if _, ok, _ := st.GetNode(ctx, "c1"); ok {
		t.Fatal("domain-scoped replace must remove the previous data of that domain")
	}
	if _, ok, _ := st.GetNode(ctx, "c2"); !ok {
		t.Fatal("new domain data missing")
	}
}
