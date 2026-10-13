package graph

import (
	"context"
	"testing"

	"github.com/krazybeastx1/omenhound/pkg/model"
)

// seedPathStore builds a small store for path tests. Callers add their own
// edges so each test states exactly the topology it depends on.
func seedPathStore(t *testing.T, nodes []model.Node, edges []model.Edge) *Memory {
	t.Helper()
	m := NewMemory()
	ctx := context.Background()
	if err := m.UpsertNodes(ctx, nodes); err != nil {
		t.Fatal(err)
	}
	if err := m.UpsertEdges(ctx, edges); err != nil {
		t.Fatal(err)
	}
	return m
}

func mustPaths(t *testing.T, m *Memory, req ShortestPathRequest) ShortestPathResult {
	t.Helper()
	res, err := m.ShortestPaths(context.Background(), req)
	if err != nil {
		t.Fatalf("ShortestPaths(%+v): %v", req, err)
	}
	return res
}

func TestShortestPathsDirection(t *testing.T) {
	// U -> H -> G; query U..G in both directions.
	m := seedPathStore(t,
		[]model.Node{
			{ID: "U", Kind: model.KindUser},
			{ID: "H", Kind: model.KindComputer},
			{ID: "G", Kind: model.KindGroup},
		},
		[]model.Edge{
			{Source: "U", Target: "H", Kind: model.EdgeAdminTo},
			{Source: "H", Target: "G", Kind: model.EdgeMemberOf},
		})

	out := mustPaths(t, m, ShortestPathRequest{SourceID: "U", TargetID: "G", Direction: Outgoing, MaxDepth: 5})
	if len(out.Paths) != 1 || out.Paths[0].Length != 2 {
		t.Fatalf("outgoing paths = %+v, want 1 path of length 2", out.Paths)
	}
	if out.Paths[0].Nodes[0].ID != "U" || out.Paths[0].Nodes[2].ID != "G" {
		t.Fatalf("outgoing node order = %v", nodeIDs(out.Paths[0]))
	}
	// Relationships must be returned as stored (Source -> Target) so callers
	// can match them against the dataset for highlighting.
	if r0 := out.Paths[0].Relationships[0]; r0.Source != "U" || r0.Target != "H" || r0.Kind != model.EdgeAdminTo {
		t.Fatalf("relationship[0] = %+v, want U->H AdminTo", r0)
	}
	if r1 := out.Paths[0].Relationships[1]; r1.Source != "H" || r1.Target != "G" || r1.Kind != model.EdgeMemberOf {
		t.Fatalf("relationship[1] = %+v, want H->G MemberOf", r1)
	}

	inc := mustPaths(t, m, ShortestPathRequest{SourceID: "U", TargetID: "G", Direction: Incoming, MaxDepth: 5})
	if len(inc.Paths) != 0 {
		t.Fatalf("incoming U->G paths = %+v, want none", inc.Paths)
	}

	rev := mustPaths(t, m, ShortestPathRequest{SourceID: "G", TargetID: "U", Direction: Incoming, MaxDepth: 5})
	if len(rev.Paths) != 1 || rev.Paths[0].Length != 2 {
		t.Fatalf("incoming G->U paths = %+v, want 1 path of length 2", rev.Paths)
	}
	if rev.Paths[0].Nodes[0].ID != "G" || rev.Paths[0].Nodes[2].ID != "U" {
		t.Fatalf("incoming node order = %v", nodeIDs(rev.Paths[0]))
	}
	// Stored orientation preserved even though traversal went backwards.
	if r0 := rev.Paths[0].Relationships[0]; r0.Source != "H" || r0.Target != "G" {
		t.Fatalf("incoming relationship[0] = %+v, want H->G (stored)", r0)
	}

	und := mustPaths(t, m, ShortestPathRequest{SourceID: "U", TargetID: "G", Direction: Undirected, MaxDepth: 5})
	if len(und.Paths) != 1 || und.Paths[0].Length != 2 {
		t.Fatalf("undirected paths = %+v, want 1 path of length 2", und.Paths)
	}
}

func TestShortestPathsMultipleEqualLength(t *testing.T) {
	// Diamond: S -> {A,B} -> T. Two distinct shortest routes.
	m := seedPathStore(t,
		[]model.Node{
			{ID: "S", Kind: model.KindUser},
			{ID: "A", Kind: model.KindGroup},
			{ID: "B", Kind: model.KindGroup},
			{ID: "T", Kind: model.KindDomain},
		},
		[]model.Edge{
			{Source: "S", Target: "A", Kind: model.EdgeMemberOf},
			{Source: "S", Target: "B", Kind: model.EdgeGenericWrite},
			{Source: "A", Target: "T", Kind: model.EdgeGenericAll},
			{Source: "B", Target: "T", Kind: model.EdgeDCSync},
		})

	res := mustPaths(t, m, ShortestPathRequest{SourceID: "S", TargetID: "T", Direction: Outgoing, MaxDepth: 5, MaxPaths: 10})
	if len(res.Paths) != 2 {
		t.Fatalf("paths = %d (%v), want 2 equal-length routes", len(res.Paths), res.Paths)
	}
	for _, p := range res.Paths {
		if p.Length != 2 {
			t.Fatalf("path length = %d, want 2", p.Length)
		}
	}
	if res.Truncated {
		t.Fatalf("result unexpectedly truncated: %+v", res)
	}

	// MaxPaths bounds the list and must be reported as truncated.
	one := mustPaths(t, m, ShortestPathRequest{SourceID: "S", TargetID: "T", Direction: Outgoing, MaxDepth: 5, MaxPaths: 1})
	if len(one.Paths) != 1 || !one.Truncated {
		t.Fatalf("maxPaths=1 result = %+v, want 1 path and truncated", one)
	}
}

func TestShortestPathsDistinctParallelRelationships(t *testing.T) {
	// Two relationship kinds between the same pair are two distinct routes.
	m := seedPathStore(t,
		[]model.Node{{ID: "A", Kind: model.KindUser}, {ID: "B", Kind: model.KindGroup}},
		[]model.Edge{
			{Source: "A", Target: "B", Kind: model.EdgeMemberOf},
			{Source: "A", Target: "B", Kind: model.EdgeGenericWrite},
		})

	res := mustPaths(t, m, ShortestPathRequest{SourceID: "A", TargetID: "B", Direction: Outgoing, MaxDepth: 3, MaxPaths: 10})
	if len(res.Paths) != 2 {
		t.Fatalf("parallel-relationship paths = %d (%v), want 2", len(res.Paths), res.Paths)
	}
}

func TestShortestPathsAvoidsCycles(t *testing.T) {
	// A -> B -> A cycle must terminate and still find A -> B -> C.
	m := seedPathStore(t,
		[]model.Node{
			{ID: "A", Kind: model.KindUser},
			{ID: "B", Kind: model.KindGroup},
			{ID: "C", Kind: model.KindDomain},
		},
		[]model.Edge{
			{Source: "A", Target: "B", Kind: model.EdgeMemberOf},
			{Source: "B", Target: "A", Kind: model.EdgeGenericAll},
			{Source: "B", Target: "C", Kind: model.EdgeGenericAll},
		})

	res := mustPaths(t, m, ShortestPathRequest{SourceID: "A", TargetID: "C", Direction: Outgoing, MaxDepth: 10, MaxPaths: 10})
	if len(res.Paths) != 1 || res.Paths[0].Length != 2 {
		t.Fatalf("cyclic result = %+v, want a single 2-hop route", res.Paths)
	}
	if got := nodeIDs(res.Paths[0]); len(got) != 3 || got[0] != "A" || got[2] != "C" {
		t.Fatalf("node order = %v, want [A B C]", got)
	}
}

func TestShortestPathsMissingEndpoints(t *testing.T) {
	m := seedPathStore(t, []model.Node{{ID: "A", Kind: model.KindUser}}, nil)

	for _, req := range []ShortestPathRequest{
		{SourceID: "A", TargetID: "missing"},
		{SourceID: "missing", TargetID: "A"},
		{SourceID: "", TargetID: "A"},
	} {
		res := mustPaths(t, m, req)
		if len(res.Paths) != 0 || res.Truncated {
			t.Fatalf("req %+v = %+v, want empty non-truncated", req, res)
		}
	}
}

// A start that equals the target has no meaningful route: the walk must not
// report the node to itself, even when a cycle would make it reachable.
func TestShortestPathsIdenticalEndpoints(t *testing.T) {
	m := seedPathStore(t,
		[]model.Node{{ID: "A", Kind: model.KindUser}, {ID: "B", Kind: model.KindGroup}},
		[]model.Edge{
			{Source: "A", Target: "B", Kind: model.EdgeMemberOf},
			{Source: "B", Target: "A", Kind: model.EdgeMemberOf},
		})

	res := mustPaths(t, m, ShortestPathRequest{SourceID: "A", TargetID: "A", Direction: Outgoing, MaxDepth: 5, MaxPaths: 10})
	if len(res.Paths) != 0 {
		t.Fatalf("A->A = %+v, want no route", res.Paths)
	}
}

func TestShortestPathsRelationshipFilters(t *testing.T) {
	m := seedPathStore(t,
		[]model.Node{
			{ID: "U", Kind: model.KindUser},
			{ID: "H", Kind: model.KindComputer},
			{ID: "G", Kind: model.KindGroup},
		},
		[]model.Edge{
			{Source: "U", Target: "H", Kind: model.EdgeAdminTo},
			{Source: "H", Target: "G", Kind: model.EdgeMemberOf},
		})

	base := ShortestPathRequest{SourceID: "U", TargetID: "G", Direction: Outgoing, MaxDepth: 5}

	onlyAdmin := base
	onlyAdmin.IncludeRelationshipTypes = []model.EdgeKind{model.EdgeAdminTo}
	if got := mustPaths(t, m, onlyAdmin); len(got.Paths) != 0 {
		t.Fatalf("include AdminTo only = %+v, want none (MemberOf hop missing)", got.Paths)
	}

	both := base
	both.IncludeRelationshipTypes = []model.EdgeKind{model.EdgeAdminTo, model.EdgeMemberOf}
	if got := mustPaths(t, m, both); len(got.Paths) != 1 {
		t.Fatalf("include both = %+v, want 1 path", got.Paths)
	}

	exclMember := base
	exclMember.ExcludeRelationshipTypes = []model.EdgeKind{model.EdgeMemberOf}
	if got := mustPaths(t, m, exclMember); len(got.Paths) != 0 {
		t.Fatalf("exclude MemberOf = %+v, want none", got.Paths)
	}
}

func TestShortestPathsNodeFilters(t *testing.T) {
	m := seedPathStore(t,
		[]model.Node{
			{ID: "U", Kind: model.KindUser},
			{ID: "H", Kind: model.KindComputer},
			{ID: "G", Kind: model.KindGroup},
		},
		[]model.Edge{
			{Source: "U", Target: "H", Kind: model.EdgeAdminTo},
			{Source: "U", Target: "G", Kind: model.EdgeMemberOf},
		})

	base := ShortestPathRequest{SourceID: "U", TargetID: "G", Direction: Outgoing, MaxDepth: 5}

	// The target (Group) is filtered out, so the route is rejected.
	incComp := base
	incComp.IncludeNodeTypes = []model.Kind{model.KindComputer}
	if got := mustPaths(t, m, incComp); len(got.Paths) != 0 {
		t.Fatalf("include Computer target=Group = %+v, want none", got.Paths)
	}

	toHost := ShortestPathRequest{SourceID: "U", TargetID: "H", Direction: Outgoing, MaxDepth: 5, IncludeNodeTypes: []model.Kind{model.KindComputer}}
	if got := mustPaths(t, m, toHost); len(got.Paths) != 1 {
		t.Fatalf("include Computer target=Computer = %+v, want 1 path", got.Paths)
	}

	exclComp := toHost
	exclComp.IncludeNodeTypes = nil
	exclComp.ExcludeNodeTypes = []model.Kind{model.KindComputer}
	if got := mustPaths(t, m, exclComp); len(got.Paths) != 0 {
		t.Fatalf("exclude Computer = %+v, want none", got.Paths)
	}
}

func TestShortestPathsMaxDepthAndRequiredIntermediate(t *testing.T) {
	// S -> B -> T (length 2) and S -> A -> M -> T (length 3).
	m := seedPathStore(t,
		[]model.Node{
			{ID: "S", Kind: model.KindUser},
			{ID: "A", Kind: model.KindGroup},
			{ID: "B", Kind: model.KindGroup},
			{ID: "M", Kind: model.KindGroup},
			{ID: "T", Kind: model.KindDomain},
		},
		[]model.Edge{
			{Source: "S", Target: "B", Kind: model.EdgeGenericWrite},
			{Source: "B", Target: "T", Kind: model.EdgeGenericAll},
			{Source: "S", Target: "A", Kind: model.EdgeMemberOf},
			{Source: "A", Target: "M", Kind: model.EdgeMemberOf},
			{Source: "M", Target: "T", Kind: model.EdgeGenericAll},
		})

	// Depth 2 allows only the short route.
	d2 := mustPaths(t, m, ShortestPathRequest{SourceID: "S", TargetID: "T", Direction: Outgoing, MaxDepth: 2, MaxPaths: 10})
	if len(d2.Paths) != 1 || d2.Paths[0].Length != 2 {
		t.Fatalf("maxDepth=2 = %+v, want the single 2-hop route", d2.Paths)
	}

	// Depth 1 cannot reach the target.
	d1 := mustPaths(t, m, ShortestPathRequest{SourceID: "S", TargetID: "T", Direction: Outgoing, MaxDepth: 1, MaxPaths: 10})
	if len(d1.Paths) != 0 {
		t.Fatalf("maxDepth=1 = %+v, want none", d1.Paths)
	}

	// Requiring A keeps only the longer route, even though a shorter one exists.
	req := mustPaths(t, m, ShortestPathRequest{
		SourceID: "S", TargetID: "T", Direction: Outgoing, MaxDepth: 5, MaxPaths: 10,
		RequiredIntermediateNodeIDs: []string{"A"},
	})
	if len(req.Paths) != 1 || req.Paths[0].Length != 3 {
		t.Fatalf("required A = %+v, want the single 3-hop route", req.Paths)
	}
	if got := nodeIDs(req.Paths[0]); got[1] != "A" {
		t.Fatalf("required route nodes = %v, want A as the first hop", got)
	}
}

func TestShortestPathsDoesNotMutateStore(t *testing.T) {
	m := seedPathStore(t,
		[]model.Node{
			{ID: "U", Kind: model.KindUser},
			{ID: "H", Kind: model.KindComputer},
			{ID: "G", Kind: model.KindGroup},
		},
		[]model.Edge{
			{Source: "U", Target: "H", Kind: model.EdgeAdminTo},
			{Source: "H", Target: "G", Kind: model.EdgeMemberOf},
		})

	before, _ := m.Stats(context.Background())
	edgesBefore, _ := m.AllEdges(context.Background())
	neighBefore, _ := m.Neighbors(context.Background(), "U")

	// Run each direction; a buggy implementation used to inject synthetic
	// reversed edges into the adjacency maps here.
	mustPaths(t, m, ShortestPathRequest{SourceID: "U", TargetID: "G", Direction: Incoming, MaxDepth: 5})
	mustPaths(t, m, ShortestPathRequest{SourceID: "U", TargetID: "G", Direction: Undirected, MaxDepth: 5})
	first := mustPaths(t, m, ShortestPathRequest{SourceID: "U", TargetID: "G", Direction: Outgoing, MaxDepth: 5})

	after, _ := m.Stats(context.Background())
	edgesAfter, _ := m.AllEdges(context.Background())
	neighAfter, _ := m.Neighbors(context.Background(), "U")

	if before != after {
		t.Fatalf("stats changed: %+v -> %+v", before, after)
	}
	if len(edgesBefore) != len(edgesAfter) {
		t.Fatalf("edge count changed: %d -> %d", len(edgesBefore), len(edgesAfter))
	}
	if len(neighBefore) != len(neighAfter) {
		t.Fatalf("neighbors(U) changed: %d -> %d", len(neighBefore), len(neighAfter))
	}

	// Repeating the same search is deterministic.
	second := mustPaths(t, m, ShortestPathRequest{SourceID: "U", TargetID: "G", Direction: Outgoing, MaxDepth: 5})
	if len(first.Paths) != len(second.Paths) {
		t.Fatalf("non-deterministic results: %d vs %d paths", len(first.Paths), len(second.Paths))
	}
	if len(first.Paths) == 1 && len(second.Paths) == 1 {
		if a, b := edgePathSig(first.Paths[0].Relationships), edgePathSig(second.Paths[0].Relationships); a != b {
			t.Fatalf("unstable route: %q vs %q", a, b)
		}
	}
}

func nodeIDs(p Path) []string {
	out := make([]string, 0, len(p.Nodes))
	for _, n := range p.Nodes {
		out = append(out, n.ID)
	}
	return out
}

func TestShortestPathsDomainFilter(t *testing.T) {
	// S(corp) -> short(corp) -> T(eng)          (length 2)
	// S(corp) -> a(eng) -> b(eng) -> T(eng)     (length 3)
	m := seedPathStore(t,
		[]model.Node{
			{ID: "S", Kind: model.KindUser, Domain: "corp.local"},
			{ID: "short", Kind: model.KindComputer, Domain: "corp.local"},
			{ID: "a", Kind: model.KindComputer, Domain: "eng.local"},
			{ID: "b", Kind: model.KindGroup, Domain: "eng.local"},
			{ID: "T", Kind: model.KindUser, Domain: "eng.local"},
		},
		[]model.Edge{
			{Source: "S", Target: "short", Kind: model.EdgeAdminTo},
			{Source: "short", Target: "T", Kind: model.EdgeMemberOf},
			{Source: "S", Target: "a", Kind: model.EdgeAdminTo},
			{Source: "a", Target: "b", Kind: model.EdgeGenericAll},
			{Source: "b", Target: "T", Kind: model.EdgeMemberOf},
		})

	// Without a domain filter the shortest route (via short) wins.
	all := mustPaths(t, m, ShortestPathRequest{SourceID: "S", TargetID: "T", Direction: Outgoing, MaxDepth: 5, MaxPaths: 10})
	if len(all.Paths) != 1 || nodeIDs(all.Paths[0])[1] != "short" {
		t.Fatalf("expected only the short corp route, got %v", all.Paths)
	}

	// Restricting to eng.local drops the corp intermediate; the longer eng route
	// is then the only one available.
	eng := mustPaths(t, m, ShortestPathRequest{SourceID: "S", TargetID: "T", Direction: Outgoing, MaxDepth: 5,
		IncludeDomains: []string{"ENG.LOCAL"}})
	if len(eng.Paths) != 1 || nodeIDs(eng.Paths[0])[1] != "a" {
		t.Fatalf("expected only the eng route, got %v", eng.Paths)
	}

	// Excluding corp.local drops the corp intermediate, leaving the eng route.
	// (The target's own domain is filtered too, so excluding eng.local would
	// yield no route at all — see the next assertion.)
	exclCorp := mustPaths(t, m, ShortestPathRequest{SourceID: "S", TargetID: "T", Direction: Outgoing, MaxDepth: 5,
		ExcludeDomains: []string{"corp.local"}})
	if len(exclCorp.Paths) != 1 || nodeIDs(exclCorp.Paths[0])[1] != "a" {
		t.Fatalf("expected only the eng route, got %v", exclCorp.Paths)
	}

	// Excluding the target's domain removes the target from the search, so no
	// route can complete.
	exclEng := mustPaths(t, m, ShortestPathRequest{SourceID: "S", TargetID: "T", Direction: Outgoing, MaxDepth: 5,
		ExcludeDomains: []string{"eng.local"}})
	if len(exclEng.Paths) != 0 {
		t.Fatalf("excluding the target domain should find nothing, got %v", exclEng.Paths)
	}
}

func TestAlternativeModeFindsLongerRoutes(t *testing.T) {
	// S -> M -> T (length 2) and S -> A -> B -> T (length 3).
	m := seedPathStore(t,
		[]model.Node{
			{ID: "S", Kind: model.KindUser},
			{ID: "M", Kind: model.KindComputer},
			{ID: "A", Kind: model.KindGroup},
			{ID: "B", Kind: model.KindGPO},
			{ID: "T", Kind: model.KindUser},
		},
		[]model.Edge{
			{Source: "S", Target: "M", Kind: model.EdgeAdminTo},
			{Source: "M", Target: "T", Kind: model.EdgeMemberOf},
			{Source: "S", Target: "A", Kind: model.EdgeGenericAll},
			{Source: "A", Target: "B", Kind: model.EdgeGPLink},
			{Source: "B", Target: "T", Kind: model.EdgeMemberOf},
		})

	// Shortest-only returns just the length-2 route.
	short := mustPaths(t, m, ShortestPathRequest{SourceID: "S", TargetID: "T", Direction: Outgoing, MaxDepth: 5, MaxPaths: 10})
	if len(short.Paths) != 1 || short.Paths[0].Length != 2 {
		t.Fatalf("shortest-only = %v", short.Paths)
	}

	// Alternative mode also surfaces the longer simple route.
	alt := mustPaths(t, m, ShortestPathRequest{SourceID: "S", TargetID: "T", Direction: Outgoing, MaxDepth: 5, MaxPaths: 10, Alternative: true})
	if len(alt.Paths) != 2 {
		t.Fatalf("alternative mode should find 2 routes, got %d (%v)", len(alt.Paths), alt.Paths)
	}
	if alt.Paths[0].Length != 2 || alt.Paths[1].Length != 3 {
		t.Fatalf("routes should be ordered by length, got %d then %d", alt.Paths[0].Length, alt.Paths[1].Length)
	}
}
