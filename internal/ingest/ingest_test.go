package ingest

import (
	"context"
	"strings"
	"testing"

	"github.com/krazybeastx1/omenhound/internal/graph"
	"github.com/krazybeastx1/omenhound/pkg/model"
)

func sample() *model.Graph {
	return &model.Graph{
		Nodes: []model.Node{
			{ID: "A", Kind: model.KindUser, Name: "alice"},
			{ID: "B", Kind: model.KindGroup, Name: "Admins"},
		},
		Edges: []model.Edge{{Source: "A", Target: "B", Kind: model.EdgeMemberOf}},
	}
}

func TestValidateOK(t *testing.T) {
	if err := Validate(sample()); err != nil {
		t.Fatalf("Validate: %v", err)
	}
}

func TestValidateDanglingEdge(t *testing.T) {
	g := sample()
	g.Edges[0].Target = "MISSING"
	if err := Validate(g); err == nil {
		t.Fatal("expected dangling-edge error")
	}
}

func TestValidateUnknownKind(t *testing.T) {
	g := sample()
	g.Nodes[0].Kind = "Wizard"
	if err := Validate(g); err == nil {
		t.Fatal("expected unknown-kind error")
	}
}

func TestValidateEmptyID(t *testing.T) {
	g := sample()
	g.Nodes[0].ID = ""
	if err := Validate(g); err == nil {
		t.Fatal("expected empty-id error")
	}
}

func TestDecodeAndWrite(t *testing.T) {
	j := `{"nodes":[{"id":"A","kind":"User"},{"id":"B","kind":"Group"}],"edges":[{"source":"A","target":"B","kind":"MemberOf"}]}`
	g, err := Decode(strings.NewReader(j))
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if len(g.Nodes) != 2 || len(g.Edges) != 1 {
		t.Fatalf("decoded %d/%d", len(g.Nodes), len(g.Edges))
	}
	st := graph.NewMemory()
	res, err := Write(context.Background(), st, g)
	if err != nil {
		t.Fatalf("Write: %v", err)
	}
	if res.Stats.Nodes != 2 || res.Stats.Edges != 1 {
		t.Fatalf("result stats = %+v", res.Stats)
	}
}

func TestDecodeRejectsGarbage(t *testing.T) {
	if _, err := Decode(strings.NewReader("{not json")); err == nil {
		t.Fatal("expected decode error")
	}
}

func TestParseMode(t *testing.T) {
	cases := map[string]Mode{
		"":        ModeMerge,
		"merge":   ModeMerge,
		"MERGE":   ModeMerge,
		" merge ": ModeMerge,
		"replace": ModeReplace,
		"Replace": ModeReplace,
	}
	for in, want := range cases {
		got, err := ParseMode(in)
		if err != nil {
			t.Fatalf("ParseMode(%q): %v", in, err)
		}
		if got != want {
			t.Fatalf("ParseMode(%q) = %q, want %q", in, got, want)
		}
	}
	for _, bad := range []string{"wipe", "replce", "true"} {
		if _, err := ParseMode(bad); err == nil {
			t.Fatalf("ParseMode(%q): expected error", bad)
		}
	}
}

func TestWriteMergeAccumulates(t *testing.T) {
	ctx := context.Background()
	st := graph.NewMemory()
	if _, err := Write(ctx, st, sample()); err != nil {
		t.Fatalf("first Write: %v", err)
	}
	second := &model.Graph{
		Nodes: []model.Node{{ID: "C", Kind: model.KindComputer, Name: "WS01"}},
	}
	if _, err := Write(ctx, st, second); err != nil {
		t.Fatalf("second Write: %v", err)
	}
	got, _ := st.Stats(ctx)
	if got.Nodes != 3 {
		t.Fatalf("merge nodes = %d, want 3 (A,B preserved)", got.Nodes)
	}
}

func TestWriteReplaceClearsFirst(t *testing.T) {
	ctx := context.Background()
	st := graph.NewMemory()
	if _, err := Write(ctx, st, sample()); err != nil {
		t.Fatalf("seed Write: %v", err)
	}
	replacement := &model.Graph{
		Nodes: []model.Node{{ID: "C", Kind: model.KindComputer, Name: "WS01"}},
		Edges: []model.Edge{},
	}
	res, err := WriteMode(ctx, st, replacement, ModeReplace)
	if err != nil {
		t.Fatalf("replace WriteMode: %v", err)
	}
	if res.Nodes != 1 || res.Edges != 0 {
		t.Fatalf("result = %+v, want 1/0", res)
	}
	if res.Stats.Nodes != 1 || res.Stats.Edges != 0 {
		t.Fatalf("stats = %+v, want 1/0 (previous graph gone)", res.Stats)
	}
	if _, ok, _ := st.GetNode(ctx, "A"); ok {
		t.Fatal("node A survived a replace ingestion")
	}
}

// A malformed payload must never wipe existing data, even in replace mode.
func TestWriteReplaceValidatesBeforeClearing(t *testing.T) {
	ctx := context.Background()
	st := graph.NewMemory()
	if _, err := Write(ctx, st, sample()); err != nil {
		t.Fatalf("seed Write: %v", err)
	}
	bad := &model.Graph{
		Nodes: []model.Node{{ID: "C", Kind: model.KindComputer}},
		Edges: []model.Edge{{Source: "C", Target: "MISSING", Kind: model.EdgeMemberOf}},
	}
	if _, err := WriteMode(ctx, st, bad, ModeReplace); err == nil {
		t.Fatal("expected validation error")
	}
	got, _ := st.Stats(ctx)
	if got.Nodes != 2 || got.Edges != 1 {
		t.Fatalf("stats after rejected replace = %+v, want 2/1 (untouched)", got)
	}
}
