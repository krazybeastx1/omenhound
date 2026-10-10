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
