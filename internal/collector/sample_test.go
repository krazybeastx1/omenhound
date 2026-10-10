package collector

import (
	"context"
	"testing"
)

func TestSampleCollectorShape(t *testing.T) {
	g, err := SampleCollector{}.Collect(context.Background(), Options{})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if len(g.Nodes) == 0 || len(g.Edges) == 0 {
		t.Fatalf("expected nodes and edges, got %d/%d", len(g.Nodes), len(g.Edges))
	}
	if g.Meta.Collector != "sample" {
		t.Fatalf("meta collector = %q", g.Meta.Collector)
	}

	ids := map[string]bool{}
	for _, n := range g.Nodes {
		ids[n.ID] = true
	}
	// every edge endpoint must exist (referential integrity)
	for _, e := range g.Edges {
		if !ids[e.Source] {
			t.Errorf("edge source %q missing from nodes", e.Source)
		}
		if !ids[e.Target] {
			t.Errorf("edge target %q missing from nodes", e.Target)
		}
	}

	// there must be a DCSync edge to the domain (the sample's "prize")
	found := false
	for _, e := range g.Edges {
		if e.Kind == "DCSync" {
			found = true
		}
	}
	if !found {
		t.Error("expected a DCSync edge in the sample graph")
	}
}

func TestCollectorNew(t *testing.T) {
	for _, name := range []string{"", "sample", "ldap"} {
		if _, err := New(name); err != nil {
			t.Errorf("New(%q) error: %v", name, err)
		}
	}
	if _, err := New("bogus"); err == nil {
		t.Error("expected error for unknown collector")
	}
}
