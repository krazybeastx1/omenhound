package analytics

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/krazybeastx1/omenhound/internal/graph"
	"github.com/krazybeastx1/omenhound/pkg/model"
)

// fixture builds a graph that exercises every query with a known, minimal set of
// subjects, so each expected count below is deliberate rather than incidental.
func fixture(t *testing.T) *graph.Memory {
	t.Helper()
	st := graph.NewMemory()
	ctx := context.Background()
	nodes := []model.Node{
		{ID: "U-KERB", Kind: model.KindUser, Name: "kerb", Props: map[string]string{"hasspn": "true"}},
		{ID: "U-SPN", Kind: model.KindUser, Name: "spn", Props: map[string]string{"serviceprincipalname": "MSSQLSvc/db.example.com:1433"}},
		{ID: "U-KRBTGT", Kind: model.KindUser, Name: "krbtgt", Props: map[string]string{"hasspn": "true"}},
		{ID: "U-ASREP", Kind: model.KindUser, Name: "asrep", Props: map[string]string{"dontreqpreauth": "true"}},
		{ID: "U-NEVER", Kind: model.KindUser, Name: "never", Props: map[string]string{"pwdneverexpires": "true"}},
		{ID: "U-SENS", Kind: model.KindUser, Name: "sens", Props: map[string]string{"sensitive": "true"}},
		{ID: "U-ADMIN", Kind: model.KindUser, Name: "admin", Props: map[string]string{"admincount": "true", "highvalue": "true"}},
		{ID: "U-OWNED", Kind: model.KindUser, Name: "owned", Props: map[string]string{"owned": "true"}},
		{ID: "U-DCSYNC", Kind: model.KindUser, Name: "dcsync"},
		{ID: "U-ADMINTO", Kind: model.KindUser, Name: "localadmin"},
		{ID: "U-SESSION", Kind: model.KindUser, Name: "sessionuser"},
		{ID: "U-DELEG", Kind: model.KindUser, Name: "deleg"},
		{ID: "U-ACT", Kind: model.KindUser, Name: "act"},
		{ID: "U-LAPS", Kind: model.KindUser, Name: "lapsreader"},
		{ID: "C-UNCON", Kind: model.KindComputer, Name: "UNCON", Props: map[string]string{"unconstraineddelegation": "true"}},
		{ID: "C-WS", Kind: model.KindComputer, Name: "WS01"},
		{ID: "G-DA", Kind: model.KindGroup, Name: "Domain Admins", Props: map[string]string{"highvalue": "true"}},
		{ID: "D-1", Kind: model.KindDomain, Name: "EXAMPLE"},
	}
	edges := []model.Edge{
		{Source: "U-DCSYNC", Target: "D-1", Kind: model.EdgeGetChanges},
		{Source: "U-DCSYNC", Target: "D-1", Kind: model.EdgeGetChangesAll},
		{Source: "U-ADMINTO", Target: "C-WS", Kind: model.EdgeAdminTo},
		{Source: "U-SESSION", Target: "C-WS", Kind: model.EdgeHasSession},
		{Source: "U-DELEG", Target: "C-WS", Kind: model.EdgeAllowedToDelegate},
		{Source: "U-ACT", Target: "C-WS", Kind: model.EdgeAllowedToAct},
		{Source: "U-LAPS", Target: "C-WS", Kind: model.EdgeReadLAPSPassword},
	}
	if err := st.UpsertNodes(ctx, nodes); err != nil {
		t.Fatal(err)
	}
	if err := st.UpsertEdges(ctx, edges); err != nil {
		t.Fatal(err)
	}
	return st
}

func run(t *testing.T, id string) Result {
	t.Helper()
	res, err := Run(context.Background(), fixture(t), id)
	if err != nil {
		t.Fatalf("Run(%s): %v", id, err)
	}
	return res
}

func ids(res Result) map[string]bool {
	m := make(map[string]bool, len(res.Findings))
	for _, f := range res.Findings {
		m[f.Node.ID] = true
	}
	return m
}

func TestQueriesAreUniqueAndComplete(t *testing.T) {
	seen := map[string]bool{}
	for _, q := range Queries() {
		if q.ID == "" || q.Title == "" || q.Description == "" {
			t.Fatalf("query %+v is missing id/title/description", q)
		}
		if seen[q.ID] {
			t.Fatalf("duplicate query id %q", q.ID)
		}
		seen[q.ID] = true
	}
	// Every query in the registry must be runnable.
	for _, q := range Queries() {
		if _, err := Run(context.Background(), fixture(t), q.ID); err != nil {
			t.Fatalf("Run(%s): %v", q.ID, err)
		}
	}
}

func TestQueryResults(t *testing.T) {
	cases := []struct {
		id   string
		want []string
	}{
		{"kerberoastable", []string{"U-KERB", "U-SPN"}}, // krbtgt excluded
		{"asreproastable", []string{"U-ASREP"}},
		{"dcsync", []string{"U-DCSYNC"}},
		{"laps-readable", []string{"U-LAPS"}},
		{"password-never-expires", []string{"U-NEVER"}},
		{"unconstrained-delegation", []string{"C-UNCON"}},
		{"constrained-delegation", []string{"U-DELEG"}},
		{"rbcd", []string{"U-ACT"}},
		{"adminto", []string{"U-ADMINTO"}},
		{"has-session", []string{"U-SESSION"}},
		{"high-value-targets", []string{"U-ADMIN", "G-DA"}},
		{"admincount", []string{"U-ADMIN"}},
		{"sensitive-users", []string{"U-SENS"}},
		{"owned", []string{"U-OWNED"}},
	}
	for _, tc := range cases {
		res := run(t, tc.id)
		if res.Count != len(res.Findings) {
			t.Fatalf("%s: Count=%d but %d findings", tc.id, res.Count, len(res.Findings))
		}
		got := ids(res)
		if len(got) != len(tc.want) {
			t.Fatalf("%s: got %v, want %v", tc.id, got, tc.want)
		}
		for _, id := range tc.want {
			if !got[id] {
				t.Fatalf("%s: missing %s in %v", tc.id, id, got)
			}
		}
	}
}

// A query with no data must explain that the underlying attribute is absent,
// not report a clean environment.
func TestAbsenceNote(t *testing.T) {
	st := graph.NewMemory()
	if err := st.UpsertNodes(context.Background(), []model.Node{{ID: "U", Kind: model.KindUser, Name: "u"}}); err != nil {
		t.Fatal(err)
	}
	res, err := Run(context.Background(), st, "kerberoastable")
	if err != nil {
		t.Fatal(err)
	}
	if res.Count != 0 {
		t.Fatalf("expected 0 findings, got %d", res.Count)
	}
	if len(res.Notes) == 0 || !strings.Contains(strings.Join(res.Notes, " "), "may reflect missing collection") {
		t.Fatalf("expected an honest absence note, got %v", res.Notes)
	}
}

func TestEdgeAbsenceNote(t *testing.T) {
	st := graph.NewMemory()
	if err := st.UpsertNodes(context.Background(), []model.Node{
		{ID: "U", Kind: model.KindUser, Name: "u"},
		{ID: "C", Kind: model.KindComputer, Name: "c"},
	}); err != nil {
		t.Fatal(err)
	}
	res, err := Run(context.Background(), st, "adminto")
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Notes) == 0 || !strings.Contains(strings.Join(res.Notes, " "), "AdminTo") {
		t.Fatalf("expected an edge-absence note, got %v", res.Notes)
	}
}

func TestEmptyGraphNote(t *testing.T) {
	res, err := Run(context.Background(), graph.NewMemory(), "owned")
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Notes) != 1 || !strings.Contains(res.Notes[0], "empty") {
		t.Fatalf("expected the empty-graph note, got %v", res.Notes)
	}
	if res.Findings == nil {
		t.Fatal("findings must be an empty slice, never null")
	}
}

func TestUnknownQuery(t *testing.T) {
	_, err := Run(context.Background(), fixture(t), "does-not-exist")
	if !errors.Is(err, ErrUnknownQuery) {
		t.Fatalf("err = %v, want ErrUnknownQuery", err)
	}
}

func TestFindingsAreDeterministic(t *testing.T) {
	first := run(t, "high-value-targets")
	second := run(t, "high-value-targets")
	for i := range first.Findings {
		if first.Findings[i].Node.ID != second.Findings[i].Node.ID {
			t.Fatalf("non-deterministic order: %v vs %v", ids(first), ids(second))
		}
	}
}
