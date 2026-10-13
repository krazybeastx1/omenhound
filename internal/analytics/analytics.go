// Package analytics answers canned, documented attack-path questions over the
// graph — the BloodHound "Attack Paths" idea, without the Cypher console.
//
// Every query is backed by properties or relationships that a real collector or
// the BloodHound CE importer can produce. When the attribute a query needs is
// absent from the whole graph, the result carries an explicit note saying so,
// rather than reporting a clean environment: an empty result is only evidence
// of absence when the data was actually collected.
package analytics

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/krazybeastx1/omenhound/internal/graph"
	"github.com/krazybeastx1/omenhound/pkg/model"
)

// ErrUnknownQuery is returned by Run for an unrecognised query id.
var ErrUnknownQuery = errors.New("analytics: unknown query")

// Query is a canned attack-path query. ID is a stable slug used in the API path.
// Cypher mirrors the equivalent BloodHound CE query so the same question can be
// run against a CE-populated Neo4j graph.
type Query struct {
	ID          string   `json:"id"`
	Title       string   `json:"title"`
	Category    string   `json:"category"`
	Description string   `json:"description"`
	Cypher      string   `json:"cypher,omitempty"`
	References  []string `json:"references,omitempty"`
}

// Finding is one entity matched by a query, carrying the concrete evidence that
// matched it and the ids of any related nodes (e.g. the hosts a principal is
// admin on).
type Finding struct {
	Node     model.Node `json:"node"`
	Reason   string     `json:"reason,omitempty"`
	Evidence []string   `json:"evidence,omitempty"`
	Related  []string   `json:"related,omitempty"`
}

// Result is the outcome of running one query against the current graph.
type Result struct {
	Query    Query     `json:"query"`
	Count    int       `json:"count"`
	Findings []Finding `json:"findings"`
	// Notes are honest caveats, e.g. that the attribute the query depends on is
	// not present in this dataset, so a zero count is not proof of a clean graph.
	Notes []string `json:"notes,omitempty"`
}

// definition pairs the public Query with the matcher that implements it and the
// data it depends on (used to emit honest "not collected" notes).
type definition struct {
	Query
	match         func(*dataset) []Finding
	requiresProps []string
	requiresEdges []model.EdgeKind
}

// dataset is an in-memory index over the graph so matchers stay O(V+E).
type dataset struct {
	nodes []model.Node
	byID  map[string]model.Node
	out   map[string][]model.Edge
}

func newDataset(nodes []model.Node, edges []model.Edge) *dataset {
	d := &dataset{
		nodes: nodes,
		byID:  make(map[string]model.Node, len(nodes)),
		out:   make(map[string][]model.Edge, len(nodes)),
	}
	for _, n := range nodes {
		d.byID[n.ID] = n
	}
	for _, e := range edges {
		d.out[e.Source] = append(d.out[e.Source], e)
	}
	return d
}

// propPresent reports whether any node in the graph carries a non-empty value
// for key. It distinguishes "collected and nothing matched" from "never
// collected", which a bare count cannot.
func (d *dataset) propPresent(key string) bool {
	for _, n := range d.nodes {
		if n.Props != nil {
			if v := strings.TrimSpace(n.Props[key]); v != "" {
				return true
			}
		}
	}
	return false
}

// edgeKindPresent reports whether any relationship of kind exists.
func (d *dataset) edgeKindPresent(k model.EdgeKind) bool {
	for _, edges := range d.out {
		for _, e := range edges {
			if e.Kind == k {
				return true
			}
		}
	}
	return false
}

// Queries returns every canned query, in display order. The matcher functions
// are not part of the returned value.
func Queries() []Query {
	out := make([]Query, 0, len(definitions))
	for _, def := range definitions {
		out = append(out, def.Query)
	}
	return out
}

func lookup(id string) (definition, bool) {
	for _, def := range definitions {
		if def.ID == id {
			return def, true
		}
	}
	return definition{}, false
}

// Run executes the query with the given id against the store.
func Run(ctx context.Context, st graph.Store, id string) (Result, error) {
	def, ok := lookup(id)
	if !ok {
		return Result{}, ErrUnknownQuery
	}
	nodes, err := st.AllNodes(ctx)
	if err != nil {
		return Result{}, err
	}
	edges, err := st.AllEdges(ctx)
	if err != nil {
		return Result{}, err
	}
	d := newDataset(nodes, edges)
	findings := def.match(d)
	sortFindings(findings)
	if findings == nil {
		findings = []Finding{}
	}
	return Result{
		Query:    def.Query,
		Count:    len(findings),
		Findings: findings,
		Notes:    absenceNotes(def, d),
	}, nil
}

// absenceNotes explains, for data-dependent queries, why a zero result may
// reflect missing collection rather than a clean environment.
func absenceNotes(def definition, d *dataset) []string {
	var notes []string
	if len(d.nodes) == 0 {
		notes = append(notes, "The graph is empty; collect or ingest data before drawing conclusions.")
		return notes
	}
	for _, key := range def.requiresProps {
		if !d.propPresent(key) {
			notes = append(notes, fmt.Sprintf(
				"No node carries a %q attribute, so this result may reflect missing collection rather than a clean environment (object properties are collected with `-c objectprops`, or supplied by a BloodHound CE import).",
				key))
		}
	}
	for _, k := range def.requiresEdges {
		if !d.edgeKindPresent(k) {
			notes = append(notes, fmt.Sprintf(
				"No %s relationship exists in this graph; it may not have been collected, so an empty result is not evidence of absence.",
				k))
		}
	}
	return notes
}

func sortFindings(f []Finding) {
	sort.SliceStable(f, func(i, j int) bool {
		a, b := f[i].Node, f[j].Node
		if a.Kind != b.Kind {
			return a.Kind < b.Kind
		}
		an, bn := strings.ToLower(label(a)), strings.ToLower(label(b))
		if an != bn {
			return an < bn
		}
		return a.ID < b.ID
	})
}

func label(n model.Node) string {
	if n.Name != "" {
		return n.Name
	}
	if n.SAMAccountName != "" {
		return n.SAMAccountName
	}
	return n.ID
}

// ---- shared matcher helpers ----

func hasTrue(n model.Node, key string) bool {
	if n.Props == nil {
		return false
	}
	switch strings.ToLower(strings.TrimSpace(n.Props[key])) {
	case "true", "1", "yes":
		return true
	}
	return false
}

func nonEmptyProp(n model.Node, key string) (string, bool) {
	if n.Props == nil {
		return "", false
	}
	v := strings.TrimSpace(n.Props[key])
	return v, v != ""
}

// collect returns the nodes of the given kinds (all kinds when none are given),
// preserving the store's deterministic order.
func collect(d *dataset, kinds ...model.Kind) []model.Node {
	if len(kinds) == 0 {
		return d.nodes
	}
	set := make(map[model.Kind]bool, len(kinds))
	for _, k := range kinds {
		set[k] = true
	}
	var out []model.Node
	for _, n := range d.nodes {
		if set[n.Kind] {
			out = append(out, n)
		}
	}
	return out
}

// outEdgeFindings builds one finding per source node that has at least one
// outgoing edge of the given kinds. When targetKind is non-empty, only edges to
// that kind count. Evidence records each matching edge; Related lists the
// distinct target ids.
func outEdgeFindings(d *dataset, kinds map[model.EdgeKind]bool, targetKind model.Kind, reason string) []Finding {
	var out []Finding
	for _, n := range d.nodes {
		var related, evidence []string
		seenTarget := map[string]bool{}
		seenEvidence := map[string]bool{}
		for _, e := range d.out[n.ID] {
			if !kinds[e.Kind] {
				continue
			}
			t, ok := d.byID[e.Target]
			if !ok {
				t = model.Node{ID: e.Target, Name: e.Target}
			}
			if targetKind != "" && t.Kind != targetKind {
				continue
			}
			if !seenTarget[e.Target] {
				related = append(related, e.Target)
				seenTarget[e.Target] = true
			}
			ev := string(e.Kind) + " \u2192 " + label(t)
			if !seenEvidence[ev] {
				evidence = append(evidence, ev)
				seenEvidence[ev] = true
			}
		}
		if len(related) > 0 {
			sort.Strings(related)
			sort.Strings(evidence)
			out = append(out, Finding{Node: n, Reason: reason, Evidence: evidence, Related: related})
		}
	}
	return out
}

func isKrbtgt(n model.Node) bool {
	return strings.HasPrefix(strings.ToUpper(n.Name), "KRBTGT") ||
		strings.EqualFold(n.SAMAccountName, "krbtgt")
}
