package graph

import (
	"context"
	"sort"
	"strings"
	"sync"

	"github.com/krazybeastx1/omenhound/pkg/model"
)

const (
	defaultPageLimit = 1000
)

// Memory is an in-memory Store. It is safe for concurrent use and is intended
// for tests, demos, and `--collector sample` runs where no Neo4j is available.
//
// Adjacency maps (out/in) make Neighbors and Incoming O(degree) instead of
// O(edges), which matters once a graph has hundreds of thousands of edges.
type Memory struct {
	mu    sync.RWMutex
	nodes map[string]model.Node
	edges map[string]model.Edge
	out   map[string]map[string]model.Edge // source -> edge key -> edge
	in    map[string]map[string]model.Edge // target -> edge key -> edge

	// Ingestion provenance. nodeProv/edgeProv map an entity to the set of batch
	// IDs that have contributed to it; batches holds the batch metadata. This is
	// deliberately separate from the canonical node/edge model.
	batches  map[string]IngestBatch
	nodeProv map[string]map[string]struct{}
	edgeProv map[string]map[string]struct{}
}

// NewMemory returns an empty in-memory store.
func NewMemory() *Memory {
	return &Memory{
		nodes:    make(map[string]model.Node),
		edges:    make(map[string]model.Edge),
		out:      make(map[string]map[string]model.Edge),
		in:       make(map[string]map[string]model.Edge),
		batches:  make(map[string]IngestBatch),
		nodeProv: make(map[string]map[string]struct{}),
		edgeProv: make(map[string]map[string]struct{}),
	}
}

func edgeKey(e model.Edge) string { return e.Source + "\x00" + string(e.Kind) + "\x00" + e.Target }

// UpsertNodes implements Store.
func (m *Memory) UpsertNodes(_ context.Context, nodes []model.Node) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, n := range nodes {
		if n.ID == "" {
			continue
		}
		m.nodes[n.ID] = n
	}
	return nil
}

// UpsertEdges implements Store.
func (m *Memory) UpsertEdges(_ context.Context, edges []model.Edge) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, e := range edges {
		if e.Source == "" || e.Target == "" || e.Kind == "" {
			continue
		}
		k := edgeKey(e)
		m.edges[k] = e
		if m.out[e.Source] == nil {
			m.out[e.Source] = make(map[string]model.Edge)
		}
		m.out[e.Source][k] = e
		if m.in[e.Target] == nil {
			m.in[e.Target] = make(map[string]model.Edge)
		}
		m.in[e.Target][k] = e
	}
	return nil
}

// DeleteNode implements Store.
func (m *Memory) DeleteNode(_ context.Context, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.nodes, id)
	for k, e := range m.out[id] {
		delete(m.edges, k)
		delete(m.in[e.Target], k)
	}
	delete(m.out, id)
	for k, e := range m.in[id] {
		delete(m.edges, k)
		delete(m.out[e.Source], k)
	}
	delete(m.in, id)
	return nil
}

// DeleteEdge implements Store.
func (m *Memory) DeleteEdge(_ context.Context, source, target string, kind model.EdgeKind) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	k := edgeKey(model.Edge{Source: source, Target: target, Kind: kind})
	if e, ok := m.edges[k]; ok {
		delete(m.edges, k)
		delete(m.out[e.Source], k)
		delete(m.in[e.Target], k)
	}
	return nil
}

// Clear implements Store. It drops every node and relationship, and the
// ingestion provenance that pointed at them.
func (m *Memory) Clear(_ context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.nodes = make(map[string]model.Node)
	m.edges = make(map[string]model.Edge)
	m.out = make(map[string]map[string]model.Edge)
	m.in = make(map[string]map[string]model.Edge)
	m.batches = make(map[string]IngestBatch)
	m.nodeProv = make(map[string]map[string]struct{})
	m.edgeProv = make(map[string]map[string]struct{})
	return nil
}

// GetNode implements Store.
func (m *Memory) GetNode(_ context.Context, id string) (model.Node, bool, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	n, ok := m.nodes[id]
	return n, ok, nil
}

// Neighbors implements Store (outgoing edges).
func (m *Memory) Neighbors(_ context.Context, id string) ([]model.Edge, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]model.Edge, 0, len(m.out[id]))
	for _, e := range m.out[id] {
		out = append(out, e)
	}
	sortEdges(out)
	return out, nil
}

// Incoming implements Store.
func (m *Memory) Incoming(_ context.Context, id string) ([]model.Edge, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]model.Edge, 0, len(m.in[id]))
	for _, e := range m.in[id] {
		out = append(out, e)
	}
	sortEdges(out)
	return out, nil
}

// AllNodes implements Store.
func (m *Memory) AllNodes(_ context.Context) ([]model.Node, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]model.Node, 0, len(m.nodes))
	for _, n := range m.nodes {
		out = append(out, n)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}

// AllEdges implements Store.
func (m *Memory) AllEdges(_ context.Context) ([]model.Edge, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]model.Edge, 0, len(m.edges))
	for _, e := range m.edges {
		out = append(out, e)
	}
	sortEdges(out)
	return out, nil
}

// Stats implements Store.
func (m *Memory) Stats(_ context.Context) (Stats, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return Stats{Nodes: len(m.nodes), Edges: len(m.edges)}, nil
}

// SearchNodes implements Store.
func (m *Memory) SearchNodes(_ context.Context, q string, kind model.Kind, domain string, limit, offset int) ([]model.Node, int, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	ql := strings.ToLower(q)
	var out []model.Node
	for _, n := range m.nodes {
		if kind != "" && n.Kind != kind {
			continue
		}
		if domain != "" && strings.ToLower(n.Domain) != strings.ToLower(domain) {
			continue
		}
		if q == "" {
			out = append(out, n)
			continue
		}
		if strings.Contains(strings.ToLower(n.Name), ql) ||
			strings.Contains(strings.ToLower(n.SAMAccountName), ql) ||
			strings.Contains(strings.ToLower(n.ID), ql) ||
			strings.Contains(strings.ToLower(n.DN), ql) {
			out = append(out, n)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	total := len(out)
	if limit <= 0 {
		limit = defaultPageLimit
	}
	if offset < 0 {
		offset = 0
	}
	if offset >= total {
		return []model.Node{}, total, nil
	}
	end := offset + limit
	if end > total {
		end = total
	}
	return out[offset:end], total, nil
}

// Domains implements Store.
func (m *Memory) Domains(_ context.Context) ([]string, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	seen := make(map[string]struct{})
	var out []string
	for _, n := range m.nodes {
		d := strings.TrimSpace(n.Domain)
		if d == "" {
			continue
		}
		if _, ok := seen[strings.ToLower(d)]; ok {
			continue
		}
		seen[strings.ToLower(d)] = struct{}{}
		out = append(out, d)
	}
	sort.Strings(out)
	return out, nil
}

// Trusts implements Store.
func (m *Memory) Trusts(_ context.Context) ([]Trust, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var out []Trust
	for _, e := range m.edges {
		if e.Kind == "Trusts" || e.Kind == "trust" {
			out = append(out, Trust{
				Source:       e.Source,
				Target:       e.Target,
				Type:         string(e.Kind),
				Transitive:   e.Props != nil && e.Props["transitive"] == "true",
				SIDFiltering: e.Props != nil && e.Props["sid_filtering"] == "true",
			})
		}
	}
	if out == nil {
		out = []Trust{}
	}
	return out, nil
}

// Close implements Store.
func (m *Memory) Close(context.Context) error { return nil }

func sortEdges(e []model.Edge) {
	sort.Slice(e, func(i, j int) bool {
		if e[i].Source != e[j].Source {
			return e[i].Source < e[j].Source
		}
		if e[i].Kind != e[j].Kind {
			return e[i].Kind < e[j].Kind
		}
		return e[i].Target < e[j].Target
	})
}

var _ Store = (*Memory)(nil)

// ShortestPaths implements Store using breadth-first search. It returns up to
// MaxPaths distinct shortest routes from SourceID to TargetID.
//
// The search is read-only: it never mutates the adjacency maps, so concurrent
// readers and later queries are unaffected. Relationships are returned exactly
// as stored (Source -> Target) so callers can match them against the dataset;
// traversal direction is conveyed by the order of the nodes.
//
// A node is only expanded at its shortest observed depth, so every returned
// route is a shortest path. Equal-length alternatives are explored (which is
// what makes MaxPaths > 1 meaningful) under a hard expansion budget so a dense
// graph yields a truncated result instead of hanging.
//
// When RequiredIntermediateNodeIDs is set, the shortest-depth prune is relaxed
// so routes through those nodes stay reachable; returned routes are then the
// shortest simple routes satisfying the constraint within the budget.
func (m *Memory) ShortestPaths(_ context.Context, req ShortestPathRequest) (ShortestPathResult, error) {
	if req.SourceID == "" || req.TargetID == "" {
		return ShortestPathResult{}, nil
	}
	if req.MaxDepth <= 0 {
		req.MaxDepth = 6
	}
	if req.MaxPaths <= 0 {
		req.MaxPaths = 10
	}
	if req.MaxPaths > maxPathLimit {
		req.MaxPaths = maxPathLimit
	}

	m.mu.RLock()
	defer m.mu.RUnlock()

	if _, ok := m.nodes[req.SourceID]; !ok {
		return ShortestPathResult{}, nil
	}
	if _, ok := m.nodes[req.TargetID]; !ok {
		return ShortestPathResult{}, nil
	}

	type frame struct {
		node  string
		nodes []string
		edges []model.Edge
		depth int
	}
	queue := []frame{{node: req.SourceID, nodes: []string{req.SourceID}}}
	// With required intermediates the shortest-to-node prune is unsound: a
	// required node may be reachable more cheaply by a branch that does not
	// visit it, so those routes must stay explorable. Alternative-mode searches
	// deliberately disable the prune too, so longer (non-shortest) simple routes
	// are enumerated in increasing length order. The expansion cap keeps both
	// cases bounded.
	prune := len(req.RequiredIntermediateNodeIDs) == 0 && !req.Alternative
	dist := map[string]int{req.SourceID: 0}
	seen := make(map[string]struct{})
	var paths []Path
	expansions := 0
	truncated := false
	over := false

	for head := 0; head < len(queue); head++ {
		if len(paths) >= req.MaxPaths {
			truncated = true
			break
		}
		cur := queue[head]
		if cur.depth >= req.MaxDepth {
			continue
		}
		for _, e := range m.pathNeighbors(cur.node, req.Direction) {
			nxt, ok := otherEnd(e, cur.node)
			if !ok || !relAllowed(e.Kind, req) {
				continue
			}
			// No repeated nodes within a single route: keeps paths simple and
			// prevents cycles from expanding forever.
			if containsNode(cur.nodes, nxt) {
				continue
			}
			nn, ok := m.nodes[nxt]
			if !ok || !nodeAllowed(nn, req) {
				continue
			}
			nd := cur.depth + 1
			if prune {
				if prev, found := dist[nxt]; found && nd > prev {
					// A strictly shorter route to this node already exists; any
					// route through the longer one cannot be a shortest path.
					continue
				}
				dist[nxt] = nd
			}
			expansions++
			if expansions > maxSearchExpansions {
				truncated = true
				over = true
				break
			}

			nodes := appendCopy(cur.nodes, nxt)
			edges := appendEdgeCopy(cur.edges, e)
			if nxt == req.TargetID {
				if !hasRequired(nodes, req.RequiredIntermediateNodeIDs) {
					continue
				}
				if sig := edgePathSig(edges); sig != "" {
					if _, dup := seen[sig]; dup {
						continue
					}
					seen[sig] = struct{}{}
				}
				paths = append(paths, Path{
					Nodes:         m.getNodesFromPath(nodes),
					Relationships: edges,
					Length:        len(edges),
				})
				continue // the target terminates the route
			}
			queue = append(queue, frame{node: nxt, nodes: nodes, edges: edges, depth: nd})
		}
		if over {
			break
		}
	}

	if len(paths) >= req.MaxPaths {
		truncated = true
	}
	return ShortestPathResult{Paths: paths, Truncated: truncated}, nil
}

// pathNeighbors returns the candidate edges to traverse from node, honouring
// the requested direction. It never mutates the store's adjacency maps; the
// result is deterministic (sorted) and deduplicated so self-loops that appear
// in both the incoming and outgoing maps are not expanded twice.
func (m *Memory) pathNeighbors(node string, dir Direction) []model.Edge {
	out := make([]model.Edge, 0, len(m.out[node])+len(m.in[node]))
	appendAll := func(mp map[string]model.Edge) {
		for _, e := range mp {
			out = append(out, e)
		}
	}
	if dir == Outgoing || dir == Undirected {
		appendAll(m.out[node])
	}
	if dir == Incoming || dir == Undirected {
		appendAll(m.in[node])
	}
	sortEdges(out)
	uniq := out[:0]
	var last string
	for i, e := range out {
		k := edgeKey(e)
		if i > 0 && k == last {
			continue
		}
		uniq = append(uniq, e)
		last = k
	}
	return uniq
}

// otherEnd returns the far endpoint of edge relative to node. The edge is
// always reported in its stored orientation, so consumers can highlight it.
func otherEnd(e model.Edge, node string) (string, bool) {
	switch {
	case e.Source == node:
		return e.Target, true
	case e.Target == node:
		return e.Source, true
	default:
		return "", false
	}
}

// appendCopy returns a new slice: ids followed by id. Siblings in the BFS must
// not share a backing array, or one route's append would corrupt another's.
func appendCopy(ids []string, id string) []string {
	out := make([]string, len(ids)+1)
	copy(out, ids)
	out[len(ids)] = id
	return out
}

// appendEdgeCopy returns a new slice: es followed by e.
func appendEdgeCopy(es []model.Edge, e model.Edge) []model.Edge {
	out := make([]model.Edge, len(es)+1)
	copy(out, es)
	out[len(es)] = e
	return out
}

// edgePathSig is a stable signature for a route, used to drop duplicate
// discovery of the same sequence of relationships.
func edgePathSig(es []model.Edge) string {
	if len(es) == 0 {
		return ""
	}
	var b strings.Builder
	for i, e := range es {
		if i > 0 {
			b.WriteByte('>')
		}
		b.WriteString(e.Source)
		b.WriteByte('|')
		b.WriteString(string(e.Kind))
		b.WriteByte('|')
		b.WriteString(e.Target)
	}
	return b.String()
}

func (m *Memory) getNodesFromPath(pids []string) []model.Node {
	out := make([]model.Node, 0, len(pids))
	for _, id := range pids {
		if n, ok := m.nodes[id]; ok {
			out = append(out, n)
		}
	}
	return out
}
