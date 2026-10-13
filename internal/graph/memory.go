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
}

// NewMemory returns an empty in-memory store.
func NewMemory() *Memory {
	return &Memory{
		nodes: make(map[string]model.Node),
		edges: make(map[string]model.Edge),
		out:   make(map[string]map[string]model.Edge),
		in:    make(map[string]map[string]model.Edge),
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

// Clear implements Store. It drops every node and relationship.
func (m *Memory) Clear(_ context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.nodes = make(map[string]model.Node)
	m.edges = make(map[string]model.Edge)
	m.out = make(map[string]map[string]model.Edge)
	m.in = make(map[string]map[string]model.Edge)
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

// ShortestPaths implements Store using BFS.
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

	m.mu.RLock()
	if _, ok1 := m.nodes[req.SourceID]; !ok1 {
		m.mu.RUnlock()
		return ShortestPathResult{}, nil
	}
	if _, ok2 := m.nodes[req.TargetID]; !ok2 {
		m.mu.RUnlock()
		return ShortestPathResult{}, nil
	}
	m.mu.RUnlock()

	type state struct {
		node  string
		path  []string
		edges []model.Edge
		depth int
	}
	queue := []state{{node: req.SourceID, path: []string{req.SourceID}, edges: []model.Edge{}, depth: 0}}
	visited := map[string]int{req.SourceID: 0}
	var paths []Path

	for i := 0; i < len(queue); i++ {
		cur := queue[i]
		if cur.depth >= req.MaxDepth {
			continue
		}
		neighbors := m.out[cur.node]
		if req.Direction == Incoming || req.Direction == Undirected {
			for _, e := range m.in[cur.node] {
				neighbors["rev"+e.Source+string(e.Kind)+e.Target] = e
			}
		}
		for _, e := range neighbors {
			edge := e
			if edge.Source != cur.node && (req.Direction == Outgoing || req.Direction == Incoming) {
				// for undirected we need to handle; but simpler: reconstruct
			}
			nxtNode := edge.Target
			if edge.Target == cur.node {
				nxtNode = edge.Source
				edge2 := model.Edge{Source: edge.Target, Target: edge.Source, Kind: edge.Kind}
				edge = edge2
			}
			if req.Direction == Incoming && edge.Source == cur.node && edge.Target != cur.node {
				continue
			}
			// filter relationship types
			if len(req.IncludeRelationshipTypes) > 0 {
				ok := false
				for _, k := range req.IncludeRelationshipTypes {
					if edge.Kind == k {
						ok = true
						break
					}
				}
				if !ok {
					continue
				}
			}
			if len(req.ExcludeRelationshipTypes) > 0 {
				ex := false
				for _, k := range req.ExcludeRelationshipTypes {
					if edge.Kind == k {
						ex = true
						break
					}
				}
				if ex {
					continue
				}
			}
			n, on := m.nodes[nxtNode]
			if !on {
				continue
			}
			if len(req.IncludeNodeTypes) > 0 {
				ok := false
				for _, k := range req.IncludeNodeTypes {
					if n.Kind == k {
						ok = true
						break
					}
				}
				if !ok {
					continue
				}
			}
			if len(req.ExcludeNodeTypes) > 0 {
				ex := false
				for _, k := range req.ExcludeNodeTypes {
					if n.Kind == k {
						ex = true
						break
					}
				}
				if ex {
					continue
				}
			}
			if nxtNode == req.TargetID {
				pn := make([]model.Node, 0, len(cur.path)+1)
				for _, pid := range append(cur.path, nxtNode) {
					if nn, ok := m.nodes[pid]; ok {
						pn = append(pn, nn)
					}
				}
				pe := make([]model.Edge, 0, len(cur.edges)+1)
				for _, ee := range cur.edges {
					pe = append(pe, ee)
				}
				pe = append(pe, edge)
				paths = append(paths, Path{Nodes: pn, Relationships: pe, Length: len(pe)})
				if len(paths) >= req.MaxPaths {
					break
				}
				continue
			}
			if prev, seen := visited[nxtNode]; seen && prev <= cur.depth+1 {
				continue
			}
			visited[nxtNode] = cur.depth + 1
			newPath := append(append([]string(nil), cur.path...), nxtNode)
			newEdges := append(append([]model.Edge(nil), cur.edges...), edge)
			queue = append(queue, state{node: nxtNode, path: newPath, edges: newEdges, depth: cur.depth + 1})
		}
		if len(paths) >= req.MaxPaths {
			break
		}
	}

	trunc := len(paths) >= req.MaxPaths
	return ShortestPathResult{Paths: paths, Truncated: trunc}, nil
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
