package graph

import (
	"context"
	"sort"
	"sync"

	"github.com/krazybeastx1/omenhound/pkg/model"
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
