package graph

import (
	"context"
	"fmt"
	"sort"

	"github.com/neo4j/neo4j-go-driver/v5/neo4j"

	"github.com/krazybeastx1/omenhound/pkg/model"
)

// Neo4jStore persists the graph in Neo4j using BloodHound CE's label/edge model
// so that existing BloodHound Cypher queries keep working.
type Neo4jStore struct {
	driver   neo4j.DriverWithContext
	database string
}

// label maps a model.Kind to a whitelisted Cypher label (prevents injection).
func label(k model.Kind) (string, error) {
	switch k {
	case model.KindUser, model.KindGroup, model.KindComputer, model.KindDomain,
		model.KindOU, model.KindGPO, model.KindContainer, model.KindTrust:
		return string(k), nil
	default:
		return "", fmt.Errorf("graph: unknown node kind %q", k)
	}
}

// allowedRels is the whitelist of relationship types (prevents injection).
var allowedRels = func() map[model.EdgeKind]bool {
	m := map[model.EdgeKind]bool{}
	for _, k := range []model.EdgeKind{
		model.EdgeGenericAll, model.EdgeGenericWrite, model.EdgeWriteDacl, model.EdgeWriteOwner,
		model.EdgeForceChangePassword, model.EdgeAddMember, model.EdgeAddSelf, model.EdgeOwns,
		model.EdgeAllowedToDelegate, model.EdgeAllowedToAct, model.EdgeAdminTo, model.EdgeCanPSRemote,
		model.EdgeExecuteDCOM, model.EdgeHasSession, model.EdgeMemberOf, model.EdgeDCSync,
		model.EdgeGetChanges, model.EdgeGetChangesAll, model.EdgeReadLAPSPassword, model.EdgeReadGMSAPassword,
		model.EdgeContains, model.EdgeGPLink, model.EdgeTrustedBy,
	} {
		m[k] = true
	}
	return m
}()

func relType(k model.EdgeKind) (string, error) {
	if !allowedRels[k] {
		return "", fmt.Errorf("graph: unknown edge kind %q", k)
	}
	return string(k), nil
}

// NewNeo4j connects to Neo4j, verifies connectivity, and ensures the schema.
func NewNeo4j(ctx context.Context, uri, user, password, database string) (*Neo4jStore, error) {
	driver, err := neo4j.NewDriverWithContext(uri, neo4j.BasicAuth(user, password, ""))
	if err != nil {
		return nil, fmt.Errorf("neo4j: create driver: %w", err)
	}
	if err := driver.VerifyConnectivity(ctx); err != nil {
		_ = driver.Close(ctx)
		return nil, fmt.Errorf("neo4j: verify connectivity to %s: %w", uri, err)
	}
	if database == "" {
		database = "neo4j"
	}
	s := &Neo4jStore{driver: driver, database: database}
	if err := s.ensureSchema(ctx); err != nil {
		_ = driver.Close(ctx)
		return nil, err
	}
	return s, nil
}

func (s *Neo4jStore) ensureSchema(ctx context.Context) error {
	labels := []string{"User", "Group", "Computer", "Domain", "OU", "GPO", "Container", "Trust"}
	return s.write(ctx, func(tx neo4j.ManagedTransaction) error {
		for _, l := range labels {
			q := fmt.Sprintf("CREATE CONSTRAINT %s_id IF NOT EXISTS FOR (n:%s) REQUIRE n.id IS UNIQUE", l, l)
			if _, err := tx.Run(ctx, q, nil); err != nil {
				return err
			}
		}
		return nil
	})
}

func (s *Neo4jStore) write(ctx context.Context, fn func(tx neo4j.ManagedTransaction) error) error {
	session := s.driver.NewSession(ctx, neo4j.SessionConfig{DatabaseName: s.database, AccessMode: neo4j.AccessModeWrite})
	defer session.Close(ctx)
	_, err := session.ExecuteWrite(ctx, func(tx neo4j.ManagedTransaction) (any, error) {
		return nil, fn(tx)
	})
	return err
}

// UpsertNodes implements Store.
func (s *Neo4jStore) UpsertNodes(ctx context.Context, nodes []model.Node) error {
	if len(nodes) == 0 {
		return nil
	}
	return s.write(ctx, func(tx neo4j.ManagedTransaction) error {
		for _, n := range nodes {
			lbl, err := label(n.Kind)
			if err != nil {
				return err
			}
			q := fmt.Sprintf("MERGE (n:%s {id:$id}) SET n.name=$name, n.domain=$domain, n.sam=$sam, n.dn=$dn, n.props=$props", lbl)
			if _, err := tx.Run(ctx, q, map[string]any{
				"id": n.ID, "name": n.Name, "domain": n.Domain,
				"sam": n.SAMAccountName, "dn": n.DN, "props": toAnyMap(n.Props),
			}); err != nil {
				return err
			}
		}
		return nil
	})
}

// UpsertEdges implements Store.
func (s *Neo4jStore) UpsertEdges(ctx context.Context, edges []model.Edge) error {
	if len(edges) == 0 {
		return nil
	}
	return s.write(ctx, func(tx neo4j.ManagedTransaction) error {
		for _, e := range edges {
			rt, err := relType(e.Kind)
			if err != nil {
				return err
			}
			q := fmt.Sprintf("MATCH (a {id:$src}), (b {id:$tgt}) MERGE (a)-[r:%s]->(b)", rt)
			if _, err := tx.Run(ctx, q, map[string]any{"src": e.Source, "tgt": e.Target}); err != nil {
				return err
			}
		}
		return nil
	})
}

// DeleteNode implements Store.
func (s *Neo4jStore) DeleteNode(ctx context.Context, id string) error {
	return s.write(ctx, func(tx neo4j.ManagedTransaction) error {
		_, err := tx.Run(ctx, "MATCH (n {id:$id}) DETACH DELETE n", map[string]any{"id": id})
		return err
	})
}

// DeleteEdge implements Store.
func (s *Neo4jStore) DeleteEdge(ctx context.Context, source, target string, kind model.EdgeKind) error {
	rt, err := relType(kind)
	if err != nil {
		return err
	}
	q := fmt.Sprintf("MATCH (a {id:$src})-[r:%s]->(b {id:$tgt}) DELETE r", rt)
	return s.write(ctx, func(tx neo4j.ManagedTransaction) error {
		_, err := tx.Run(ctx, q, map[string]any{"src": source, "tgt": target})
		return err
	})
}

// Neighbors implements Store (outgoing edges).
func (s *Neo4jStore) Neighbors(ctx context.Context, id string) ([]model.Edge, error) {
	return s.edges(ctx, "MATCH (a {id:$id})-[r]->(b) RETURN a.id AS src, b.id AS tgt, type(r) AS kind", id)
}

// Incoming implements Store.
func (s *Neo4jStore) Incoming(ctx context.Context, id string) ([]model.Edge, error) {
	return s.edges(ctx, "MATCH (a)-[r]->(b {id:$id}) RETURN a.id AS src, b.id AS tgt, type(r) AS kind", id)
}

func (s *Neo4jStore) edges(ctx context.Context, query, id string) ([]model.Edge, error) {
	session := s.driver.NewSession(ctx, neo4j.SessionConfig{DatabaseName: s.database, AccessMode: neo4j.AccessModeRead})
	defer session.Close(ctx)
	v, err := session.ExecuteRead(ctx, func(tx neo4j.ManagedTransaction) (any, error) {
		r, err := tx.Run(ctx, query, map[string]any{"id": id})
		if err != nil {
			return nil, err
		}
		var out []model.Edge
		for r.Next(ctx) {
			rec := r.Record()
			out = append(out, model.Edge{
				Source: asString(rec, "src"),
				Target: asString(rec, "tgt"),
				Kind:   model.EdgeKind(asString(rec, "kind")),
			})
		}
		return out, r.Err()
	})
	if err != nil {
		return nil, err
	}
	edges, _ := v.([]model.Edge)
	sort.Slice(edges, func(i, j int) bool {
		if edges[i].Source != edges[j].Source {
			return edges[i].Source < edges[j].Source
		}
		return edges[i].Kind < edges[j].Kind
	})
	return edges, nil
}

// AllNodes implements Store.
func (s *Neo4jStore) AllNodes(ctx context.Context) ([]model.Node, error) {
	session := s.driver.NewSession(ctx, neo4j.SessionConfig{DatabaseName: s.database, AccessMode: neo4j.AccessModeRead})
	defer session.Close(ctx)
	v, err := session.ExecuteRead(ctx, func(tx neo4j.ManagedTransaction) (any, error) {
		r, err := tx.Run(ctx, "MATCH (n) RETURN n.id AS id, labels(n) AS labels, n.name AS name, n.domain AS domain, n.sam AS sam, n.dn AS dn, n.props AS props", nil)
		if err != nil {
			return nil, err
		}
		var out []model.Node
		for r.Next(ctx) {
			rec := r.Record()
			n := model.Node{
				ID:             asString(rec, "id"),
				Kind:           model.Kind(firstLabel(rec, "labels")),
				Name:           asString(rec, "name"),
				Domain:         asString(rec, "domain"),
				SAMAccountName: asString(rec, "sam"),
				DN:             asString(rec, "dn"),
				Props:          asStringMap(rec, "props"),
			}
			out = append(out, n)
		}
		return out, r.Err()
	})
	if err != nil {
		return nil, err
	}
	nodes, _ := v.([]model.Node)
	sort.Slice(nodes, func(i, j int) bool { return nodes[i].ID < nodes[j].ID })
	return nodes, nil
}

// AllEdges implements Store.
func (s *Neo4jStore) AllEdges(ctx context.Context) ([]model.Edge, error) {
	session := s.driver.NewSession(ctx, neo4j.SessionConfig{DatabaseName: s.database, AccessMode: neo4j.AccessModeRead})
	defer session.Close(ctx)
	v, err := session.ExecuteRead(ctx, func(tx neo4j.ManagedTransaction) (any, error) {
		r, err := tx.Run(ctx, "MATCH (a)-[r]->(b) RETURN a.id AS src, b.id AS tgt, type(r) AS kind", nil)
		if err != nil {
			return nil, err
		}
		var out []model.Edge
		for r.Next(ctx) {
			rec := r.Record()
			out = append(out, model.Edge{
				Source: asString(rec, "src"),
				Target: asString(rec, "tgt"),
				Kind:   model.EdgeKind(asString(rec, "kind")),
			})
		}
		return out, r.Err()
	})
	if err != nil {
		return nil, err
	}
	edges, _ := v.([]model.Edge)
	return edges, nil
}

// Stats implements Store.
func (s *Neo4jStore) Stats(ctx context.Context) (Stats, error) {
	session := s.driver.NewSession(ctx, neo4j.SessionConfig{DatabaseName: s.database, AccessMode: neo4j.AccessModeRead})
	defer session.Close(ctx)
	v, err := session.ExecuteRead(ctx, func(tx neo4j.ManagedTransaction) (any, error) {
		var st Stats
		r1, err := tx.Run(ctx, "MATCH (n) RETURN count(n) AS c", nil)
		if err != nil {
			return nil, err
		}
		if r1.Next(ctx) {
			st.Nodes = asInt(r1.Record(), "c")
		}
		r2, err := tx.Run(ctx, "MATCH ()-[r]->() RETURN count(r) AS c", nil)
		if err != nil {
			return nil, err
		}
		if r2.Next(ctx) {
			st.Edges = asInt(r2.Record(), "c")
		}
		return st, nil
	})
	if err != nil {
		return Stats{}, err
	}
	st, _ := v.(Stats)
	return st, nil
}

// Close implements Store.
func (s *Neo4jStore) Close(ctx context.Context) error { return s.driver.Close(ctx) }

// ---- value helpers ----

func asString(rec *neo4j.Record, key string) string {
	v, ok := rec.Get(key)
	if !ok || v == nil {
		return ""
	}
	s, _ := v.(string)
	return s
}

func asInt(rec *neo4j.Record, key string) int {
	v, ok := rec.Get(key)
	if !ok || v == nil {
		return 0
	}
	switch n := v.(type) {
	case int64:
		return int(n)
	case int:
		return n
	case float64:
		return int(n)
	default:
		return 0
	}
}

func firstLabel(rec *neo4j.Record, key string) string {
	v, ok := rec.Get(key)
	if !ok {
		return ""
	}
	labels, ok := v.([]any)
	if !ok || len(labels) == 0 {
		return ""
	}
	s, _ := labels[0].(string)
	return s
}

func asStringMap(rec *neo4j.Record, key string) map[string]string {
	v, ok := rec.Get(key)
	if !ok || v == nil {
		return nil
	}
	raw, ok := v.(map[string]any)
	if !ok {
		return nil
	}
	out := make(map[string]string, len(raw))
	for k, val := range raw {
		if s, ok := val.(string); ok {
			out[k] = s
		} else if val != nil {
			out[k] = fmt.Sprint(val)
		}
	}
	return out
}

func toAnyMap(m map[string]string) map[string]any {
	if m == nil {
		return nil
	}
	out := make(map[string]any, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}

var _ Store = (*Neo4jStore)(nil)
