package graph

import (
	"strings"

	"github.com/krazybeastx1/omenhound/pkg/model"
)

// Shared path-search limits and predicates. Keeping them in one place means the
// in-memory and Neo4j backends apply identical include/exclude semantics, and a
// hostile or accidental request cannot turn into an unbounded graph walk.
const (
	// maxPathLimit caps how many routes a single search may return, regardless
	// of what the caller asks for.
	maxPathLimit = 100
	// maxSearchExpansions caps breadth-first node expansions in the in-memory
	// backend so a dense graph degrades into a truncated result, not a hang.
	maxSearchExpansions = 20000
)

// relAllowed reports whether an edge kind passes the request's include/exclude
// relationship filters.
func relAllowed(kind model.EdgeKind, req ShortestPathRequest) bool {
	if len(req.IncludeRelationshipTypes) > 0 {
		ok := false
		for _, k := range req.IncludeRelationshipTypes {
			if k == kind {
				ok = true
				break
			}
		}
		if !ok {
			return false
		}
	}
	for _, k := range req.ExcludeRelationshipTypes {
		if k == kind {
			return false
		}
	}
	return true
}

// nodeAllowed reports whether a node passes the request's include/exclude node
// kind and domain filters.
func nodeAllowed(n model.Node, req ShortestPathRequest) bool {
	if len(req.IncludeNodeTypes) > 0 {
		ok := false
		for _, k := range req.IncludeNodeTypes {
			if k == n.Kind {
				ok = true
				break
			}
		}
		if !ok {
			return false
		}
	}
	for _, k := range req.ExcludeNodeTypes {
		if k == n.Kind {
			return false
		}
	}
	return domainAllowed(n.Domain, req)
}

// domainAllowed applies the domain include/exclude filters (case-insensitive).
func domainAllowed(domain string, req ShortestPathRequest) bool {
	if len(req.IncludeDomains) == 0 && len(req.ExcludeDomains) == 0 {
		return true
	}
	d := strings.ToLower(strings.TrimSpace(domain))
	if len(req.IncludeDomains) > 0 {
		ok := false
		for _, want := range req.IncludeDomains {
			if strings.EqualFold(strings.TrimSpace(want), d) {
				ok = true
				break
			}
		}
		if !ok {
			return false
		}
	}
	for _, no := range req.ExcludeDomains {
		if strings.EqualFold(strings.TrimSpace(no), d) {
			return false
		}
	}
	return true
}

// containsNode reports whether id appears in ids.
func containsNode(ids []string, id string) bool {
	for _, v := range ids {
		if v == id {
			return true
		}
	}
	return false
}

// hasRequired reports whether ids contains every required node.
func hasRequired(ids, required []string) bool {
	for _, r := range required {
		if !containsNode(ids, r) {
			return false
		}
	}
	return true
}

// kindFromLabelName is the inverse of label(): it maps a Neo4j node label back
// to a model.Kind. It returns "" for labels OmenHound did not write.
func kindFromLabelName(l string) model.Kind {
	for _, k := range model.AllKinds() {
		if lbl, err := label(k); err == nil && lbl == l {
			return k
		}
	}
	return ""
}
