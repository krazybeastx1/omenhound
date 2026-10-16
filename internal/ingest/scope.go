package ingest

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/krazybeastx1/omenhound/internal/graph"
	"github.com/krazybeastx1/omenhound/pkg/model"
)

// Scope constrains an ingestion to one explicitly selected domain. A zero Scope
// (empty Domain) keeps the historical behaviour: every domain present in the
// uploaded file is imported as-is.
type Scope struct {
	// Domain is the selected domain.
	Domain string
	// StampUnknown assigns Domain to entities that carry no domain of their own.
	// Off by default: an object present in a file is not assumed to belong to
	// the selected domain unless the data says so.
	StampUnknown bool
	// OnMismatch is "reject" (default) or "skip".
	OnMismatch string
}

// ScopedPreview describes what a domain-scoped ingestion would write.
type ScopedPreview struct {
	Domain          string   `json:"domain,omitempty"`
	Domains         []string `json:"domains"`
	Nodes           int      `json:"nodes"`
	Edges           int      `json:"edges"`
	AssignedNodes   int      `json:"assigned_nodes"`
	StampedNodes    int      `json:"stamped_nodes"`
	MismatchNodes   int      `json:"mismatch_nodes"`
	MismatchDomains []string `json:"mismatch_domains,omitempty"`
	SkippedNodes    int      `json:"skipped_nodes"`
	SkippedEdges    int      `json:"skipped_edges"`
	CrossDomainEdge int      `json:"cross_domain_edges"`
	SampleMismatch  []string `json:"sample_mismatch,omitempty"`
	Warnings        []string `json:"warnings,omitempty"`
}

// PlanScoped validates g against the scope and returns the filtered graph that
// would be written plus a preview. It never mutates its input.
func PlanScoped(g *model.Graph, sc Scope) (ScopedPreview, *model.Graph, error) {
	if g == nil {
		return ScopedPreview{}, nil, errors.New("ingest: nil graph")
	}
	onMismatch := strings.ToLower(strings.TrimSpace(sc.OnMismatch))
	if onMismatch == "" {
		onMismatch = "reject"
	}
	if onMismatch != "reject" && onMismatch != "skip" {
		return ScopedPreview{}, nil, fmt.Errorf("ingest: unknown on_mismatch %q (want reject or skip)", sc.OnMismatch)
	}
	domain := strings.TrimSpace(sc.Domain)

	out := &model.Graph{Meta: g.Meta}
	prev := ScopedPreview{Domain: domain}
	keep := make(map[string]bool, len(g.Nodes))
	wantDomain := domain != ""

	for _, n := range g.Nodes {
		if n.ID == "" {
			// Preserve the existing validation behaviour; Validate reports it.
			keep[n.ID] = true
			out.Nodes = append(out.Nodes, n)
			continue
		}
		nd := strings.TrimSpace(n.Domain)
		if !wantDomain {
			keep[n.ID] = true
			out.Nodes = append(out.Nodes, n)
			continue
		}
		switch {
		case strings.EqualFold(nd, domain):
			keep[n.ID] = true
			prev.AssignedNodes++
			out.Nodes = append(out.Nodes, n)
		case nd == "" && sc.StampUnknown:
			n.Domain = domain
			keep[n.ID] = true
			prev.StampedNodes++
			out.Nodes = append(out.Nodes, n)
		default:
			prev.MismatchNodes++
			label := nd
			if label == "" {
				label = "(no domain)"
			}
			if !containsString(prev.MismatchDomains, label) {
				prev.MismatchDomains = append(prev.MismatchDomains, label)
			}
			if len(prev.SampleMismatch) < 8 {
				prev.SampleMismatch = append(prev.SampleMismatch, n.ID)
			}
			if onMismatch == "skip" {
				prev.SkippedNodes++
				continue
			}
			// reject: keep it out of the write graph so Validate cannot pass and
			// the error message stays focused on the domain mismatch.
		}
	}

	if wantDomain && prev.MismatchNodes > 0 && onMismatch == "reject" {
		sort.Strings(prev.MismatchDomains)
		return prev, nil, fmt.Errorf(
			"ingest: %d node(s) do not belong to domain %q (found: %s); use the correct domain, enable stamping of unknown domains, or set on_mismatch=skip",
			prev.MismatchNodes, domain, strings.Join(prev.MismatchDomains, ", "))
	}

	for _, e := range g.Edges {
		if keep[e.Source] && keep[e.Target] {
			out.Edges = append(out.Edges, e)
		} else {
			prev.SkippedEdges++
		}
	}

	// Distinct domains actually present, and edges that cross domain boundaries.
	seen := map[string]string{}
	for _, n := range out.Nodes {
		d := strings.TrimSpace(n.Domain)
		if d == "" {
			continue
		}
		seen[strings.ToLower(d)] = d
	}
	if !wantDomain {
		for k := range seen {
			prev.Domains = append(prev.Domains, seen[k])
		}
	} else {
		prev.Domains = []string{domain}
	}
	sort.Strings(prev.Domains)

	domOf := make(map[string]string, len(out.Nodes))
	for _, n := range out.Nodes {
		domOf[n.ID] = strings.ToLower(strings.TrimSpace(n.Domain))
	}
	for _, e := range out.Edges {
		if domOf[e.Source] != domOf[e.Target] {
			prev.CrossDomainEdge++
		}
	}
	if prev.CrossDomainEdge > 0 {
		prev.Warnings = append(prev.Warnings, fmt.Sprintf("%d relationship(s) span two domains; they are kept because the source data identifies both endpoints.", prev.CrossDomainEdge))
	}
	if len(prev.Domains) > 1 && !wantDomain {
		prev.Warnings = append(prev.Warnings, "This file contains multiple domains; it will be imported as a multi-domain batch.")
	}
	prev.Nodes = len(out.Nodes)
	prev.Edges = len(out.Edges)

	if err := Validate(out); err != nil {
		return prev, nil, err
	}
	return prev, out, nil
}

func containsString(xs []string, s string) bool {
	for _, x := range xs {
		if x == s {
			return true
		}
	}
	return false
}

// ScopedResult extends Result with the batch metadata recorded for provenance.
type ScopedResult struct {
	Result
	Batch   *graph.IngestBatch `json:"batch,omitempty"`
	Scope   *ScopedPreview     `json:"scope,omitempty"`
	Tracked bool               `json:"tracked"`
}

// WriteScoped validates then writes g under the given scope and mode. When the
// store supports provenance, the write is recorded as a batch so it can later
// be inspected and (safely) removed.
func WriteScoped(ctx context.Context, st graph.Store, g *model.Graph, sc Scope, mode Mode, source string) (ScopedResult, error) {
	if mode == "" {
		mode = ModeMerge
	}
	// Attribute the batch to a source automatically when the caller did not
	// name one: the collector label distinguishes a native OmenHound collect
	// ("ldap", "sample", …) from an imported BloodHound dataset
	// ("bloodhound-import"), which is what lets the UI separate two datasets
	// that describe the same domain.
	if strings.TrimSpace(source) == "" {
		source = strings.TrimSpace(g.Meta.Collector)
	}
	prev, planned, err := PlanScoped(g, sc)
	if err != nil {
		return ScopedResult{}, err
	}

	if mode == ModeReplace {
		if strings.TrimSpace(sc.Domain) == "" {
			if err := st.Clear(ctx); err != nil {
				return ScopedResult{}, fmt.Errorf("ingest: clear: %w", err)
			}
		} else {
			im, ok := st.(graph.IngestManager)
			if !ok {
				return ScopedResult{}, errors.New("ingest: domain-scoped replace needs a store that tracks ingestion provenance (the in-memory store does)")
			}
			// Replace only the selected domain's data; other domains survive.
			p, perr := im.PreviewDeleteDomain(ctx, sc.Domain)
			if perr != nil && !errors.Is(perr, graph.ErrDomainNotFound) {
				return ScopedResult{}, fmt.Errorf("ingest: replace %s: %w", sc.Domain, perr)
			}
			if perr == nil {
				if _, derr := im.DeleteDomain(ctx, sc.Domain, p.Token); derr != nil {
					return ScopedResult{}, fmt.Errorf("ingest: replace %s: %w", sc.Domain, derr)
				}
			}
		}
	}

	res := ScopedResult{Tracked: false, Scope: &prev}
	im, tracked := st.(graph.IngestManager)
	if tracked {
		batch := &graph.IngestBatch{
			ID:        newBatchID(),
			Source:    source,
			Mode:      string(mode),
			Domain:    strings.TrimSpace(sc.Domain),
			Domains:   prev.Domains,
			Status:    "completed",
			CreatedAt: time.Now().UTC(),
		}
		if prev.MismatchNodes > 0 {
			batch.MismatchNodes = prev.MismatchNodes
			if prev.SkippedNodes > 0 {
				batch.Status = "partial"
			}
		}
		batch.NodesSkipped = prev.SkippedNodes
		batch.EdgesSkipped = prev.SkippedEdges
		if _, err := im.ApplyBatch(ctx, batch, planned.Nodes, planned.Edges); err != nil {
			batch.Status = "failed"
			batch.Errors = append(batch.Errors, err.Error())
			_, _ = im.ApplyBatch(ctx, batch, nil, nil)
			return ScopedResult{}, fmt.Errorf("ingest: apply batch: %w", err)
		}
		res.Tracked = true
		res.Batch = batch
	} else {
		if err := st.UpsertNodes(ctx, planned.Nodes); err != nil {
			return ScopedResult{}, fmt.Errorf("ingest: upsert nodes: %w", err)
		}
		if err := st.UpsertEdges(ctx, planned.Edges); err != nil {
			return ScopedResult{}, fmt.Errorf("ingest: upsert edges: %w", err)
		}
	}
	stats, err := st.Stats(ctx)
	if err != nil {
		return ScopedResult{}, fmt.Errorf("ingest: stats: %w", err)
	}
	res.Nodes = len(planned.Nodes)
	res.Edges = len(planned.Edges)
	res.Stats = stats
	return res, nil
}

// newBatchID returns a sortable, collision-resistant batch identifier.
func newBatchID() string {
	var b [5]byte
	_, _ = rand.Read(b[:])
	return "batch_" + time.Now().UTC().Format("20060102T150405.000") + "_" + hex.EncodeToString(b[:])
}
