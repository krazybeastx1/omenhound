package api

import (
	"errors"
	"net/http"
	"strconv"
	"strings"

	"github.com/krazybeastx1/omenhound/internal/audit"
	"github.com/krazybeastx1/omenhound/internal/graph"
	"github.com/krazybeastx1/omenhound/internal/ingest"
)

// This file adds the ingestion-management API: scoped import previews, batch
// history and the scoped deletions. Every destructive endpoint requires the
// write token, an explicit confirmation and a preview token so the graph cannot
// change underneath a confirmed operation.

// ingestManager returns the store's provenance manager or writes a 501 when the
// backend cannot track batch provenance. Deletion is never faked: a backend
// without provenance reports that it cannot scope a deletion safely.
func (s *Server) ingestManager(w http.ResponseWriter) (graph.IngestManager, bool) {
	im, ok := s.store.(graph.IngestManager)
	if !ok {
		writeErr(w, http.StatusNotImplemented, "this graph backend does not track ingestion provenance, so scoped deletion is unavailable")
		return nil, false
	}
	return im, true
}

func writeStoreErr(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, graph.ErrBatchNotFound), errors.Is(err, graph.ErrDomainNotFound):
		writeErr(w, http.StatusNotFound, err.Error())
	case errors.Is(err, graph.ErrStalePreview):
		writeErr(w, http.StatusConflict, err.Error())
	case errors.Is(err, graph.ErrNotImplemented):
		writeErr(w, http.StatusNotImplemented, err.Error())
	default:
		writeErr(w, http.StatusBadRequest, err.Error())
	}
}

// handleIngestPreview validates an upload against a domain scope without
// writing anything.
func (s *Server) handleIngestPreview(w http.ResponseWriter, r *http.Request) {
	if !s.requireWrite(w, r) {
		return
	}
	q := r.URL.Query()
	sc := ingest.Scope{Domain: q.Get("domain"), OnMismatch: q.Get("on_mismatch")}
	switch strings.ToLower(strings.TrimSpace(q.Get("unknown"))) {
	case "", "keep", "reject":
		sc.StampUnknown = false
	case "stamp", "assign":
		sc.StampUnknown = true
	default:
		writeErr(w, http.StatusBadRequest, "unknown= must be keep or stamp")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 512<<20)
	g, err := ingest.DecodeStrict(r.Body)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	prev, _, err := ingest.PlanScoped(g, sc)
	if err != nil {
		// A domain mismatch is a validation result, not a server fault: return
		// it with the preview so the UI can show what would be skipped.
		writeJSON(w, http.StatusUnprocessableEntity, map[string]any{"error": err.Error(), "preview": prev})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"preview": prev})
}

// handleListBatches returns ingestion history, newest first.
func (s *Server) handleListBatches(w http.ResponseWriter, r *http.Request) {
	im, ok := s.ingestManager(w)
	if !ok {
		return
	}
	batches, err := im.ListBatches(r.Context())
	if err != nil {
		writeStoreErr(w, err)
		return
	}
	if batches == nil {
		batches = []graph.IngestBatch{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"batches": batches})
}

// handleGetBatch returns one batch's metadata.
func (s *Server) handleGetBatch(w http.ResponseWriter, r *http.Request) {
	im, ok := s.ingestManager(w)
	if !ok {
		return
	}
	b, found, err := im.GetBatch(r.Context(), r.PathValue("id"))
	if err != nil {
		writeStoreErr(w, err)
		return
	}
	if !found {
		writeErr(w, http.StatusNotFound, graph.ErrBatchNotFound.Error())
		return
	}
	writeJSON(w, http.StatusOK, b)
}

// handleBatchDeletePreview computes the impact of deleting one batch.
func (s *Server) handleBatchDeletePreview(w http.ResponseWriter, r *http.Request) {
	if !s.requireWrite(w, r) {
		return
	}
	im, ok := s.ingestManager(w)
	if !ok {
		return
	}
	prev, err := im.PreviewDeleteBatch(r.Context(), r.PathValue("id"))
	if err != nil {
		writeStoreErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, prev)
}

// handleBatchDelete deletes the records solely owned by one batch.
func (s *Server) handleBatchDelete(w http.ResponseWriter, r *http.Request) {
	if !s.requireWrite(w, r) {
		return
	}
	if !requireConfirm(w, r) {
		return
	}
	im, ok := s.ingestManager(w)
	if !ok {
		return
	}
	id := r.PathValue("id")
	res, err := im.DeleteBatch(r.Context(), id, r.URL.Query().Get("token"))
	if err != nil {
		s.audit.Log(audit.Event{Actor: "api", Action: "ingest.batch.delete", Target: id, Result: "error", Reason: err.Error(), RemoteAddr: r.RemoteAddr})
		writeStoreErr(w, err)
		return
	}
	s.audit.Log(audit.Event{Actor: "api", Action: "ingest.batch.delete", Target: id, Result: "ok", RemoteAddr: r.RemoteAddr,
		Fields: map[string]string{"nodes": strconv.Itoa(res.DeletedNodes), "edges": strconv.Itoa(res.DeletedEdges)}})
	writeJSON(w, http.StatusOK, res)
}

// domainSummary is one row of the ingestion-management domain list.
type domainSummary struct {
	Domain  string `json:"domain"`
	Nodes   int    `json:"nodes"`
	Edges   int    `json:"edges"`
	Batches int    `json:"batches"`
}

// handleIngestDomains lists domains with node/edge/batch counts.
func (s *Server) handleIngestDomains(w http.ResponseWriter, r *http.Request) {
	names, err := s.store.Domains(r.Context())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	counts := map[string]graph.Stats{}
	if dc, ok := s.store.(graph.DomainCounter); ok {
		if c, err := dc.DomainCounts(r.Context()); err == nil {
			counts = c
		}
	} else {
		counts = s.computeDomainCounts(r)
	}
	batchCount := map[string]int{}
	if im, ok := s.store.(graph.IngestManager); ok {
		if bs, err := im.ListBatches(r.Context()); err == nil {
			for _, b := range bs {
				if b.Domain != "" {
					batchCount[b.Domain]++
				}
			}
		}
	}
	out := make([]domainSummary, 0, len(names))
	for _, d := range names {
		st := counts[d]
		out = append(out, domainSummary{Domain: d, Nodes: st.Nodes, Edges: st.Edges, Batches: batchCount[d]})
	}
	writeJSON(w, http.StatusOK, map[string]any{"domains": out})
}

func (s *Server) computeDomainCounts(r *http.Request) map[string]graph.Stats {
	out := map[string]graph.Stats{}
	nodes, err := s.store.AllNodes(r.Context())
	if err != nil {
		return out
	}
	dom := make(map[string]string, len(nodes))
	for _, n := range nodes {
		d := strings.TrimSpace(n.Domain)
		dom[n.ID] = strings.ToLower(d)
		if d == "" {
			continue
		}
		st := out[d]
		st.Nodes++
		out[d] = st
	}
	edges, err := s.store.AllEdges(r.Context())
	if err != nil {
		return out
	}
	for _, e := range edges {
		ds := dom[e.Source]
		if ds == "" || ds != dom[e.Target] {
			continue
		}
		for k, v := range out {
			if strings.ToLower(k) == ds {
				v.Edges++
				out[k] = v
				break
			}
		}
	}
	return out
}

// handleDomainDeletePreview computes the impact of deleting one domain's data.
func (s *Server) handleDomainDeletePreview(w http.ResponseWriter, r *http.Request) {
	if !s.requireWrite(w, r) {
		return
	}
	im, ok := s.ingestManager(w)
	if !ok {
		return
	}
	prev, err := im.PreviewDeleteDomain(r.Context(), r.PathValue("domain"))
	if err != nil {
		writeStoreErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, prev)
}

// handleDomainDelete deletes the imported data belonging to one domain.
func (s *Server) handleDomainDelete(w http.ResponseWriter, r *http.Request) {
	if !s.requireWrite(w, r) {
		return
	}
	if !requireConfirm(w, r) {
		return
	}
	im, ok := s.ingestManager(w)
	if !ok {
		return
	}
	domain := r.PathValue("domain")
	res, err := im.DeleteDomain(r.Context(), domain, r.URL.Query().Get("token"))
	if err != nil {
		s.audit.Log(audit.Event{Actor: "api", Action: "ingest.domain.delete", Target: domain, Result: "error", Reason: err.Error(), RemoteAddr: r.RemoteAddr})
		writeStoreErr(w, err)
		return
	}
	s.audit.Log(audit.Event{Actor: "api", Action: "ingest.domain.delete", Target: domain, Result: "ok", RemoteAddr: r.RemoteAddr,
		Fields: map[string]string{"nodes": strconv.Itoa(res.DeletedNodes), "edges": strconv.Itoa(res.DeletedEdges)}})
	writeJSON(w, http.StatusOK, res)
}

type recordDeleteReq struct {
	Scope    string   `json:"scope"`
	Target   string   `json:"target"`
	NodeIDs  []string `json:"node_ids"`
	EdgeKeys []string `json:"edge_keys"`
}

// handleRecordsDeletePreview validates a selected-record deletion.
func (s *Server) handleRecordsDeletePreview(w http.ResponseWriter, r *http.Request) {
	if !s.requireWrite(w, r) {
		return
	}
	im, ok := s.ingestManager(w)
	if !ok {
		return
	}
	var req recordDeleteReq
	if err := decodeJSON(w, r, &req, 1<<20); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid json: "+err.Error())
		return
	}
	prev, err := im.PreviewDeleteRecords(r.Context(), req.Scope, req.Target, req.NodeIDs, req.EdgeKeys)
	if err != nil {
		writeStoreErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, prev)
}

// handleRecordsDelete removes the validated subset of selected records.
func (s *Server) handleRecordsDelete(w http.ResponseWriter, r *http.Request) {
	if !s.requireWrite(w, r) {
		return
	}
	if !requireConfirm(w, r) {
		return
	}
	im, ok := s.ingestManager(w)
	if !ok {
		return
	}
	var req recordDeleteReq
	if err := decodeJSON(w, r, &req, 1<<20); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid json: "+err.Error())
		return
	}
	res, err := im.DeleteRecords(r.Context(), req.Scope, req.Target, req.NodeIDs, req.EdgeKeys, r.URL.Query().Get("token"))
	if err != nil {
		s.audit.Log(audit.Event{Actor: "api", Action: "ingest.records.delete", Target: req.Target, Result: "error", Reason: err.Error(), RemoteAddr: r.RemoteAddr})
		writeStoreErr(w, err)
		return
	}
	s.audit.Log(audit.Event{Actor: "api", Action: "ingest.records.delete", Target: req.Target, Result: "ok", RemoteAddr: r.RemoteAddr,
		Fields: map[string]string{"nodes": strconv.Itoa(res.DeletedNodes), "edges": strconv.Itoa(res.DeletedEdges)}})
	writeJSON(w, http.StatusOK, res)
}

// requireConfirm enforces the ?confirm=true guard shared by destructive calls.
func requireConfirm(w http.ResponseWriter, r *http.Request) bool {
	switch strings.ToLower(strings.TrimSpace(r.URL.Query().Get("confirm"))) {
	case "true", "yes", "1":
		return true
	default:
		writeErr(w, http.StatusBadRequest, "confirmation required: re-send with ?confirm=true")
		return false
	}
}
