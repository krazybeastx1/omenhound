// Package api exposes OmenHound's graph and, when explicitly enabled, its
// gated credential-change action over HTTP. Every write endpoint requires a
// bearer token and is fully audited.
package api

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"log"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/krazybeastx1/omenhound/internal/abuse"
	"github.com/krazybeastx1/omenhound/internal/act"
	"github.com/krazybeastx1/omenhound/internal/audit"
	"github.com/krazybeastx1/omenhound/internal/creds"
	"github.com/krazybeastx1/omenhound/internal/graph"
	"github.com/krazybeastx1/omenhound/internal/ingest"
	"github.com/krazybeastx1/omenhound/pkg/model"
	"github.com/krazybeastx1/omenhound/web"
)

// PasswordChanger is the AD write action, injected so the API can be tested
// without a domain.
type PasswordChanger func(ctx context.Context, o act.Options, targetDN string, newPassword []byte) error

// Config wires the server's dependencies.
type Config struct {
	Store      *graph.Memory // fallback store used only if StoreIface is nil
	StoreIface graph.Store

	Creds *creds.Store
	Audit *audit.Logger

	Version string

	// APIToken gates all write endpoints. If empty, writes are refused.
	APIToken string
	// EnableCredentialOps enables the AD password-change endpoint (off by
	// default; lab/authorized use only).
	EnableCredentialOps bool
	// ChangePassword performs the AD write. Required when EnableCredentialOps.
	ChangePassword PasswordChanger
	// ActServer is the DC host used for credential operations.
	ActServer string
	// ActInsecureSkipVerify disables TLS verification for the AD write (lab only).
	ActInsecureSkipVerify bool

	// WriteRatePerMinute / WriteBurst tune the write-API rate limiter.
	// Zero values select safe defaults (120/min, burst 30).
	WriteRatePerMinute int
	WriteBurst         int

	// Logger for request logging; defaults to stderr.
	Logger *log.Logger
}

// Server is the HTTP handler for OmenHound.
type Server struct {
	cfg     Config
	store   graph.Store
	creds   *creds.Store
	audit   *audit.Logger
	log     *log.Logger
	limiter *rateLimiter
}

// New builds a Server, filling defaults.
func New(cfg Config) *Server {
	store := cfg.StoreIface
	if store == nil && cfg.Store != nil {
		store = cfg.Store
	}
	if store == nil {
		store = graph.NewMemory()
	}
	c := cfg.Creds
	if c == nil {
		c = creds.NewStore(15*time.Minute, 64)
	}
	a := cfg.Audit
	if a == nil {
		a = audit.New(io.Discard)
	}
	lg := cfg.Logger
	if lg == nil {
		lg = log.New(io.Discard, "", 0)
	}
	return &Server{cfg: cfg, store: store, creds: c, audit: a, log: lg,
		limiter: newRateLimiter(cfg.WriteRatePerMinute, cfg.WriteBurst)}
}

// Handler returns the routed, panic-safe HTTP handler.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("GET /api/v1/health", s.handleHealth)
	mux.HandleFunc("GET /api/v1/stats", s.handleStats)
	mux.HandleFunc("GET /api/v1/graph", s.handleGraph)
	mux.HandleFunc("GET /api/v1/nodes", s.handleNodes)
	mux.HandleFunc("GET /api/v1/edges", s.handleEdges)
	mux.HandleFunc("GET /api/v1/domains", s.handleDomains)
	mux.HandleFunc("GET /api/v1/trusts", s.handleTrusts)
	mux.HandleFunc("GET /api/v1/audit", s.handleAudit)
	mux.HandleFunc("GET /api/v1/objects", s.handleObjects)
	mux.HandleFunc("GET /api/v1/nodes/{id}", s.handleNode)
	mux.HandleFunc("GET /api/v1/objects/{id}", s.handleObject)
	mux.HandleFunc("GET /api/v1/objects/{id}/relationships", s.handleObjectRelationships)
	mux.HandleFunc("GET /api/v1/nodes/{id}/neighbors", s.handleNeighbors)
	mux.HandleFunc("GET /api/v1/paths/shortest", s.handlePathsShortest)
	mux.HandleFunc("POST /api/v1/paths/shortest", s.handlePathsShortest)
	mux.HandleFunc("GET /api/v1/abuse", s.handleAbuse)
	mux.HandleFunc("GET /api/v1/abuse/supported", s.handleAbuseSupported)

	mux.HandleFunc("POST /api/v1/ingest", s.handleIngest)
	mux.HandleFunc("POST /api/v1/credentials", s.handleCredentialPut)
	mux.HandleFunc("DELETE /api/v1/credentials/{id}", s.handleCredentialDelete)
	mux.HandleFunc("POST /api/v1/credentials/{id}/change-password", s.handleChangePassword)

	sub, err := fs.Sub(web.FS, "static")
	if err == nil {
		mux.Handle("/", http.FileServer(http.FS(sub)))
	}

	return securityHeaders(s.limiter.middleware(s.recover(mux)))
}

func (s *Server) recover(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		defer func() {
			if rec := recover(); rec != nil {
				s.log.Printf("PANIC %s %s: %v", r.Method, r.URL.Path, rec)
				writeErr(w, http.StatusInternalServerError, "internal error")
			}
			s.log.Printf("%s %s %s (%s)", r.Method, r.URL.Path, r.RemoteAddr, time.Since(start).Round(time.Millisecond))
		}()
		next.ServeHTTP(w, r)
	})
}

// ---- read handlers ----

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"status":                 "ok",
		"version":                s.cfg.Version,
		"credential_ops_enabled": s.cfg.EnableCredentialOps,
		"write_api_enabled":      s.cfg.APIToken != "",
		"time":                   time.Now().UTC(),
	})
}

func (s *Server) handleStats(w http.ResponseWriter, r *http.Request) {
	st, err := s.store.Stats(r.Context())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	// Per-kind totals so the Overview and Path Explorer render real counts
	// without shipping the entire graph to the browser. SearchNodes with a
	// limit of 1 returns the cheap count(*) for both backends.
	kinds := make(map[string]int, len(model.AllKinds()))
	for _, k := range model.AllKinds() {
		_, total, err := s.store.SearchNodes(r.Context(), "", k, "", 1, 0)
		if err != nil {
			writeErr(w, http.StatusInternalServerError, err.Error())
			return
		}
		if total > 0 {
			kinds[string(k)] = total
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"nodes": st.Nodes,
		"edges": st.Edges,
		"kinds": kinds,
	})
}

func (s *Server) handleGraph(w http.ResponseWriter, r *http.Request) {
	nodes, err := s.store.AllNodes(r.Context())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	edges, err := s.store.AllEdges(r.Context())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"nodes": nodes, "edges": edges})
}

// defaultPageLimit / maxPageLimit bound list endpoints so a large graph cannot
// exhaust a browser or a client in one response.
const (
	defaultPageLimit = 1000
	maxPageLimit     = 10000
)

// pageParams reads limit/offset query parameters with safe defaults.
func pageParams(r *http.Request) (limit, offset int) {
	limit, offset = defaultPageLimit, 0
	if v := r.URL.Query().Get("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			limit = min(n, maxPageLimit)
		}
	}
	if v := r.URL.Query().Get("offset"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			offset = n
		}
	}
	return limit, offset
}

func page[T any](items []T, limit, offset int) []T {
	if offset >= len(items) {
		return []T{}
	}
	end := min(offset+limit, len(items))
	return items[offset:end]
}

func (s *Server) handleNodes(w http.ResponseWriter, r *http.Request) {
	limit, offset := pageParams(r)
	nodes, err := s.store.AllNodes(r.Context())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"total": len(nodes), "limit": limit, "offset": offset,
		"nodes": page(nodes, limit, offset),
	})
}

func (s *Server) handleEdges(w http.ResponseWriter, r *http.Request) {
	limit, offset := pageParams(r)
	edges, err := s.store.AllEdges(r.Context())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"total": len(edges), "limit": limit, "offset": offset,
		"edges": page(edges, limit, offset),
	})
}

func (s *Server) handleNode(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	n, ok, err := s.store.GetNode(r.Context(), id)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if !ok {
		writeErr(w, http.StatusNotFound, "node not found")
		return
	}
	writeJSON(w, http.StatusOK, n)
}

func (s *Server) handleNeighbors(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	out, err := s.store.Neighbors(r.Context(), id)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	in, err := s.store.Incoming(r.Context(), id)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"outgoing": out, "incoming": in})
}

func (s *Server) handleAbuseSupported(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"edges": abuse.Supported()})
}

func (s *Server) handleAbuse(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	srcID, kind, dstID := q.Get("src"), q.Get("kind"), q.Get("dst")
	if srcID == "" || kind == "" || dstID == "" {
		writeErr(w, http.StatusBadRequest, "src, kind and dst query parameters are required")
		return
	}
	src, ok, err := s.store.GetNode(r.Context(), srcID)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if !ok {
		writeErr(w, http.StatusNotFound, "source node not found")
		return
	}
	dst, ok, err := s.store.GetNode(r.Context(), dstID)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if !ok {
		writeErr(w, http.StatusNotFound, "target node not found")
		return
	}
	edge := model.Edge{Source: srcID, Target: dstID, Kind: model.EdgeKind(kind)}
	rendered, ok := abuse.Render(edge, src, dst)
	if !ok {
		writeErr(w, http.StatusNotFound, "no abuse template for edge kind "+kind)
		return
	}
	writeJSON(w, http.StatusOK, rendered)
}

// ---- write handlers ----

// requireWrite enforces the bearer token. It returns false and writes a
// response when the request must not proceed.
func (s *Server) requireWrite(w http.ResponseWriter, r *http.Request) bool {
	if s.cfg.APIToken == "" {
		writeErr(w, http.StatusForbidden, "write API is disabled: start the server with --api-token to enable it")
		return false
	}
	got := strings.TrimSpace(strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "))
	if got == "" || subtle.ConstantTimeCompare([]byte(got), []byte(s.cfg.APIToken)) != 1 {
		s.audit.Log(audit.Event{Actor: "unknown", Action: "auth", Target: r.URL.Path, Result: "denied", Reason: "bad or missing bearer token", RemoteAddr: r.RemoteAddr})
		writeErr(w, http.StatusUnauthorized, "unauthorized")
		return false
	}
	return true
}

func (s *Server) handleIngest(w http.ResponseWriter, r *http.Request) {
	if !s.requireWrite(w, r) {
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 512<<20)
	g, err := ingest.DecodeStrict(r.Body)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	res, err := ingest.Write(r.Context(), s.store, g)
	if err != nil {
		s.audit.Log(audit.Event{Actor: "api", Action: "ingest", Result: "error", Reason: err.Error(), RemoteAddr: r.RemoteAddr})
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	s.audit.Log(audit.Event{Actor: "api", Action: "ingest", Result: "ok", RemoteAddr: r.RemoteAddr,
		Fields: map[string]string{"nodes": strconv.Itoa(res.Nodes), "edges": strconv.Itoa(res.Edges)}})
	writeJSON(w, http.StatusOK, res)
}

type credPutReq struct {
	Domain   string `json:"domain"`
	Username string `json:"username"`
	Password string `json:"password"`
}

func (s *Server) handleCredentialPut(w http.ResponseWriter, r *http.Request) {
	if !s.requireWrite(w, r) {
		return
	}
	if !s.cfg.EnableCredentialOps {
		writeErr(w, http.StatusForbidden, "credential operations are disabled (start with --enable-credential-ops on an authorized lab)")
		return
	}
	var req credPutReq
	if err := decodeJSON(w, r, &req, 1<<20); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid json: "+err.Error())
		return
	}
	secret := []byte(req.Password)
	id, exp, err := s.creds.Put(req.Domain, req.Username, secret)
	creds.Zero(secret)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	s.audit.Log(audit.Event{Actor: "api", Action: "credential.put", Target: req.Domain + "\\" + req.Username, Result: "ok", RemoteAddr: r.RemoteAddr})
	writeJSON(w, http.StatusCreated, map[string]any{"session_id": id, "expires": exp})
}

func (s *Server) handleCredentialDelete(w http.ResponseWriter, r *http.Request) {
	if !s.requireWrite(w, r) {
		return
	}
	id := r.PathValue("id")
	s.creds.Delete(id)
	s.audit.Log(audit.Event{Actor: "api", Action: "credential.delete", Target: id, Result: "ok", RemoteAddr: r.RemoteAddr})
	writeJSON(w, http.StatusOK, map[string]any{"deleted": id})
}

type changePwReq struct {
	TargetDN    string `json:"target_dn"`
	TargetSID   string `json:"target_sid"`
	NewPassword string `json:"new_password"`
	Reason      string `json:"reason"`
}

func (s *Server) handleChangePassword(w http.ResponseWriter, r *http.Request) {
	if !s.requireWrite(w, r) {
		return
	}
	id := r.PathValue("id")
	if !s.cfg.EnableCredentialOps {
		writeErr(w, http.StatusForbidden, "credential operations are disabled")
		return
	}
	if s.cfg.ChangePassword == nil {
		writeErr(w, http.StatusNotImplemented, "no password changer configured")
		return
	}
	// Explicit per-action approval gate.
	if !strings.EqualFold(r.Header.Get("X-Omenhound-Approval"), "yes") {
		s.audit.Log(audit.Event{Actor: "api", Action: "credential.change_password", Target: id, Result: "denied", Reason: "missing X-Omenhound-Approval: yes", RemoteAddr: r.RemoteAddr})
		writeErr(w, http.StatusPreconditionRequired, "this action requires the header X-Omenhound-Approval: yes")
		return
	}
	var req changePwReq
	if err := decodeJSON(w, r, &req, 1<<20); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid json: "+err.Error())
		return
	}
	cred, err := s.creds.Take(id) // one-shot
	if err != nil {
		writeErr(w, http.StatusNotFound, err.Error())
		return
	}
	defer cred.Destroy()

	newPw := []byte(req.NewPassword)
	defer creds.Zero(newPw)

	o := act.Options{
		Server:             s.cfg.ActServer,
		Domain:             cred.Domain,
		Username:           cred.Username,
		Password:           cred.Reveal(),
		InsecureSkipVerify: s.cfg.ActInsecureSkipVerify,
	}
	err = s.cfg.ChangePassword(r.Context(), o, req.TargetDN, newPw)
	result := "ok"
	status := http.StatusOK
	if err != nil {
		result, status = "error", http.StatusBadGateway
	}
	s.audit.Log(audit.Event{
		Actor: "api", Action: "credential.change_password", Target: req.TargetDN,
		Result: result, Reason: req.Reason, RemoteAddr: r.RemoteAddr,
		Fields: map[string]string{"target_sid": req.TargetSID},
	})
	if err != nil {
		writeErr(w, status, err.Error())
		return
	}
	writeJSON(w, status, map[string]any{"changed": req.TargetDN, "target_sid": req.TargetSID})
}

// ---- helpers ----

var errTrailingJSON = errors.New("unexpected trailing JSON after request body")

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]any{"error": msg})
}

// decodeJSON decodes a bounded JSON body, rejecting unknown fields.
func decodeJSON(w http.ResponseWriter, r *http.Request, v any, max int64) error {
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, max))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return err
	}
	if dec.More() {
		return errTrailingJSON
	}
	return nil
}

func (s *Server) handleDomains(w http.ResponseWriter, r *http.Request) {
	domains, err := s.store.Domains(r.Context())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"domains": domains})
}

func (s *Server) handleTrusts(w http.ResponseWriter, r *http.Request) {
	trusts, err := s.store.Trusts(r.Context())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"trusts": trusts})
}

func (s *Server) handleAudit(w http.ResponseWriter, r *http.Request) {
	limit := 50
	if v := r.URL.Query().Get("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			limit = n
		}
	}
	events := s.audit.GetEvents(limit)
	writeJSON(w, http.StatusOK, map[string]any{"events": events})
}

func (s *Server) handleObjects(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	domain := q.Get("domain")
	kindStr := q.Get("type")
	search := q.Get("search")
	if search == "" {
		search = q.Get("q")
	}
	sortKey := q.Get("sort")
	limit, offset := pageParams(r)
	var kind model.Kind
	if kindStr != "" {
		kind = model.Kind(strings.TrimSpace(kindStr))
	}
	// Attribute filters arrive as attr_<prop>=<value> (e.g. attr_enabled=true,
	// attr_os=Windows 11). They are applied to collector props so new filters
	// need no schema change.
	attrs := map[string]string{}
	for k, v := range q {
		if name, ok := strings.CutPrefix(k, "attr_"); ok && name != "" && len(v) > 0 && v[0] != "" {
			attrs[name] = v[0]
		}
	}
	nodes, total, err := s.store.SearchNodes(r.Context(), search, kind, domain, limit, offset)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	// Sorting and attribute filtering need the full (unpaged) match set so that
	// totals and paging stay correct.
	if sortKey != "" || len(attrs) > 0 {
		all, _, err := s.store.SearchNodes(r.Context(), search, kind, domain, total, 0)
		if err != nil {
			writeErr(w, http.StatusInternalServerError, err.Error())
			return
		}
		if len(attrs) > 0 {
			all = filterByProps(all, attrs)
			total = len(all)
		}
		sortNodes(all, sortKey)
		nodes = page(all, limit, offset)
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"total":  total,
		"limit":  limit,
		"offset": offset,
		"nodes":  nodes,
	})
}

// filterByProps keeps nodes whose collector props match every requested value
// (case-insensitive). An empty filter returns the input unchanged.
func filterByProps(nodes []model.Node, attrs map[string]string) []model.Node {
	if len(attrs) == 0 {
		return nodes
	}
	out := make([]model.Node, 0, len(nodes))
	for _, n := range nodes {
		match := true
		for k, want := range attrs {
			got := ""
			if n.Props != nil {
				got = n.Props[k]
			}
			if !strings.EqualFold(strings.TrimSpace(got), strings.TrimSpace(want)) {
				match = false
				break
			}
		}
		if match {
			out = append(out, n)
		}
	}
	return out
}

// sortNodes orders nodes in place by an allowlisted UI sort key. Unknown or
// empty keys keep the store's natural SID ordering so the endpoint never
// rejects a request from the UI.
func sortNodes(nodes []model.Node, key string) {
	field := ""
	switch key {
	case "name":
		field = "name"
	case "sam":
		field = "sam"
	case "domain":
		field = "domain"
	case "dn":
		field = "dn"
	case "os":
		field = "os"
	case "guid":
		field = "guid"
	case "type":
		field = "type"
	default:
		return
	}
	value := func(n model.Node) string {
		switch field {
		case "name":
			return strings.ToLower(n.Name)
		case "sam":
			return strings.ToLower(n.SAMAccountName)
		case "domain":
			return strings.ToLower(n.Domain)
		case "dn":
			return strings.ToLower(n.DN)
		default:
			if n.Props == nil {
				return ""
			}
			return strings.ToLower(n.Props[field])
		}
	}
	sort.SliceStable(nodes, func(i, j int) bool {
		a, b := value(nodes[i]), value(nodes[j])
		if a == b {
			return nodes[i].ID < nodes[j].ID
		}
		return a < b
	})
}

func (s *Server) handleObject(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	n, ok, err := s.store.GetNode(r.Context(), id)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if !ok {
		writeErr(w, http.StatusNotFound, "object not found")
		return
	}
	writeJSON(w, http.StatusOK, n)
}

func (s *Server) handleObjectRelationships(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	out, err := s.store.Neighbors(r.Context(), id)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	in, err := s.store.Incoming(r.Context(), id)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"outgoing": out, "incoming": in})
}

type pathRequest struct {
	SourceID                    string           `json:"source_id"`
	TargetID                    string           `json:"target_id"`
	MaxDepth                    int              `json:"max_depth"`
	MaxPaths                    int              `json:"max_paths"`
	Direction                   string           `json:"direction"`
	IncludeNodeTypes            []model.Kind     `json:"include_node_types"`
	ExcludeNodeTypes            []model.Kind     `json:"exclude_node_types"`
	IncludeRelationshipTypes    []model.EdgeKind `json:"include_relationship_types"`
	ExcludeRelationshipTypes    []model.EdgeKind `json:"exclude_relationship_types"`
	RequiredIntermediateNodeIDs []string         `json:"required_intermediate_node_ids"`
}

func (s *Server) handlePathsShortest(w http.ResponseWriter, r *http.Request) {
	var req pathRequest
	if r.Method == http.MethodPost {
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeErr(w, http.StatusBadRequest, "invalid request body")
			return
		}
	} else {
		q := r.URL.Query()
		req.SourceID = q.Get("from")
		req.TargetID = q.Get("to")
		if md := q.Get("max_depth"); md != "" {
			v, _ := strconv.Atoi(md)
			req.MaxDepth = v
		}
		if mp := q.Get("max_paths"); mp != "" {
			v, _ := strconv.Atoi(mp)
			req.MaxPaths = v
		}
		req.Direction = q.Get("direction")
	}

	dir := graph.Outgoing
	switch strings.ToLower(req.Direction) {
	case "undirected":
		dir = graph.Undirected
	case "incoming":
		dir = graph.Incoming
	default:
		dir = graph.Outgoing
	}

	greq := graph.ShortestPathRequest{
		SourceID:                    req.SourceID,
		TargetID:                    req.TargetID,
		MaxDepth:                    req.MaxDepth,
		MaxPaths:                    req.MaxPaths,
		Direction:                   dir,
		IncludeNodeTypes:            req.IncludeNodeTypes,
		ExcludeNodeTypes:            req.ExcludeNodeTypes,
		IncludeRelationshipTypes:    req.IncludeRelationshipTypes,
		ExcludeRelationshipTypes:    req.ExcludeRelationshipTypes,
		RequiredIntermediateNodeIDs: req.RequiredIntermediateNodeIDs,
	}
	if greq.MaxDepth <= 0 {
		greq.MaxDepth = 5
	}
	if greq.MaxPaths <= 0 {
		greq.MaxPaths = 10
	}

	res, err := s.store.ShortestPaths(r.Context(), greq)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, res)
}
