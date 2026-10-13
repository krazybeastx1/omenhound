package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/krazybeastx1/omenhound/internal/graph"
	"github.com/krazybeastx1/omenhound/pkg/model"
)

func seeded(t *testing.T) *graph.Memory {
	t.Helper()
	st := graph.NewMemory()
	ctx := context.Background()
	if err := st.UpsertNodes(ctx, []model.Node{
		{ID: "S-1-5-21-1-2-3-1103", Kind: model.KindUser, Name: "jdoe", SAMAccountName: "jdoe", Domain: "corp.local", DN: "CN=jdoe,DC=corp,DC=local"},
		{ID: "S-1-5-21-1-2-3-1003", Kind: model.KindComputer, Name: "WS01", SAMAccountName: "WS01$", Domain: "corp.local", DN: "CN=WS01,DC=corp,DC=local"},
	}); err != nil {
		t.Fatal(err)
	}
	if err := st.UpsertEdges(ctx, []model.Edge{{Source: "S-1-5-21-1-2-3-1103", Target: "S-1-5-21-1-2-3-1003", Kind: model.EdgeGenericAll}}); err != nil {
		t.Fatal(err)
	}
	return st
}

func newTestServer(t *testing.T) *Server {
	t.Helper()
	return New(Config{StoreIface: seeded(t), Version: "test", APIToken: "secret"})
}

func do(t *testing.T, h http.Handler, method, path, body string, headers map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	var r *http.Request
	if body == "" {
		r = httptest.NewRequest(method, path, nil)
	} else {
		r = httptest.NewRequest(method, path, strings.NewReader(body))
	}
	for k, v := range headers {
		r.Header.Set(k, v)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

func TestHealth(t *testing.T) {
	h := newTestServer(t).Handler()
	w := do(t, h, "GET", "/api/v1/health", "", nil)
	if w.Code != 200 {
		t.Fatalf("health status = %d", w.Code)
	}
	if !strings.Contains(w.Body.String(), `"status":"ok"`) {
		t.Fatalf("body = %s", w.Body.String())
	}
}

func TestStatsAndGraph(t *testing.T) {
	h := newTestServer(t).Handler()
	w := do(t, h, "GET", "/api/v1/stats", "", nil)
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"nodes":2`) {
		t.Fatalf("stats = %d %s", w.Code, w.Body.String())
	}
	w = do(t, h, "GET", "/api/v1/graph", "", nil)
	if w.Code != 200 || !strings.Contains(w.Body.String(), "GenericAll") {
		t.Fatalf("graph = %d %s", w.Code, w.Body.String())
	}
}

func TestStatsIncludesKindCounts(t *testing.T) {
	h := newTestServer(t).Handler()
	w := do(t, h, "GET", "/api/v1/stats", "", nil)
	if w.Code != 200 {
		t.Fatalf("stats status = %d", w.Code)
	}
	// encoding/json sorts map keys, so the ordering is stable.
	if !strings.Contains(w.Body.String(), `"kinds":{"Computer":1,"User":1}`) {
		t.Fatalf("stats kinds = %s", w.Body.String())
	}
}

func TestObjectsSort(t *testing.T) {
	h := newTestServer(t).Handler()
	// Unpaged store order is SID ascending: ...1003 (WS01) then ...1103 (jdoe).
	w := do(t, h, "GET", "/api/v1/objects?type=User", "", nil)
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"total":1`) {
		t.Fatalf("objects = %d %s", w.Code, w.Body.String())
	}
	w = do(t, h, "GET", "/api/v1/objects?sort=name", "", nil)
	if w.Code != 200 {
		t.Fatalf("sorted objects = %d %s", w.Code, w.Body.String())
	}
	body := w.Body.String()
	// jdoe sorts before WS01, and the User node must appear first.
	if strings.Index(body, "jdoe") > strings.Index(body, "WS01") {
		t.Fatalf("sort=name did not order by name: %s", body)
	}
}

func TestObjectsSortIsStableWithUnknownKey(t *testing.T) {
	h := newTestServer(t).Handler()
	w := do(t, h, "GET", "/api/v1/objects?sort=bogus", "", nil)
	if w.Code != 200 {
		t.Fatalf("unknown sort must not error: %d %s", w.Code, w.Body.String())
	}
}

func TestObjectsAttributeFilter(t *testing.T) {
	st := graph.NewMemory()
	ctx := context.Background()
	if err := st.UpsertNodes(ctx, []model.Node{
		{ID: "A", Kind: model.KindUser, Name: "alice", Domain: "corp.local", Props: map[string]string{"enabled": "true"}},
		{ID: "B", Kind: model.KindUser, Name: "bob", Domain: "corp.local", Props: map[string]string{"enabled": "false"}},
	}); err != nil {
		t.Fatal(err)
	}
	h := New(Config{StoreIface: st, Version: "test"}).Handler()
	w := do(t, h, "GET", "/api/v1/objects?type=User&attr_enabled=true", "", nil)
	if w.Code != 200 {
		t.Fatalf("attr filter status = %d %s", w.Code, w.Body.String())
	}
	body := w.Body.String()
	if !strings.Contains(body, `"total":1`) || !strings.Contains(body, "alice") || strings.Contains(body, "bob") {
		t.Fatalf("attr_enabled=true filter = %s", body)
	}
}

func TestAbuseEndpoint(t *testing.T) {
	h := newTestServer(t).Handler()
	w := do(t, h, "GET", "/api/v1/abuse?src=S-1-5-21-1-2-3-1103&kind=GenericAll&dst=S-1-5-21-1-2-3-1003", "", nil)
	if w.Code != 200 {
		t.Fatalf("abuse status = %d %s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "jdoe") || !strings.Contains(w.Body.String(), "opsec") {
		t.Fatalf("abuse body = %s", w.Body.String())
	}
}

func TestIngestAuthRequired(t *testing.T) {
	h := newTestServer(t).Handler()
	w := do(t, h, "POST", "/api/v1/ingest", `{"nodes":[],"edges":[]}`, nil)
	if w.Code != 401 {
		t.Fatalf("expected 401 without token, got %d", w.Code)
	}
	w = do(t, h, "POST", "/api/v1/ingest", `{"nodes":[{"id":"X","kind":"User"}],"edges":[]}`,
		map[string]string{"Authorization": "Bearer secret"})
	if w.Code != 200 {
		t.Fatalf("expected 200 with token, got %d %s", w.Code, w.Body.String())
	}
}

func TestCredentialOpsDisabledByDefault(t *testing.T) {
	h := newTestServer(t).Handler()
	w := do(t, h, "POST", "/api/v1/credentials", `{"domain":"d","username":"u","password":"p"}`,
		map[string]string{"Authorization": "Bearer secret"})
	if w.Code != 403 {
		t.Fatalf("expected 403 when credential-ops disabled, got %d", w.Code)
	}
}

func TestWriteDisabledWithoutToken(t *testing.T) {
	h := New(Config{StoreIface: seeded(t), Version: "test"}).Handler()
	w := do(t, h, "POST", "/api/v1/ingest", `{"nodes":[],"edges":[]}`,
		map[string]string{"Authorization": "Bearer whatever"})
	if w.Code != 403 {
		t.Fatalf("expected 403 when no token configured, got %d", w.Code)
	}
}

func TestClearGraphAuthRequired(t *testing.T) {
	srv := newTestServer(t)
	h := srv.Handler()
	w := do(t, h, "DELETE", "/api/v1/graph?confirm=true", "", nil)
	if w.Code != 401 {
		t.Fatalf("expected 401 without token, got %d %s", w.Code, w.Body.String())
	}
	// The store must be untouched by a denied request.
	if st, _ := srv.store.Stats(context.Background()); st.Nodes != 2 {
		t.Fatalf("nodes = %d, want 2 (denied clear must not mutate)", st.Nodes)
	}
}

func TestClearGraphRequiresConfirm(t *testing.T) {
	srv := newTestServer(t)
	h := srv.Handler()
	auth := map[string]string{"Authorization": "Bearer secret"}
	w := do(t, h, "DELETE", "/api/v1/graph", "", auth)
	if w.Code != 400 {
		t.Fatalf("expected 400 without confirm, got %d %s", w.Code, w.Body.String())
	}
	if st, _ := srv.store.Stats(context.Background()); st.Nodes != 2 {
		t.Fatalf("nodes = %d, want 2 (unconfirmed clear must not mutate)", st.Nodes)
	}
}

func TestClearGraphEmptiesStore(t *testing.T) {
	srv := newTestServer(t)
	h := srv.Handler()
	w := do(t, h, "DELETE", "/api/v1/graph?confirm=true", "", map[string]string{"Authorization": "Bearer secret"})
	if w.Code != 200 {
		t.Fatalf("clear status = %d %s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), `"cleared":true`) {
		t.Fatalf("body = %s", w.Body.String())
	}
	if st, _ := srv.store.Stats(context.Background()); st.Nodes != 0 || st.Edges != 0 {
		t.Fatalf("stats after clear = %+v, want 0/0", st)
	}
	// The read API must now report an empty graph.
	w = do(t, h, "GET", "/api/v1/stats", "", nil)
	if !strings.Contains(w.Body.String(), `"nodes":0`) {
		t.Fatalf("stats body = %s", w.Body.String())
	}
}

func TestIngestModeReplaceReplacesGraph(t *testing.T) {
	srv := newTestServer(t)
	h := srv.Handler()
	body := `{"nodes":[{"id":"Z","kind":"Computer","name":"NEWPC"}],"edges":[]}`
	w := do(t, h, "POST", "/api/v1/ingest?mode=replace", body,
		map[string]string{"Authorization": "Bearer secret"})
	if w.Code != 200 {
		t.Fatalf("replace ingest status = %d %s", w.Code, w.Body.String())
	}
	// The original seeded nodes must be gone.
	if st, _ := srv.store.Stats(context.Background()); st.Nodes != 1 {
		t.Fatalf("nodes = %d, want 1 (old graph replaced)", st.Nodes)
	}
	if _, ok, _ := srv.store.GetNode(context.Background(), "S-1-5-21-1-2-3-1103"); ok {
		t.Fatal("seed node survived replace-mode ingest")
	}
}

func TestIngestModeMergeIsDefault(t *testing.T) {
	srv := newTestServer(t)
	h := srv.Handler()
	body := `{"nodes":[{"id":"Z","kind":"Computer","name":"NEWPC"}],"edges":[]}`
	w := do(t, h, "POST", "/api/v1/ingest", body,
		map[string]string{"Authorization": "Bearer secret"})
	if w.Code != 200 {
		t.Fatalf("merge ingest status = %d %s", w.Code, w.Body.String())
	}
	if st, _ := srv.store.Stats(context.Background()); st.Nodes != 3 {
		t.Fatalf("nodes = %d, want 3 (merge keeps existing)", st.Nodes)
	}
}

func TestIngestRejectsUnknownMode(t *testing.T) {
	srv := newTestServer(t)
	h := srv.Handler()
	body := `{"nodes":[{"id":"Z","kind":"Computer"}],"edges":[]}`
	w := do(t, h, "POST", "/api/v1/ingest?mode=wipe", body,
		map[string]string{"Authorization": "Bearer secret"})
	if w.Code != 400 {
		t.Fatalf("unknown mode status = %d, want 400", w.Code)
	}
	// A rejected mode must not have touched the store.
	if st, _ := srv.store.Stats(context.Background()); st.Nodes != 2 {
		t.Fatalf("nodes = %d, want 2 (invalid mode must not mutate)", st.Nodes)
	}
}
