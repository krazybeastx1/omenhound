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
