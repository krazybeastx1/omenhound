package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/krazybeastx1/omenhound/internal/graph"
)

func mgmtServer(t *testing.T) *Server {
	t.Helper()
	return New(Config{StoreIface: graph.NewMemory(), Version: "test", APIToken: "secret"})
}

func authHdr() map[string]string { return map[string]string{"Authorization": "Bearer secret"} }

func decodeBody(t *testing.T, w *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &m); err != nil {
		t.Fatalf("decode body %q: %v", w.Body.String(), err)
	}
	return m
}

const corpIngest = `{"nodes":[{"id":"c1","kind":"User","name":"carol","domain":"corp.local"},{"id":"c2","kind":"Computer","name":"PC1","domain":"corp.local"}],"edges":[{"source":"c1","target":"c2","kind":"GenericAll"}]}`
const engIngest = `{"nodes":[{"id":"e1","kind":"User","name":"erin","domain":"eng.local"}],"edges":[]}`

func ingestDomain(t *testing.T, h http.Handler, domain, body string) map[string]any {
	t.Helper()
	w := do(t, h, "POST", "/api/v1/ingest?domain="+domain, body, authHdr())
	if w.Code != 200 {
		t.Fatalf("ingest %s status = %d %s", domain, w.Code, w.Body.String())
	}
	return decodeBody(t, w)
}

func batchID(t *testing.T, res map[string]any) string {
	t.Helper()
	b, ok := res["batch"].(map[string]any)
	if !ok {
		t.Fatalf("response has no batch: %v", res)
	}
	id, _ := b["id"].(string)
	if id == "" {
		t.Fatalf("batch has no id: %v", b)
	}
	return id
}

func TestIngestScopedRecordsBatchAndIsolatesDomains(t *testing.T) {
	srv := mgmtServer(t)
	h := srv.Handler()

	corp := ingestDomain(t, h, "corp.local", corpIngest)
	if b, _ := corp["batch"].(map[string]any); b == nil || b["domain"] != "corp.local" {
		t.Fatalf("expected corp batch with domain, got %v", corp)
	}
	ingestDomain(t, h, "eng.local", engIngest)

	// Both domains present, scoped separately.
	w := do(t, h, "GET", "/api/v1/ingest/batches", "", nil)
	if w.Code != 200 {
		t.Fatalf("batches status = %d", w.Code)
	}
	batches := decodeBody(t, w)["batches"].([]any)
	if len(batches) != 2 {
		t.Fatalf("expected 2 batches, got %d", len(batches))
	}

	w = do(t, h, "GET", "/api/v1/ingest/domains", "", nil)
	rows := decodeBody(t, w)["domains"].([]any)
	byName := map[string]map[string]any{}
	for _, r := range rows {
		m := r.(map[string]any)
		byName[m["domain"].(string)] = m
	}
	if byName["corp.local"]["nodes"].(float64) != 2 || byName["corp.local"]["edges"].(float64) != 1 {
		t.Fatalf("corp counts wrong: %v", byName["corp.local"])
	}
	if byName["eng.local"]["nodes"].(float64) != 1 {
		t.Fatalf("eng counts wrong: %v", byName["eng.local"])
	}
}

func TestIngestDomainMismatchRejected(t *testing.T) {
	srv := mgmtServer(t)
	h := srv.Handler()
	w := do(t, h, "POST", "/api/v1/ingest?domain=corp.local", engIngest, authHdr())
	if w.Code != 400 {
		t.Fatalf("expected 400 on domain mismatch, got %d %s", w.Code, w.Body.String())
	}
	if st, _ := srv.store.Stats(context.Background()); st.Nodes != 0 {
		t.Fatalf("rejected ingest must not mutate the store: %+v", st)
	}
}

func TestIngestPreviewEndpoint(t *testing.T) {
	h := mgmtServer(t).Handler()
	// Matching domain: 200 with a preview and no write.
	w := do(t, h, "POST", "/api/v1/ingest/preview?domain=corp.local", corpIngest, authHdr())
	if w.Code != 200 {
		t.Fatalf("preview status = %d %s", w.Code, w.Body.String())
	}
	prev := decodeBody(t, w)["preview"].(map[string]any)
	if prev["nodes"].(float64) != 2 || prev["assigned_nodes"].(float64) != 2 {
		t.Fatalf("unexpected preview %v", prev)
	}
	// Mismatch: 422 carrying the preview so the UI can explain what is skipped.
	w = do(t, h, "POST", "/api/v1/ingest/preview?domain=corp.local", engIngest, authHdr())
	if w.Code != 422 {
		t.Fatalf("expected 422 on mismatch, got %d %s", w.Code, w.Body.String())
	}
}

func TestBatchDeleteWorkflowPreservesOtherDomains(t *testing.T) {
	srv := mgmtServer(t)
	h := srv.Handler()
	corpID := batchID(t, ingestDomain(t, h, "corp.local", corpIngest))
	ingestDomain(t, h, "eng.local", engIngest)

	// The batch preview is server-generated.
	w := do(t, h, "POST", "/api/v1/ingest/batches/"+corpID+"/delete-preview", "", authHdr())
	if w.Code != 200 {
		t.Fatalf("preview status = %d %s", w.Code, w.Body.String())
	}
	prev := decodeBody(t, w)
	if prev["delete_nodes"].(float64) != 2 || prev["delete_edges"].(float64) != 1 {
		t.Fatalf("unexpected preview %v", prev)
	}
	token := prev["token"].(string)

	w = do(t, h, "DELETE", "/api/v1/ingest/batches/"+corpID+"?confirm=true&token="+token, "", authHdr())
	if w.Code != 200 {
		t.Fatalf("delete status = %d %s", w.Code, w.Body.String())
	}
	res := decodeBody(t, w)
	if res["deleted_nodes"].(float64) != 2 {
		t.Fatalf("unexpected delete result %v", res)
	}
	if _, ok, _ := srv.store.GetNode(context.Background(), "e1"); !ok {
		t.Fatal("eng.local must survive a corp batch deletion")
	}
	if _, ok, _ := srv.store.GetNode(context.Background(), "c1"); ok {
		t.Fatal("corp nodes should be gone")
	}
	// Batch history no longer lists the deleted batch.
	w = do(t, h, "GET", "/api/v1/ingest/batches", "", nil)
	if strings.Contains(w.Body.String(), corpID) {
		t.Fatal("deleted batch still present in history")
	}
}

func TestBatchDeleteStaleTokenConflict(t *testing.T) {
	srv := mgmtServer(t)
	h := srv.Handler()
	corpID := batchID(t, ingestDomain(t, h, "corp.local", corpIngest))

	w := do(t, h, "POST", "/api/v1/ingest/batches/"+corpID+"/delete-preview", "", authHdr())
	token := decodeBody(t, w)["token"].(string)

	// A second import that also touches c1 makes it shared, changing the plan.
	ingestDomain(t, h, "corp.local", `{"nodes":[{"id":"c1","kind":"User","name":"carol","domain":"corp.local"}],"edges":[]}`)

	w = do(t, h, "DELETE", "/api/v1/ingest/batches/"+corpID+"?confirm=true&token="+token, "", authHdr())
	if w.Code != http.StatusConflict {
		t.Fatalf("expected 409 stale preview, got %d %s", w.Code, w.Body.String())
	}
	if _, ok, _ := srv.store.GetNode(context.Background(), "c1"); !ok {
		t.Fatal("stale deletion must not mutate the store")
	}
}

func TestDomainDeleteWorkflowPreservesOtherDomains(t *testing.T) {
	srv := mgmtServer(t)
	h := srv.Handler()
	ingestDomain(t, h, "corp.local", corpIngest)
	ingestDomain(t, h, "eng.local", engIngest)

	w := do(t, h, "POST", "/api/v1/ingest/domains/corp.local/delete-preview", "", authHdr())
	if w.Code != 200 {
		t.Fatalf("domain preview status = %d %s", w.Code, w.Body.String())
	}
	prev := decodeBody(t, w)
	token := prev["token"].(string)

	w = do(t, h, "DELETE", "/api/v1/ingest/domains/corp.local?confirm=true&token="+token, "", authHdr())
	if w.Code != 200 {
		t.Fatalf("domain delete status = %d %s", w.Code, w.Body.String())
	}
	if _, ok, _ := srv.store.GetNode(context.Background(), "e1"); !ok {
		t.Fatal("eng.local must survive a corp.local domain deletion")
	}
	if _, ok, _ := srv.store.GetNode(context.Background(), "c1"); ok {
		t.Fatal("corp.local nodes should be gone")
	}
}

func TestIngestMgmtAuthAndConfirmGuards(t *testing.T) {
	srv := mgmtServer(t)
	h := srv.Handler()
	id := batchID(t, ingestDomain(t, h, "corp.local", corpIngest))

	// No token.
	if w := do(t, h, "DELETE", "/api/v1/ingest/batches/"+id+"?confirm=true", "", nil); w.Code != 401 {
		t.Fatalf("expected 401 without token, got %d", w.Code)
	}
	// No confirm.
	if w := do(t, h, "DELETE", "/api/v1/ingest/batches/"+id, "", authHdr()); w.Code != 400 {
		t.Fatalf("expected 400 without confirm, got %d %s", w.Code, w.Body.String())
	}
	// Preview also requires the token.
	if w := do(t, h, "POST", "/api/v1/ingest/batches/"+id+"/delete-preview", "", nil); w.Code != 401 {
		t.Fatalf("expected 401 for preview without token, got %d", w.Code)
	}
}

func TestIngestMgmtNotFound(t *testing.T) {
	h := mgmtServer(t).Handler()
	if w := do(t, h, "POST", "/api/v1/ingest/batches/ghost/delete-preview", "", authHdr()); w.Code != 404 {
		t.Fatalf("expected 404 for unknown batch, got %d %s", w.Code, w.Body.String())
	}
	if w := do(t, h, "POST", "/api/v1/ingest/domains/ghost.local/delete-preview", "", authHdr()); w.Code != 404 {
		t.Fatalf("expected 404 for unknown domain, got %d %s", w.Code, w.Body.String())
	}
}

func TestRecordsDeleteWorkflow(t *testing.T) {
	srv := mgmtServer(t)
	h := srv.Handler()
	id := batchID(t, ingestDomain(t, h, "corp.local", corpIngest))

	body := `{"scope":"batch","target":"` + id + `","node_ids":["c2"]}`
	w := do(t, h, "POST", "/api/v1/ingest/records/delete-preview", body, authHdr())
	if w.Code != 200 {
		t.Fatalf("records preview status = %d %s", w.Code, w.Body.String())
	}
	token := decodeBody(t, w)["token"].(string)

	w = do(t, h, "POST", "/api/v1/ingest/records/delete?confirm=true&token="+token, body, authHdr())
	if w.Code != 200 {
		t.Fatalf("records delete status = %d %s", w.Code, w.Body.String())
	}
	if _, ok, _ := srv.store.GetNode(context.Background(), "c2"); ok {
		t.Fatal("selected record c2 should be deleted")
	}
	if _, ok, _ := srv.store.GetNode(context.Background(), "c1"); !ok {
		t.Fatal("unselected record c1 should survive")
	}
}
