package api

import (
	"encoding/json"
	"testing"

	"github.com/krazybeastx1/omenhound/pkg/model"
)

func TestNodesPagination(t *testing.T) {
	h := newTestServer(t).Handler()

	type listResp struct {
		Total  int          `json:"total"`
		Limit  int          `json:"limit"`
		Offset int          `json:"offset"`
		Nodes  []model.Node `json:"nodes"`
	}

	w := do(t, h, "GET", "/api/v1/nodes?limit=1&offset=0", "", nil)
	if w.Code != 200 {
		t.Fatalf("page 0 = %d %s", w.Code, w.Body.String())
	}
	var p0 listResp
	if err := json.Unmarshal(w.Body.Bytes(), &p0); err != nil {
		t.Fatal(err)
	}
	if p0.Total != 2 || p0.Limit != 1 || p0.Offset != 0 || len(p0.Nodes) != 1 {
		t.Fatalf("page 0 = %+v", p0)
	}

	w = do(t, h, "GET", "/api/v1/nodes?limit=1&offset=1", "", nil)
	var p1 listResp
	if err := json.Unmarshal(w.Body.Bytes(), &p1); err != nil {
		t.Fatal(err)
	}
	if len(p1.Nodes) != 1 || p1.Nodes[0].ID == p0.Nodes[0].ID {
		t.Fatalf("page 1 did not advance: %+v vs %+v", p0.Nodes, p1.Nodes)
	}

	w = do(t, h, "GET", "/api/v1/nodes?offset=99", "", nil)
	var past listResp
	if err := json.Unmarshal(w.Body.Bytes(), &past); err != nil {
		t.Fatal(err)
	}
	if len(past.Nodes) != 0 {
		t.Fatalf("offset past end should be empty, got %+v", past.Nodes)
	}
}

func TestEdgesPagination(t *testing.T) {
	h := newTestServer(t).Handler()
	w := do(t, h, "GET", "/api/v1/edges?limit=10", "", nil)
	if w.Code != 200 {
		t.Fatalf("edges = %d", w.Code)
	}
	var resp struct {
		Total int          `json:"total"`
		Edges []model.Edge `json:"edges"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp.Total != 1 || len(resp.Edges) != 1 {
		t.Fatalf("edges resp = %+v", resp)
	}
}

func TestGetNodeByID(t *testing.T) {
	h := newTestServer(t).Handler()
	w := do(t, h, "GET", "/api/v1/nodes/S-1-5-21-1-2-3-1103", "", nil)
	if w.Code != 200 || !json.Valid(w.Body.Bytes()) {
		t.Fatalf("get node = %d %s", w.Code, w.Body.String())
	}
	var n model.Node
	if err := json.Unmarshal(w.Body.Bytes(), &n); err != nil {
		t.Fatal(err)
	}
	if n.Name != "jdoe" || n.Kind != model.KindUser {
		t.Fatalf("node = %+v", n)
	}

	if w := do(t, h, "GET", "/api/v1/nodes/does-not-exist", "", nil); w.Code != 404 {
		t.Fatalf("missing node should be 404, got %d", w.Code)
	}
}

func TestIngestRejectsUnknownFields(t *testing.T) {
	h := newTestServer(t).Handler()
	auth := map[string]string{"Authorization": "Bearer secret"}
	w := do(t, h, "POST", "/api/v1/ingest", `{"nodes":[],"edges":[],"bogus":true}`, auth)
	if w.Code != 400 {
		t.Fatalf("unknown field should be rejected, got %d %s", w.Code, w.Body.String())
	}
}

func TestIngestRejectsTrailingData(t *testing.T) {
	h := newTestServer(t).Handler()
	auth := map[string]string{"Authorization": "Bearer secret"}
	w := do(t, h, "POST", "/api/v1/ingest", `{"nodes":[],"edges":[]} {"extra":1}`, auth)
	if w.Code != 400 {
		t.Fatalf("trailing data should be rejected, got %d %s", w.Code, w.Body.String())
	}
}
