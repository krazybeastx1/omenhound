package api

import (
	"net/http/httptest"
	"testing"
	"time"
)

func TestSecurityHeadersSetOnEveryResponse(t *testing.T) {
	h := newTestServer(t).Handler()
	w := do(t, h, "GET", "/api/v1/health", "", nil)
	for _, k := range []string{
		"Content-Security-Policy",
		"X-Content-Type-Options",
		"X-Frame-Options",
		"Referrer-Policy",
		"Cross-Origin-Opener-Policy",
		"Cross-Origin-Resource-Policy",
	} {
		if v := w.Header().Get(k); v == "" {
			t.Errorf("missing security header %s", k)
		}
	}
	if got := w.Header().Get("X-Content-Type-Options"); got != "nosniff" {
		t.Errorf("nosniff = %q", got)
	}
}

func TestHSTSOnlyOverTLS(t *testing.T) {
	h := newTestServer(t).Handler()
	w := do(t, h, "GET", "/api/v1/health", "", nil)
	if w.Header().Get("Strict-Transport-Security") != "" {
		t.Fatal("HSTS must not be sent over plain HTTP")
	}
}

func TestRateLimiterTokenBucket(t *testing.T) {
	rl := newRateLimiter(60, 1) // 1 token/sec, burst 1
	now := time.Now()
	rl.now = func() time.Time { return now }

	if !rl.allow("1.2.3.4") {
		t.Fatal("first request should pass")
	}
	if rl.allow("1.2.3.4") {
		t.Fatal("second request should be limited")
	}
	now = now.Add(time.Second)
	if !rl.allow("1.2.3.4") {
		t.Fatal("token should refill after one second")
	}
	if !rl.allow("5.6.7.8") {
		t.Fatal("a different key must have its own bucket")
	}
}

func TestWriteRateLimited(t *testing.T) {
	h := New(Config{
		StoreIface:         seeded(t),
		Version:            "test",
		APIToken:           "secret",
		WriteRatePerMinute: 1,
		WriteBurst:         1,
	}).Handler()
	auth := map[string]string{"Authorization": "Bearer secret"}

	w := do(t, h, "POST", "/api/v1/ingest", `{"nodes":[],"edges":[]}`, auth)
	if w.Code != 200 {
		t.Fatalf("first write = %d %s", w.Code, w.Body.String())
	}
	w = do(t, h, "POST", "/api/v1/ingest", `{"nodes":[],"edges":[]}`, auth)
	if w.Code != 429 {
		t.Fatalf("second write should be rate limited, got %d", w.Code)
	}
	if w.Header().Get("Retry-After") == "" {
		t.Error("429 should carry Retry-After")
	}
	// reads are never limited
	if w := do(t, h, "GET", "/api/v1/health", "", nil); w.Code != 200 {
		t.Fatalf("read should not be limited, got %d", w.Code)
	}
}

func TestClientIPIgnoresForwardedFor(t *testing.T) {
	r := httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = "10.0.0.5:1234"
	r.Header.Set("X-Forwarded-For", "1.2.3.4")
	if got := clientIP(r); got != "10.0.0.5" {
		t.Fatalf("clientIP = %q, want 10.0.0.5 (proxy headers untrusted)", got)
	}
}
