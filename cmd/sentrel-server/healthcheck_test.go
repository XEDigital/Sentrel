package main

import (
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
)

func TestHealthcheckLocalTLSAndRedirectRefusal(t *testing.T) {
	tlsServer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) }))
	defer tlsServer.Close()
	if err := healthcheck([]string{"--url", tlsServer.URL + "/healthz"}); err != nil {
		t.Fatalf("local self-signed health check: %v", err)
	}
	var hits atomic.Int32
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hits.Add(1) }))
	defer target.Close()
	redirect := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, target.URL, http.StatusFound) }))
	defer redirect.Close()
	if err := healthcheck([]string{"--url", redirect.URL}); err == nil {
		t.Fatal("healthcheck accepted a redirect")
	}
	if hits.Load() != 0 {
		t.Fatal("healthcheck followed a redirect")
	}
	for _, raw := range []string{"file:///etc/passwd", "://bad"} {
		if err := healthcheck([]string{"--url", raw}); err == nil {
			t.Fatalf("accepted invalid health URL %q", raw)
		}
	}
}
