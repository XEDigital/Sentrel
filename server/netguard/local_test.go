package netguard

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestHealthDialerConfinesConnectionsToLocalMachine(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer srv.Close()
	cl := &http.Client{Transport: &http.Transport{DialContext: LocalDialer(time.Second).DialContext}}
	resp, err := cl.Get(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if _, err := cl.Get("http://192.0.2.1:80"); !errors.Is(err, ErrBlocked) {
		t.Fatalf("nonlocal destination not blocked by dialer: %v", err)
	}
}
