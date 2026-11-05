package api

import (
	"github.com/rs/zerolog"
	"net/http/httptest"
	"testing"
)

func TestLicenseServingReadinessSeparatesReadsAndWrites(t *testing.T) {
	s := NewServer(&ServerConfig{}, zerolog.Nop())
	s.RegisterRoutes()
	s.MarkReady()
	allowed := false
	s.SetServingReadiness(func() bool { return allowed })
	for _, path := range []string{"/ready", "/ready/write"} {
		response, err := s.GetApp().Test(httptest.NewRequest("GET", path, nil))
		if err != nil {
			t.Fatal(err)
		}
		response.Body.Close()
		if response.StatusCode != 503 {
			t.Fatalf("fenced %s returned %d", path, response.StatusCode)
		}
	}
	allowed = true
	s.SetWriteReadiness(func() bool { return false })
	read, err := s.GetApp().Test(httptest.NewRequest("GET", "/ready", nil))
	if err != nil {
		t.Fatal(err)
	}
	defer read.Body.Close()
	write, err := s.GetApp().Test(httptest.NewRequest("GET", "/ready/write", nil))
	if err != nil {
		t.Fatal(err)
	}
	defer write.Body.Close()
	if read.StatusCode != 200 || write.StatusCode != 503 {
		t.Fatal("read-only preparation readiness was conflated with ingest readiness")
	}
}
