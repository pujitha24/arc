package tiering

import (
	"context"
	"testing"
	"time"
)

func TestLicenseQuiesceWaitsForCompleteMigrationRelease(t *testing.T) {
	m := &Manager{}
	m.cycleRunning.Store(true) // Includes post-completion manifest/hot release.
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if m.QuiesceLicense(ctx) == nil {
		t.Fatal("sealed while migration release was active")
	}
	if m.scanRunning.Load() {
		t.Fatal("failed drain retained scan reservation")
	}
	m.cycleRunning.Store(false)
	if err := m.QuiesceLicense(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !m.scanRunning.Load() || !m.cycleRunning.Load() {
		t.Fatal("new mutations can start after drain")
	}
	if err := m.QuiesceLicense(context.Background()); err != nil {
		t.Fatal(err)
	}
}
