package tiering

import (
	"bytes"
	"context"
	"database/sql"
	"path/filepath"
	"testing"
	"time"

	"github.com/basekick-labs/arc/internal/config"
	"github.com/basekick-labs/arc/internal/storage"
	_ "github.com/mattn/go-sqlite3"
	"github.com/rs/zerolog"
)

func TestReadOnlyManagerKeepsColdDataReadableWithoutLicense(t *testing.T) {
	db, err := sql.Open("sqlite3", filepath.Join(t.TempDir(), "metadata.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	hot, err := storage.NewLocalBackend(t.TempDir(), zerolog.Nop())
	if err != nil {
		t.Fatal(err)
	}
	cold, err := storage.NewLocalBackend(t.TempDir(), zerolog.Nop())
	if err != nil {
		t.Fatal(err)
	}
	cfg := &config.TieredStorageConfig{Enabled: true, MigrationSchedule: "0 2 * * *", DefaultHotMaxAgeDays: 1, Cold: config.ColdTierConfig{Enabled: true, Backend: "s3"}}
	m, err := NewManager(&ManagerConfig{ReadOnly: true, DB: db, Config: cfg, HotBackend: hot, ColdBackend: cold, Logger: zerolog.Nop()})
	if err != nil {
		t.Fatal(err)
	}
	defer m.Stop()
	ctx := context.Background()
	key := "example/events/2026/11/01/events_20261101_daily.parquet"
	content := []byte("existing cold bytes")
	if err := cold.Write(ctx, key, content); err != nil {
		t.Fatal(err)
	}
	if err := m.metadata.RecordFile(ctx, &FileMetadata{Path: key, Database: "example", Measurement: "events", Tier: TierCold, PartitionTime: time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC), SizeBytes: int64(len(content))}); err != nil {
		t.Fatal(err)
	}
	paths, err := m.router.GetStoragePathsForQuery(ctx, "example", "events", nil, nil)
	if err != nil || len(paths) != 1 || paths[0].Tier != TierCold {
		t.Fatalf("read routing=%v, error=%v", paths, err)
	}
	var got bytes.Buffer
	if err := m.GetBackendForTier(TierCold).ReadTo(ctx, paths[0].Path, &got); err != nil || !bytes.Equal(got.Bytes(), content) {
		t.Fatalf("cold read failed: %v", err)
	}
	if _, _, err := m.TriggerFilteredMigration(ctx, TierHot, TierCold, "example", "events"); err == nil {
		t.Fatal("read-only manager admitted new migration")
	}
	status, err := m.GetStatus(ctx)
	if err != nil || status.LicenseValid {
		t.Fatalf("read-only mode falsely advertises entitlement: %+v %v", status, err)
	}
}

func TestReadOnlyScansPreserveHotOnlyColdCopies(t *testing.T) {
	for _, startup := range []bool{false, true} {
		t.Run(map[bool]string{false: "scheduled", true: "startup"}[startup], func(t *testing.T) {
			m, _, cold, cleanup := setupHotOnlyCleanupCandidate(t, gateDailyA)
			defer cleanup()
			m.readOnly = true
			m.coldBackend = &coldLister{mockBackend: cold, lastModified: time.Now().Add(-time.Hour)}
			ctx := context.Background()
			if startup {
				if _, err := m.ScanTiers(ctx); err != nil {
					t.Fatal(err)
				}
			} else if err := m.RunMigrationCycle(ctx); err != nil {
				t.Fatal(err)
			}
			if exists, err := cold.Exists(ctx, gateDailyA); err != nil || !exists {
				t.Fatalf("read-serving scan deleted cold data: exists=%v err=%v", exists, err)
			}
		})
	}
}

func TestReadOnlyScanRespectsConfiguredBudget(t *testing.T) {
	m, hot, _, cleanup := setupIntegrationTest(t, false)
	defer cleanup()
	m.readOnly = true
	m.config.ScanTimeout = 20 * time.Millisecond
	m.hotBackend = &blockingListBackend{Backend: hot, entered: make(chan struct{})}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	started := time.Now()
	if err := m.RunMigrationCycle(ctx); err == nil {
		t.Fatal("blocked scan must report incomplete work")
	}
	if elapsed := time.Since(started); elapsed > time.Second {
		t.Fatalf("read-only scan ignored 20ms configured budget: %s", elapsed)
	}
	if ctx.Err() != nil {
		t.Fatal("read-only scan consumed outer cycle budget")
	}
}
