package main

import (
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/basekick-labs/arc/internal/cluster"
	"github.com/basekick-labs/arc/internal/config"
	"github.com/basekick-labs/arc/internal/license"
)

func TestLicensePreparedIdentitySurvivesGeneratedProcessID(t *testing.T) {
	canonical := &cluster.LicenseBootRecord{Generation: 2, Owner: "old-owner", Controller: "control", InventorySHA256: "inventory", Participants: map[string]string{"old-owner": "a:1", "control": "b:2", "generated-123": "c:3"}}
	local := *canonical
	local.LocalNodeID = "generated-123"
	cfg := &config.Config{}
	if err := prepareLicenseOSSConfig(cfg, canonical, &local); err != nil || cfg.Cluster.NodeID != "generated-123" {
		t.Fatalf("identity not restored: %v", err)
	}
	cfg.Cluster.NodeID = "another-node"
	if prepareLicenseOSSConfig(cfg, canonical, &local) == nil {
		t.Fatal("accepted another node's namespace")
	}
	cfg.Cluster.NodeID = ""
	local.Controller = "another-controller"
	if prepareLicenseOSSConfig(cfg, canonical, &local) == nil {
		t.Fatal("accepted incompatible certificate")
	}
}

func TestLicenseOSSPathsIsolateIcebergMetadata(t *testing.T) {
	for _, warehouse := range []string{"", "file:///old/data/custom-warehouse", "s3://old-bucket/exports"} {
		t.Run(warehouse, func(t *testing.T) {
			root := t.TempDir()
			oldCatalog := filepath.Join(root, "old-catalog.db")
			if err := os.WriteFile(oldCatalog, []byte("retained predecessor catalog"), 0600); err != nil {
				t.Fatal(err)
			}
			cfg := &config.Config{}
			cfg.ConfigFile = "/etc/arc/original.toml"
			cfg.Auth.DBPath = oldCatalog
			cfg.Iceberg.Enabled = true
			cfg.Iceberg.Warehouse = warehouse
			cfg.Iceberg.CatalogDBPath = oldCatalog
			cfg.Iceberg.NamespacePrefix = "custom"
			cfg.Iceberg.RetainSnapshots = 7
			record := &cluster.LicenseBootRecord{StoragePath: filepath.Join(root, "generation", "storage"), WALPath: filepath.Join(root, "generation", "wal")}
			configureLicenseOSSPaths(cfg, record)
			if cfg.Iceberg.CatalogDBPath == oldCatalog || !strings.HasPrefix(cfg.Iceberg.CatalogDBPath, filepath.Dir(record.StoragePath)+string(filepath.Separator)) {
				t.Fatal("new exporter reused predecessor catalog")
			}
			u, err := url.Parse(cfg.Iceberg.Warehouse)
			uriRoot := filepath.ToSlash(record.StoragePath)
			if !strings.HasPrefix(uriRoot, "/") {
				uriRoot = "/" + uriRoot
			}
			if err != nil || u.Scheme != "file" || !strings.HasPrefix(u.Path, uriRoot+"/") {
				t.Fatalf("warehouse is not bound to current local namespace: %q", cfg.Iceberg.Warehouse)
			}
			if data, err := os.ReadFile(oldCatalog); err != nil || string(data) != "retained predecessor catalog" {
				t.Fatal("predecessor metadata was modified")
			}
			if cfg.Auth.DBPath != oldCatalog || cfg.ConfigFile != "/etc/arc/original.toml" || cfg.Iceberg.NamespacePrefix != "custom" || cfg.Iceberg.RetainSnapshots != 7 {
				t.Fatal("unrelated configuration was lost")
			}
		})
	}
}

func TestLicensePreparedIdentityBeforeLocalSealAcrossProcessRestart(t *testing.T) {
	if dir := os.Getenv("ARC_TEST_PREPARED_IDENTITY_DIR"); dir != "" {
		cfg := &config.Config{}
		cfg.Cluster.RaftDataDir = dir
		cfg.Cluster.ClusterName = "test"
		cfg.Cluster.Enabled = true
		if err := loadLicensePreparedIdentity(cfg); err != nil {
			t.Fatal(err)
		}
		if !cfg.Cluster.Enabled || cfg.Storage.LocalPath != "" {
			t.Fatal("prepared identity authorized OSS")
		}
		fmt.Printf("IDENTITY=%s PID=%d\n", cfg.Cluster.NodeID, os.Getpid())
		return
	}
	dir := t.TempDir()
	old := fmt.Sprintf("generated-%d", os.Getpid())
	r := &cluster.LicenseBootRecord{Version: 1, ClusterName: "test", Generation: 2, Owner: old, Controller: old, LocalNodeID: old, Participants: map[string]string{old: "127.0.0.1:9100"}, StoragePath: filepath.Join(dir, "storage"), WALPath: filepath.Join(dir, "wal"), InventorySHA256: strings.Repeat("a", 64)}
	if err := cluster.WriteLicenseBootRecord(filepath.Join(dir, "license-lifecycle.json.prepared"), r); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(os.Args[0], "-test.run=^TestLicensePreparedIdentityBeforeLocalSealAcrossProcessRestart$")
	cmd.Env = append(os.Environ(), "ARC_TEST_PREPARED_IDENTITY_DIR="+dir)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("new process: %v %s", err, out)
	}
	if !strings.Contains(string(out), "IDENTITY="+old+" ") || strings.Contains(string(out), fmt.Sprintf("PID=%d\n", os.Getpid())) {
		t.Fatalf("identity changed with PID: %s", out)
	}
	for _, name := range []string{"license-lifecycle.json", "license-lifecycle.json.sealed"} {
		if _, err := os.Stat(filepath.Join(dir, name)); !os.IsNotExist(err) {
			t.Fatal("prepared identity created boot authority")
		}
	}
}

func TestLicenseRuntimeShapeRebuildsCapabilitiesAndLimitsOnly(t *testing.T) {
	l := &license.License{Tier: license.TierProfessional, MaxCores: 32, MaxMachines: 3, Features: []string{"clustering", "tiering"}}
	original := licenseRuntimeShape(l)
	l.ExpiresAt = time.Now()
	l.Status = "grace_period"
	l.Features = []string{"tiering", "clustering"}
	if licenseRuntimeShape(l) != original {
		t.Fatal("authority refresh or feature order restarted process")
	}
	l.MaxCores = 4
	if licenseRuntimeShape(l) == original {
		t.Fatal("capacity change did not rebuild")
	}
	l.MaxCores = 32
	l.Features = append(l.Features, "audit_logging")
	if licenseRuntimeShape(l) == original {
		t.Fatal("new feature did not rebuild")
	}
}
