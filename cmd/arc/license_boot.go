package main

import (
	"encoding/json"
	"errors"
	"path/filepath"
	"reflect"
	"sort"

	"github.com/basekick-labs/arc/internal/cluster"
	"github.com/basekick-labs/arc/internal/config"
	"github.com/basekick-labs/arc/internal/license"
)

func prepareLicenseOSSConfig(cfg *config.Config, record, local *cluster.LicenseBootRecord) error {
	if local == nil || local.Generation != record.Generation || local.InventorySHA256 != record.InventorySHA256 || local.Owner != record.Owner || local.Controller != record.Controller || !reflect.DeepEqual(local.Participants, record.Participants) {
		return errors.New("local prepared namespace differs from committed certificate")
	}
	return applyLicensePreparedIdentity(cfg, local)
}

// Prepared state pins identity even if a crash prevented local seal persistence.
// It never authorizes an OSS boot or changes cluster enablement/data roots.
func loadLicensePreparedIdentity(cfg *config.Config) error {
	local, err := cluster.ReadLicenseBootRecord(filepath.Join(cfg.Cluster.RaftDataDir, "license-lifecycle.json.prepared"), cfg.Cluster.ClusterName)
	if err != nil {
		return err
	}
	if local == nil {
		return nil
	}
	return applyLicensePreparedIdentity(cfg, local)
}

func applyLicensePreparedIdentity(cfg *config.Config, local *cluster.LicenseBootRecord) error {
	if local.LocalNodeID != "" {
		if cfg.Cluster.NodeID != "" && cfg.Cluster.NodeID != local.LocalNodeID {
			return errors.New("configured node identity differs from prepared namespace")
		}
		cfg.Cluster.NodeID = local.LocalNodeID
	}
	return nil
}

// Expiration and authority refreshes do not change constructed components.
// Capabilities or resource limits do, and require rebuilding the runtime.
func licenseRuntimeShape(l *license.License) string {
	if l == nil {
		return ""
	}
	features := append([]string(nil), l.Features...)
	sort.Strings(features)
	raw, _ := json.Marshal(struct {
		Tier            license.Tier
		Cores, Machines int
		Features        []string
	}{l.Tier, l.MaxCores, l.MaxMachines, features})
	return string(raw)
}
