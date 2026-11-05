package cluster

import (
	"encoding/json"
	"github.com/basekick-labs/arc/internal/cluster/raft"
	"github.com/basekick-labs/arc/internal/config"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLicenseNamespacesRespectRootAndParticipantIsolation(t *testing.T) {
	root := t.TempDir()
	seen := map[string]bool{}
	for _, base := range []string{filepath.Join(root, "a"), filepath.Join(root, "b")} {
		for _, cluster := range []string{"cluster-a", "cluster-b"} {
			for _, node := range []string{"w1", "w2"} {
				p := licenseNamespace(base, cluster, node, 2, "storage")
				if !strings.HasPrefix(p, base+string(filepath.Separator)) || seen[p] {
					t.Fatalf("namespace escaped or collided: %s", p)
				}
				seen[p] = true
			}
		}
	}
}

func TestLicenseLocalSealDoesNotAuthorizeRaftOffRestart(t *testing.T) {
	r := bootRecord(t)
	c := &Coordinator{cfg: &config.ClusterConfig{ClusterName: r.ClusterName, RaftDataDir: t.TempDir()}}
	raw, _ := json.Marshal(r)
	s := raft.LicenseLifecycleState{Mode: "sealed", Generation: r.Generation, Owner: r.Owner, Controller: r.Controller, Certificate: raw}
	if err := c.PersistLicenseOSS(s); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(c.LicenseBootPath()); !os.IsNotExist(err) {
		t.Fatal("local durability prematurely authorized Raft shutdown")
	}
	if _, err := os.Stat(c.LicenseBootPath() + ".sealed"); err != nil {
		t.Fatal(err)
	}
	if err := c.authorizeLicenseOSS(s); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadLicenseBootRecord(c.LicenseBootPath(), r.ClusterName); err != nil {
		t.Fatal(err)
	}
}
