package cluster

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	arcRaft "github.com/basekick-labs/arc/internal/cluster/raft"
	"github.com/basekick-labs/arc/internal/config"
	"github.com/basekick-labs/arc/internal/license"
	hraft "github.com/hashicorp/raft"
	"github.com/rs/zerolog"
)

func TestLicenseRoleFencePrecedesPermissiveFallbacks(t *testing.T) {
	for _, shared := range []bool{false, true} {
		f := arcRaft.NewClusterFSM(zerolog.Nop())
		for i, id := range []string{"w1", "w2"} {
			raw, _ := json.Marshal(arcRaft.AddNodePayload{Node: arcRaft.NodeInfo{ID: id, Role: "writer", State: "healthy"}})
			cmd, _ := json.Marshal(arcRaft.Command{Type: arcRaft.CommandAddNode, Payload: raw})
			if err := f.Apply(&hraft.Log{Index: uint64(i + 1), Data: cmd}); err != nil {
				t.Fatal(err)
			}
		}
		state := arcRaft.LicenseLifecycleState{Generation: 1, Mode: "reduced", Controller: "w1", Owner: "w1", Roles: map[string]string{"writer": "w1"}, Participants: []string{"w1", "w2"}}
		raw, _ := json.Marshal(state)
		cmd, _ := json.Marshal(arcRaft.Command{Type: arcRaft.CommandLicenseLifecycle, Payload: raw})
		if err := f.Apply(&hraft.Log{Index: 3, Data: cmd}); err != nil {
			t.Fatal(err)
		}
		for _, id := range []string{"w1", "w2"} {
			c := &Coordinator{cfg: &config.ClusterConfig{SharedStorageMode: shared}, localNode: NewNode(id, id, RoleWriter, "test"), raftFSM: f, lifecycleRecovery: true}
			c.lifecycle.ready.Store(true)
			c.lifecycle.phase = func() license.ExpiryState {
				return license.ExpiryState{Valid: true, GraceDay: 8, Phase: license.PhaseReducedRoles}
			}
			if c.ServingAllowed() != (id == "w1") || c.MayAcceptIngest() != (id == "w1") || c.IsPrimaryWriter() != (id == "w1") {
				t.Fatalf("shared=%v id=%s escaped role fence", shared, id)
			}
			c.lifecycle.ready.Store(true)
			c.lifecycle.phase = func() license.ExpiryState { return license.ExpiryState{Phase: license.PhaseAuthorityUnavailable} }
			if c.ServingAllowed() {
				t.Fatal("unavailable clock opened service")
			}
		}
	}
}

func TestLicenseRoleSelectionKeepsExistingPrimaryAndConfiguredRoles(t *testing.T) {
	nodes := []*arcRaft.NodeInfo{{ID: "w2", Role: "writer", State: "healthy"}, {ID: "r2", Role: "reader", State: "healthy"}, {ID: "w1", Role: "writer", State: "healthy"}, {ID: "r1", Role: "reader", State: "healthy"}}
	s, err := chooseLifecycleOwners(nodes, "w2", "")
	if err != nil {
		t.Fatal(err)
	}
	if s.Owner != "w2" || s.Roles["reader"] != "r1" || len(s.Roles) != 2 {
		t.Fatalf("unexpected owners: %+v", s)
	}
	nodes[0].State = "dead"
	nodes[1].State = "dead"
	nodes[2].State = "dead"
	nodes[3].State = "dead"
	if _, err := chooseLifecycleOwners(nodes, "", ""); err == nil {
		t.Fatal("selected unavailable serving owners")
	}
}

func TestLicenseReplacementCannotServeUnlicensedSharedMode(t *testing.T) {
	l := &license.License{Tier: license.TierProfessional, Features: []string{license.FeatureClustering}, Status: "active", ExpiresAt: time.Now().Add(time.Hour)}
	if p := licensePhaseForMode(l, false); !p.Valid {
		t.Fatal("clustering grant refused local mode")
	}
	if p := licensePhaseForMode(l, true); p.Valid || p.Phase != license.PhaseOSS {
		t.Fatal("recovery exception enabled unlicensed shared mode")
	}
	l.Features = append(l.Features, license.FeatureSharedStorageMultiWriter)
	if p := licensePhaseForMode(l, true); !p.Valid {
		t.Fatal("shared grant refused shared mode")
	}
}

func TestLicenseReplacementRespectsClusterWideCapacity(t *testing.T) {
	l := &license.License{MaxMachines: 3, MaxCores: 4}
	if licenseFitsTopology(l, 3, 6) {
		t.Fatal("per-process core clamp bypassed aggregate limit")
	}
	if licenseFitsTopology(l, 4, 4) {
		t.Fatal("retained membership exceeded machine limit")
	}
	if !licenseFitsTopology(l, 2, 4) {
		t.Fatal("within-capacity topology was refused")
	}
	l.MaxMachines = -1
	l.MaxCores = -1
	if !licenseFitsTopology(l, 100, 1000) {
		t.Fatal("unlimited capacity was capped")
	}
}

func TestLicenseRenewalBeforeSealReopensThroughFreshProcess(t *testing.T) {
	rn := startSingleNodeRaft(t, "writer-A")
	c := newPauseForwardingCoordinator(t, "writer-A", RoleWriter, rn)
	if err := rn.AddNode(&arcRaft.NodeInfo{ID: "writer-A", Name: "writer-A", Role: "writer", State: "healthy"}, time.Second); err != nil {
		t.Fatal(err)
	}
	s := arcRaft.LicenseLifecycleState{Generation: 1, Controller: "writer-A", Mode: "preparing", Owner: "writer-A", Roles: map[string]string{"writer": "writer-A"}, Participants: []string{"writer-A"}}
	if _, err := c.proposeLeader(arcRaft.CommandLicenseLifecycle, s); err != nil {
		t.Fatal(err)
	}
	c.lifecycle.ready.Store(true)
	c.lifecycle.phase = func() license.ExpiryState { return license.ExpiryState{Valid: true, Phase: license.PhaseActive} }
	c.SetLocalPolicyLister(lifecyclePolicyKind, func(context.Context) (json.RawMessage, error) {
		return json.Marshal(lifecycleReport{Phase: c.licensePhase(), Generation: c.LifecycleState().Generation, Mode: c.LifecycleState().Mode})
	})
	restarted := false
	c.lifecycle.release = func(arcRaft.LicenseLifecycleState) { restarted = true }
	if err := c.lifecycleTick(context.Background()); err != nil {
		t.Fatal(err)
	}
	if c.LifecycleState().Mode != "active" {
		t.Fatal("renewal did not cancel unsealed preparation")
	}
	if err := c.lifecycleTick(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !restarted {
		t.Fatal("closed admission and skipped components were not rebuilt")
	}
}

func TestLicensePreparingRetainsDataReadsButFencesIngest(t *testing.T) {
	rn := startSingleNodeRaft(t, "writer-A")
	c := newPauseForwardingCoordinator(t, "writer-A", RoleWriter, rn)
	if err := rn.AddNode(&arcRaft.NodeInfo{ID: "writer-A", Name: "writer-A", Role: "writer", State: "healthy"}, time.Second); err != nil {
		t.Fatal(err)
	}
	s := arcRaft.LicenseLifecycleState{Generation: 1, Mode: "preparing", Controller: "writer-A", Owner: "writer-A", Roles: map[string]string{"writer": "writer-A"}, Participants: []string{"writer-A"}}
	if _, err := c.proposeLeader(arcRaft.CommandLicenseLifecycle, s); err != nil {
		t.Fatal(err)
	}
	c.lifecycle.ready.Store(true)
	c.lifecycle.started.Store(true)
	c.lifecycle.phase = func() license.ExpiryState { return license.ExpiryState{Phase: license.PhaseOSS} }
	if !c.ReadServingAllowed() || c.ServingAllowed() || c.MayAcceptIngest() {
		t.Fatal("immutable preparation did not separate reads from mutating admission")
	}
	if c.IngestGate()() == nil {
		t.Fatal("non-HTTP live ingest escaped the lifecycle fence")
	}
}
