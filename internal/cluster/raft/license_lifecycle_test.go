package raft

import (
	"encoding/json"
	"io"
	"strings"
	"testing"

	hraft "github.com/hashicorp/raft"
	"github.com/rs/zerolog"
)

func TestLicenseLifecycleDurableRoleOwners(t *testing.T) {
	f := NewClusterFSM(zerolog.Nop())
	f.nodes["w1"] = &NodeInfo{ID: "w1", Role: "writer"}
	f.nodes["w2"] = &NodeInfo{ID: "w2", Role: "writer"}
	state := LicenseLifecycleState{Generation: 1, Controller: "w1", Mode: "reduced", Owner: "w1", Roles: map[string]string{"writer": "w1"}, Participants: []string{"w1", "w2"}}
	apply := func(s LicenseLifecycleState) interface{} {
		p, _ := json.Marshal(s)
		b, _ := json.Marshal(Command{Type: CommandLicenseLifecycle, Payload: p})
		return f.Apply(&hraft.Log{Index: 1, Data: b})
	}
	if err := apply(state); err != nil {
		t.Fatal(err)
	}
	// Caller mutation must not change the committed owners.
	copy := f.LicenseLifecycle()
	copy.Roles["writer"] = "w2"
	if f.LicenseLifecycle().Roles["writer"] != "w1" {
		t.Fatal("mutable owner map")
	}
	state.Generation = 2
	state.Roles["writer"] = "unknown"
	if err := apply(state); err == nil {
		t.Fatal("unknown role owner accepted")
	}
	state.Roles["writer"] = "w1"
	state.Participants = []string{"w1"}
	if err := apply(state); err == nil {
		t.Fatal("participant silently dropped")
	}
	snap, err := f.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	fs := snap.(*fsmSnapshot)
	raw, _ := json.Marshal(FSMSnapshot{Nodes: fs.nodes, LicenseLifecycle: fs.licenseLifecycle})
	restored := NewClusterFSM(zerolog.Nop())
	if err := restored.Restore(io.NopCloser(strings.NewReader(string(raw)))); err != nil {
		t.Fatal(err)
	}
	if restored.LicenseLifecycle().Roles["writer"] != "w1" {
		t.Fatal("snapshot lost contraction")
	}
}
