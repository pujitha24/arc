package main

import (
	"context"
	"encoding/json"
	"github.com/basekick-labs/arc/internal/auth"
	"github.com/basekick-labs/arc/internal/cluster/raft"
	hraft "github.com/hashicorp/raft"
	"github.com/rs/zerolog"
	"testing"
)

func TestLicenseFinalAuthDrainMaterializesMissedRevocation(t *testing.T) {
	am := newReconcileAuth(t)
	token := raft.TokenEntry{ID: 50, Name: "revoked-before-callbacks", Permissions: "read", TokenHash: "hash", TokenPrefix: "prefix", Enabled: true, CreatedAtUnixNano: 1}
	if err := am.ApplyCreateToken(auth.ClusterTokenEntry{ID: 50, Name: token.Name, Permissions: "read", TokenHash: "hash", TokenPrefix: "prefix", Enabled: true, CreatedAtUnixNano: 1}); err != nil {
		t.Fatal(err)
	}
	fsm := raft.NewClusterFSM(zerolog.Nop())
	apply := func(index uint64, kind raft.CommandType, payload any) {
		t.Helper()
		raw, _ := json.Marshal(payload)
		cmd, _ := json.Marshal(raft.Command{Type: kind, Payload: raw})
		if err := fsm.Apply(&hraft.Log{Index: index, Data: cmd}); err != nil {
			t.Fatal(err)
		}
	}
	apply(50, raft.CommandCreateToken, raft.CreateTokenPayload{Token: token})
	apply(51, raft.CommandRevokeToken, raft.RevokeTokenPayload{ID: 50})
	if err := reconcileLicenseAuth(context.Background(), fsm, 1, am, nil, zerolog.Nop()); err != nil {
		t.Fatal(err)
	}
	var enabled bool
	if err := am.GetDB().QueryRow("SELECT enabled FROM api_tokens WHERE id=50").Scan(&enabled); err != nil {
		t.Fatal(err)
	}
	if enabled {
		t.Fatal("missed revocation became standalone authority")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if reconcileLicenseAuth(ctx, fsm, 1, am, nil, zerolog.Nop()) == nil {
		t.Fatal("failed auth materialization allowed seal")
	}
}
