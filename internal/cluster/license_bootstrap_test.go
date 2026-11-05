package cluster

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/basekick-labs/arc/internal/cluster/protocol"
	"github.com/basekick-labs/arc/internal/cluster/security"
	"github.com/basekick-labs/arc/internal/config"
	"github.com/rs/zerolog"
)

func bootRecord(t *testing.T) *LicenseBootRecord {
	t.Helper()
	dir := t.TempDir()
	return &LicenseBootRecord{Version: 1, ClusterName: "test", Generation: 2, Owner: "owner", Controller: "controller", Participants: map[string]string{"owner": "127.0.0.1:9100", "controller": "127.0.0.1:9101"}, StoragePath: filepath.Join(dir, "store"), WALPath: filepath.Join(dir, "wal"), InventorySHA256: strings.Repeat("a", 64)}
}

func TestLicenseBootRecordPersistence(t *testing.T) {
	r := bootRecord(t)
	path := filepath.Join(t.TempDir(), "boot.json")
	if got, err := ReadLicenseBootRecord(path, "test"); got != nil || err != nil {
		t.Fatalf("missing: %v %v", got, err)
	}
	if err := WriteLicenseBootRecord(path, r); err != nil {
		t.Fatal(err)
	}
	got, err := ReadLicenseBootRecord(path, "test")
	if err != nil || got.Owner != r.Owner {
		t.Fatalf("read: %v %v", got, err)
	}
	info, _ := os.Stat(path)
	if info.Mode().Perm() != 0600 {
		t.Fatalf("mode %o", info.Mode().Perm())
	}
	if _, err := ReadLicenseBootRecord(path, "another"); err == nil {
		t.Fatal("cross-cluster accepted")
	}
	if err := WriteLicenseBootRecord(path, r); err != nil {
		t.Fatal(err)
	}
	r.Owner = "controller"
	if err := WriteLicenseBootRecord(path, r); err == nil {
		t.Fatal("changed certificate within generation")
	}
	r.Generation--
	if err := WriteLicenseBootRecord(path, r); err == nil {
		t.Fatal("regressed generation")
	}
	got, err = ReadLicenseBootRecord(path, "test")
	if err != nil || got.Owner != "owner" {
		t.Fatal("failed write changed certificate")
	}
}

func TestLicenseBootRecordRejectsMalformed(t *testing.T) {
	for _, mutate := range []func(*LicenseBootRecord){
		func(r *LicenseBootRecord) { r.Version = 2 }, func(r *LicenseBootRecord) { r.Generation = 0 },
		func(r *LicenseBootRecord) { r.Owner = "outsider" }, func(r *LicenseBootRecord) { r.Controller = "outsider" },
		func(r *LicenseBootRecord) { r.StoragePath = "relative" }, func(r *LicenseBootRecord) { r.WALPath = r.StoragePath },
		func(r *LicenseBootRecord) { r.InventorySHA256 = "bad" }, func(r *LicenseBootRecord) { r.Participants["owner"] = "no-port" },
		func(r *LicenseBootRecord) { r.Participants["bad\x00identity"] = "localhost:1234" },
	} {
		r := bootRecord(t)
		mutate(r)
		data, _ := json.Marshal(r)
		path := filepath.Join(t.TempDir(), "boot.json")
		if err := os.WriteFile(path, data, 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := ReadLicenseBootRecord(path, "test"); err == nil {
			t.Fatalf("accepted %s", data)
		}
	}
	path := filepath.Join(t.TempDir(), "boot.json")
	if err := os.WriteFile(path, []byte("{broken"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadLicenseBootRecord(path, "test"); err == nil {
		t.Fatal("accepted corrupt file")
	}
}

func TestLicenseBootstrapAuthenticationAndReplay(t *testing.T) {
	r := bootRecord(t)
	b := &LicenseBootstrap{record: *r, nodeID: "owner", secret: "secret", nonces: security.NewNonceCache(security.HMACTimestampTolerance)}
	query := func(node, kind string) *protocol.LocalPoliciesQuery {
		q := &protocol.LocalPoliciesQuery{NodeID: node, ClusterName: "test", Kind: kind, Epoch: 2, Nonce: node + kind, Timestamp: time.Now().Unix()}
		q.HMAC = security.ComputeLocalPoliciesQueryHMAC(b.secret, q.Nonce, q.NodeID, q.ClusterName, q.Kind, q.Epoch, q.Timestamp)
		return q
	}
	q := query("controller", "license_boot_v1")
	forged := *q
	forged.HMAC = "bad"
	if b.authorize(&forged) == nil {
		t.Fatal("forged MAC accepted")
	}
	if err := b.authorize(q); err != nil {
		t.Fatal(err)
	}
	if b.authorize(q) == nil {
		t.Fatal("replay accepted")
	}
	if b.authorize(query("outsider", "license_boot_v1")) == nil {
		t.Fatal("nonmember accepted")
	}
	if b.authorize(query("owner", "license_release_v1")) == nil {
		t.Fatal("noncontroller release accepted")
	}
	if err := b.authorize(query("controller", "license_release_v1")); err != nil {
		t.Fatal(err)
	}
	wrong := query("controller", "license_boot_v1")
	wrong.Epoch++
	wrong.HMAC = security.ComputeLocalPoliciesQueryHMAC(b.secret, wrong.Nonce, wrong.NodeID, wrong.ClusterName, wrong.Kind, wrong.Epoch, wrong.Timestamp)
	if b.authorize(wrong) == nil {
		t.Fatal("wrong generation accepted")
	}
	b.nodeID = "controller"
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := b.WaitOwner(ctx); err == nil {
		t.Fatal("nonowner opened")
	}
}

func TestLicenseBootstrapStateLock(t *testing.T) {
	path := filepath.Join(t.TempDir(), "lock")
	first, err := acquireLicenseBootLock(path)
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	if second, err := acquireLicenseBootLock(path); err == nil {
		second.Close()
		t.Fatal("duplicate state owner accepted")
	}
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	next, err := acquireLicenseBootLock(path)
	if err != nil {
		t.Fatal(err)
	}
	next.Close()
}

func TestLicenseBootstrapOwnerWaitsForMatchingPeers(t *testing.T) {
	addresses := make([]string, 2)
	for i := range addresses {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		addresses[i] = ln.Addr().String()
		ln.Close()
	}
	r := bootRecord(t)
	r.Participants = map[string]string{"owner": addresses[0], "controller": addresses[1]}
	start := func(id, addr string, record *LicenseBootRecord) *LicenseBootstrap {
		t.Helper()
		b, err := StartLicenseBootstrap(&config.ClusterConfig{NodeID: id, ClusterName: "test", SharedSecret: "secret", RaftDataDir: t.TempDir(), CoordinatorAddr: addr}, record, zerolog.Nop())
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { b.Close() })
		return b
	}
	owner := start("owner", addresses[0], r)
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	if err := owner.WaitOwner(ctx); err == nil {
		t.Fatal("opened before peer stopped Raft")
	}
	wrong := *r
	wrong.InventorySHA256 = strings.Repeat("b", 64)
	peer := start("controller", addresses[1], &wrong)
	ctx, cancel = context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	if err := owner.WaitOwner(ctx); err == nil {
		t.Fatal("opened against a different sealed inventory")
	}
	peer.Close()
	peer = start("controller", addresses[1], r)
	ctx, cancel = context.WithCancel(context.Background())
	defer cancel()
	winners := make(chan *LicenseBootstrap, 4)
	startWait := func(b *LicenseBootstrap) {
		go func() {
			if b.WaitOwner(ctx) == nil {
				winners <- b
			}
		}()
	}
	startWait(owner)
	startWait(peer)
	var winner *LicenseBootstrap
	select {
	case winner = <-winners:
	case <-time.After(5 * time.Second):
		t.Fatal("no unanimous owner")
	}
	if winner.SelectedOwner() != winner.nodeID || !winner.status().Serving {
		t.Fatal("winner did not publish serving ownership")
	}
	select {
	case <-winners:
		t.Fatal("two serving owners")
	case <-time.After(100 * time.Millisecond):
	}
	// No replacement while the predecessor is unreachable, even though another
	// participant's complete local copy remains available.
	winner.Close()
	select {
	case <-winners:
		t.Fatal("elected through an unreachable predecessor")
	case <-time.After(1100 * time.Millisecond):
	}
	restarted := start(winner.nodeID, r.Participants[winner.nodeID], r)
	if restarted.incarnation == winner.incarnation {
		t.Fatal("restart reused process incarnation")
	}
	startWait(restarted)
	var next *LicenseBootstrap
	select {
	case next = <-winners:
	case <-time.After(5 * time.Second):
		t.Fatal("restart did not permit a new unanimous election")
	}
	if !next.status().Serving || next.SelectedOwner() != next.nodeID {
		t.Fatal("invalid replacement owner")
	}
	select {
	case <-winners:
		t.Fatal("two owners after restart")
	case <-time.After(100 * time.Millisecond):
	}
}

func TestLicenseBootstrapElectionUsesEveryIncarnation(t *testing.T) {
	incarnations := map[string]string{"a": strings.Repeat("1", 32), "b": strings.Repeat("2", 32), "c": strings.Repeat("3", 32)}
	first := licenseBootOwner(incarnations)
	reordered := map[string]string{"c": incarnations["c"], "b": incarnations["b"], "a": incarnations["a"]}
	if licenseBootOwner(reordered) != first {
		t.Fatal("selection depends on map iteration")
	}
	seen := map[string]bool{}
	for i := 0; i < 256; i++ {
		incarnations["c"] = fmt.Sprintf("%032x", i)
		seen[licenseBootOwner(incarnations)] = true
	}
	if len(seen) != 3 {
		t.Fatalf("not every configured participant can win: %v", seen)
	}
}

func TestLicenseBootstrapPrepareRequiresCompleteCurrentVector(t *testing.T) {
	r := bootRecord(t)
	vector := map[string]string{"owner": strings.Repeat("1", 32), "controller": strings.Repeat("2", 32)}
	e := &licenseBootElection{Owner: licenseBootOwner(vector), Incarnations: vector, CertificateSHA256: "certificate"}
	b := &LicenseBootstrap{record: *r, nodeID: "owner", incarnation: vector["owner"], digest: "certificate"}
	if err := b.acceptPrepare("outsider", e); err == nil {
		t.Fatal("noncandidate prepare accepted")
	}
	if err := b.acceptPrepare(e.Owner, e); err != nil {
		t.Fatal(err)
	}
	if err := b.acceptPrepare(e.Owner, e); err != nil {
		t.Fatal("idempotent prepare failed", err)
	}
	missing := &licenseBootElection{Owner: "owner", Incarnations: map[string]string{"owner": vector["owner"]}, CertificateSHA256: "certificate"}
	if b.acceptPrepare("owner", missing) == nil {
		t.Fatal("partial membership accepted")
	}
	changed := &licenseBootElection{Incarnations: map[string]string{"owner": vector["owner"], "controller": strings.Repeat("3", 32)}, CertificateSHA256: "certificate"}
	changed.Owner = licenseBootOwner(changed.Incarnations)
	if b.acceptPrepare(changed.Owner, changed) == nil {
		t.Fatal("prepare overwrote an outstanding promise")
	}
	b.observeRound(changed)
	if err := b.acceptPrepare(changed.Owner, changed); err != nil {
		t.Fatal("changed process vector did not permit another round", err)
	}
	// A fresh process cannot acknowledge a predecessor incarnation.
	fresh := &LicenseBootstrap{record: *r, nodeID: "controller", incarnation: changed.Incarnations["controller"], digest: "certificate"}
	if fresh.acceptPrepare(e.Owner, e) == nil {
		t.Fatal("new process acknowledged old incarnation")
	}
}

func TestLicenseBootstrapServingOwnerNeverReleasesPromise(t *testing.T) {
	r := bootRecord(t)
	vector := map[string]string{"owner": strings.Repeat("1", 32), "controller": strings.Repeat("2", 32)}
	e := &licenseBootElection{Owner: licenseBootOwner(vector), Incarnations: vector, CertificateSHA256: "certificate"}
	b := &LicenseBootstrap{record: *r, nodeID: e.Owner, incarnation: vector[e.Owner], digest: "certificate"}
	if err := b.acceptPrepare(e.Owner, e); err != nil {
		t.Fatal(err)
	}
	b.serving, b.selected = true, e.Owner
	other := "controller"
	if other == e.Owner {
		other = "owner"
	}
	changed := &licenseBootElection{Incarnations: map[string]string{"owner": vector["owner"], "controller": vector["controller"]}, CertificateSHA256: "certificate"}
	for i := 3; i < 256; i++ {
		changed.Incarnations[other] = fmt.Sprintf("%032x", i)
		changed.Owner = licenseBootOwner(changed.Incarnations)
		if changed.Owner != e.Owner {
			break
		}
	}
	if changed.Owner == e.Owner {
		t.Fatal("no competing owner selected across restart vectors")
	}
	b.observeRound(changed)
	if b.SelectedOwner() != e.Owner || b.promise.digest() != e.digest() {
		t.Fatal("live owner released its promise")
	}
	if b.acceptPrepare(changed.Owner, changed) == nil {
		t.Fatal("live owner acknowledged a competing owner")
	}
}

func TestLicenseBootstrapRenewalPreferenceOverridesHash(t *testing.T) {
	r := bootRecord(t)
	vector := map[string]string{"owner": strings.Repeat("1", 32), "controller": strings.Repeat("2", 32)}
	hashed := licenseBootOwner(vector)
	preferred := "owner"
	if preferred == hashed {
		preferred = "controller"
	}
	retained := &LicenseBootstrap{record: *r, nodeID: preferred, incarnation: vector[preferred], digest: "certificate", preferSelf: true}
	other := &LicenseBootstrap{record: *r, nodeID: hashed, incarnation: vector[hashed], digest: "certificate"}
	ordinary := &licenseBootElection{Owner: hashed, Incarnations: vector, CertificateSHA256: "certificate"}
	if retained.acceptPrepare(hashed, ordinary) == nil {
		t.Fatal("renewal gave current data ownership to the hash winner")
	}
	renewal := &licenseBootElection{Owner: preferred, PreferredOwner: preferred, Incarnations: vector, CertificateSHA256: "certificate"}
	for _, node := range []*LicenseBootstrap{retained, other} {
		if err := node.acceptPrepare(preferred, renewal); err != nil {
			t.Fatal(err)
		}
	}
	if retained.status().PreferredOwner != preferred {
		t.Fatal("renewal preference not advertised")
	}
	withoutPreference := *renewal
	withoutPreference.PreferredOwner = ""
	if withoutPreference.digest() == renewal.digest() {
		t.Fatal("preference absent from election digest")
	}
	// Even a valid renewal preference cannot replace an already serving owner.
	other.promise = ordinary
	other.serving, other.selected = true, hashed
	if other.acceptPrepare(preferred, renewal) == nil {
		t.Fatal("renewal displaced a serving process")
	}
}

func TestLicenseBootstrapConflictingRenewalPreferences(t *testing.T) {
	r := bootRecord(t)
	vector := map[string]string{"owner": strings.Repeat("1", 32), "controller": strings.Repeat("2", 32)}
	nodes := map[string]*LicenseBootstrap{}
	for id, incarnation := range vector {
		nodes[id] = &LicenseBootstrap{record: *r, nodeID: id, incarnation: incarnation, digest: "certificate", preferSelf: true}
	}
	for id := range nodes {
		election := &licenseBootElection{Owner: id, PreferredOwner: id, Incarnations: vector, CertificateSHA256: "certificate"}
		acks := 0
		for _, node := range nodes {
			if node.acceptPrepare(id, election) == nil {
				acks++
			}
		}
		if acks == len(nodes) {
			t.Fatal("conflicting preferences reached unanimous preparation")
		}
	}
}

func TestLicenseBootstrapRenewalPreferenceLive(t *testing.T) {
	for _, conflict := range []bool{false, true} {
		t.Run(fmt.Sprint("conflict=", conflict), func(t *testing.T) {
			r := bootRecord(t)
			for id := range r.Participants {
				ln, err := net.Listen("tcp", "127.0.0.1:0")
				if err != nil {
					t.Fatal(err)
				}
				r.Participants[id] = ln.Addr().String()
				ln.Close()
			}
			timeout := 3 * time.Second
			if conflict {
				timeout = 300 * time.Millisecond
			}
			ctx, cancel := context.WithTimeout(context.Background(), timeout)
			defer cancel()
			type result struct {
				id  string
				err error
			}
			results := make(chan result, 2)
			nodes := make(map[string]*LicenseBootstrap)
			for id, addr := range r.Participants {
				b, err := StartLicenseBootstrap(&config.ClusterConfig{NodeID: id, ClusterName: "test", SharedSecret: "secret", RaftDataDir: t.TempDir(), CoordinatorAddr: addr}, r, zerolog.Nop(), id == "owner" || conflict)
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { b.Close() })
				nodes[id] = b
			}
			for id, b := range nodes {
				go func() { results <- result{id, b.WaitOwner(ctx)} }()
			}
			if conflict {
				for range nodes {
					outcome := <-results
					if outcome.err == nil || !strings.Contains(outcome.err.Error(), "conflicting bootstrap renewal owner preferences") {
						t.Fatalf("conflicting preference result: %s %v", outcome.id, outcome.err)
					}
				}
				return
			}
			outcome := <-results
			if outcome.err != nil || outcome.id != "owner" {
				t.Fatalf("renewal owner = %s, err=%v", outcome.id, outcome.err)
			}
		})
	}
}

func TestLicenseBootstrapControllerResumesReleaseAfterCrash(t *testing.T) {
	r := bootRecord(t)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	r.Participants["owner"] = ln.Addr().String()
	control, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	r.Participants["controller"] = control.Addr().String()
	control.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	peerResult := make(chan *LicenseBootstrap, 1)
	fail := make(chan error, 1)
	go func() {
		defer ln.Close()
		for {
			conn, e := ln.Accept()
			if e != nil {
				fail <- e
				return
			}
			msg, e := protocol.ReceiveMessage(conn, time.Second)
			if e != nil {
				conn.Close()
				fail <- e
				return
			}
			q := msg.Payload.(*protocol.LocalPoliciesQuery)
			if e = security.ValidateLocalPoliciesQueryHMAC("secret", q.Nonce, q.NodeID, q.ClusterName, q.Kind, q.Epoch, q.Timestamp, q.HMAC, security.HMACTimestampTolerance); e != nil {
				conn.Close()
				fail <- e
				return
			}
			status := protocol.LocalPoliciesRefused
			rows := json.RawMessage(`{}`)
			if q.Kind == lifecycleDurableKind {
				status = protocol.LocalPoliciesOK
				raw, _ := json.Marshal(r)
				digest := sha256.Sum256(raw)
				rows, _ = json.Marshal(licenseBootStatus{Owner: r.Owner, Generation: r.Generation, CertificateSHA256: hex.EncodeToString(digest[:])})
			}
			if q.Kind == "license_release_v1" && q.NodeID == "controller" && q.Epoch == r.Generation {
				status = protocol.LocalPoliciesOK
			}
			reply := &protocol.LocalPoliciesReply{NodeID: "owner", Status: status, Policies: rows, Timestamp: time.Now().Unix()}
			reply.HMAC = security.ComputeLocalPoliciesReplyHMAC("secret", q.Nonce, "owner", "test", q.Kind, q.Epoch, status, reply.Policies, reply.Timestamp)
			protocol.SendMessage(conn, &protocol.Message{Type: protocol.MsgLocalPoliciesReply, Payload: reply}, time.Second)
			conn.Close()
			if q.Kind == lifecycleReleaseKind && status == protocol.LocalPoliciesOK {
				ln.Close()
				peer, e := StartLicenseBootstrap(&config.ClusterConfig{NodeID: "owner", ClusterName: "test", SharedSecret: "secret", RaftDataDir: t.TempDir(), CoordinatorAddr: r.Participants["owner"]}, r, zerolog.Nop())
				if e != nil {
					fail <- e
					return
				}
				peerResult <- peer
				go peer.WaitOwner(ctx)
				return
			}
		}
	}()
	b, err := StartLicenseBootstrap(&config.ClusterConfig{NodeID: "controller", ClusterName: "test", SharedSecret: "secret", RaftDataDir: t.TempDir(), CoordinatorAddr: r.Participants["controller"]}, r, zerolog.Nop(), true)
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	if err := b.WaitOwner(ctx); err != nil {
		t.Fatal(err)
	}
	select {
	case peer := <-peerResult:
		defer peer.Close()
	case err := <-fail:
		t.Fatal(err)
	default:
		t.Fatal("peer was never released")
	}
	if !b.status().Serving {
		t.Fatal("controller did not recover unanimous OSS owner")
	}
}
