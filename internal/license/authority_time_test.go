package license

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"sync/atomic"
	"testing"
	"time"
)

func signedTimeFor(t *testing.T, nonce, key, fp, file string, now time.Time, mutate func(*AuthorityTime)) (string, string) {
	t.Helper()
	payload, err := base64.StdEncoding.DecodeString(file)
	if err != nil {
		t.Fatal(err)
	}
	kh, ph := sha256.Sum256([]byte(key)), sha256.Sum256(payload)
	grant := AuthorityTime{Version: 1, Purpose: "arc-license-time", Nonce: nonce, LicenseKeySHA256: hex.EncodeToString(kh[:]), MachineFingerprint: fp, LicenseSHA256: hex.EncodeToString(ph[:]), ServerTime: now}
	if mutate != nil {
		mutate(&grant)
	}
	raw, err := json.Marshal(grant)
	if err != nil {
		t.Fatal(err)
	}
	return signDetachedRaw(t, rsaKey1, raw)
}

func TestAuthorityTimeRejectsReplayAndBindingSubstitution(t *testing.T) {
	withTestPublicKey(t, &rsaKey1.PublicKey)
	nonce, err := timeNonce()
	if err != nil {
		t.Fatal(err)
	}
	file, sig := signDetached(t, rsaKey1, &SignedLicense{Version: 1, LicenseKey: "configured-key", MachineFingerprint: "machine", ExpiresAt: time.Now().Add(time.Hour)})
	if _, err := VerifyLicenseFile(file, sig); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name   string
		mutate func(*AuthorityTime)
	}{
		{"valid", nil},
		{"replay", func(g *AuthorityTime) { g.Nonce = "old-request" }},
		{"other-key", func(g *AuthorityTime) { g.LicenseKeySHA256 = "wrong" }},
		{"other-machine", func(g *AuthorityTime) { g.MachineFingerprint = "other" }},
		{"other-payload", func(g *AuthorityTime) { g.LicenseSHA256 = "wrong" }},
		{"other-purpose", func(g *AuthorityTime) { g.Purpose = "other" }},
		{"unknown-version", func(g *AuthorityTime) { g.Version = 2 }},
		{"missing-time", func(g *AuthorityTime) { g.ServerTime = time.Time{} }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a, b := signedTimeFor(t, nonce, "configured-key", "machine", file, time.Now().UTC(), tc.mutate)
			_, err := verifyAuthorityTime(a, b, nonce, "configured-key", "machine", file)
			if (err == nil) != (tc.mutate == nil) {
				t.Fatalf("binding outcome=%v", err)
			}
		})
	}
}

func TestAuthorityClockAdvancesThroughEveryPredicateWithoutWallTime(t *testing.T) {
	start := time.Now()
	tick := start
	clock := &authorityClock{tick: func() time.Time { return tick }, origin: time.Date(2099, 1, 1, 0, 0, 0, 0, time.UTC), at: start}
	server := time.Date(2026, 11, 5, 0, 0, 0, 0, time.UTC)
	if err := clock.accept(&AuthorityTime{ServerTime: server}, start); err != nil {
		t.Fatal(err)
	}
	l := &License{Tier: TierEnterprise, ExpiresAt: server.Add(time.Hour), Features: []string{FeatureClustering, FeatureTieredStorage}, clock: clock}
	if !l.IsValid() || !l.HasFeature(FeatureClustering) {
		t.Fatal("local future date overrode signed time")
	}
	tick = tick.Add(2 * time.Hour)
	if l.IsValid() || l.HasFeature(FeatureClustering) || l.CanUseTieredStorage() {
		t.Fatal("elapsed process time did not expire all direct gates")
	}
	before := clock.now()
	if err := clock.accept(&AuthorityTime{ServerTime: server.Add(-time.Hour)}, tick); err == nil {
		t.Fatal("backward server refresh accepted")
	}
	if !clock.now().Equal(before) || l.IsValid() {
		t.Fatal("rejected refresh resurrected license")
	}
	if err := clock.accept(&AuthorityTime{ServerTime: server.Add(time.Minute)}, tick); err != nil {
		t.Fatal(err)
	}
	if clock.now().Before(before) || l.IsValid() {
		t.Fatal("shorter request timing moved trusted time backwards")
	}
	if err := clock.accept(&AuthorityTime{ServerTime: server.Add(3 * time.Hour)}, tick.Add(-31*time.Second)); err == nil {
		t.Fatal("delayed proof accepted")
	}
}

func TestOnlineClientRequiresFreshSignedTimeAndKeepsPreviousEntitlementOnReplay(t *testing.T) {
	var c *Client
	var replay bool
	var previousFile, previousSig string
	serverNow := time.Date(2026, 11, 5, 0, 0, 0, 0, time.UTC)
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		file, sig := runtimePair(t, c, serverNow.Add(time.Hour))
		nonce := r.URL.Query().Get("time_nonce")
		a, b := signedTimeFor(t, nonce, c.licenseKey, c.fingerprint, file, serverNow, nil)
		if replay {
			a, b = previousFile, previousSig
		} else {
			previousFile, previousSig = a, b
		}
		_ = json.NewEncoder(w).Encode(VerifyResponse{Valid: true, LicenseFile: file, LicenseSignature: sig, TimeFile: a, TimeSignature: b})
	}))
	defer ts.Close()
	c = newTestClient(t, ts.URL, t.TempDir())
	c.requireAuthorityTime = true
	if _, err := c.ActivateOrVerify(context.Background()); err != nil {
		t.Fatal(err)
	}
	assertRuntimeGates(t, c, true)
	if c.HealthStatus().ClockSource != "license_server" {
		t.Fatal("clock source not reported")
	}
	old := c.GetLicense()
	replay = true
	if _, err := c.ActivateOrVerify(context.Background()); err == nil || FailureClassOf(err) != ClassTransient {
		t.Fatalf("replay=%v", err)
	}
	if c.GetLicense() != old || !c.IsValid() {
		t.Fatal("untrusted refresh replaced current entitlement")
	}
}

func TestOnlineCacheCannotAuthorizeRestartWithoutFreshServerTime(t *testing.T) {
	c := newTestClient(t, "http://127.0.0.1:1", t.TempDir())
	file, sig := runtimePair(t, c, time.Now().Add(time.Hour))
	c.saveCache(file, sig)
	c.requireAuthorityTime = true
	if _, err := c.LoadCachedLicense(); err == nil {
		t.Fatal("online restart accepted cached local time")
	}
	if c.GetLicense() != nil {
		t.Fatal("cached entitlement became active")
	}
	// Requiring fresh time must not destroy signed data needed for recovery.
	if _, err := os.Stat(c.cachePath()); err != nil {
		t.Fatal(err)
	}
}

func TestOnlineAuthorityOutageWaitIsCancelableAndDoesNotActivateCache(t *testing.T) {
	c := newTestClient(t, "http://127.0.0.1:1", t.TempDir())
	file, sig := runtimePair(t, c, time.Now().Add(time.Hour))
	c.saveCache(file, sig)
	c.requireAuthorityTime = true
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	if _, _, err := c.AwaitOnlineAuthority(ctx); err == nil {
		t.Fatal("authority outage unexpectedly authorized startup")
	}
	if c.GetLicense() != nil {
		t.Fatal("waiting process activated cached entitlement")
	}
}

func TestRequestedPolicyCannotDowngradeToLegacyResponse(t *testing.T) {
	var c *Client
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		file, sig := runtimePair(t, c, time.Now().Add(time.Hour))
		a, b := signedTimeFor(t, r.URL.Query().Get("time_nonce"), c.licenseKey, c.fingerprint, file, time.Now().UTC(), nil)
		_ = json.NewEncoder(w).Encode(VerifyResponse{Valid: true, LicenseFile: file, LicenseSignature: sig, TimeFile: a, TimeSignature: b})
	}))
	defer ts.Close()
	c = newTestClient(t, ts.URL, t.TempDir())
	c.requireAuthorityTime = true
	c.policyProtocol = 2
	if _, err := c.Verify(context.Background()); err == nil || FailureClassOf(err) != ClassTransient {
		t.Fatalf("policy stripping accepted: %v", err)
	}
	if c.GetLicense() != nil || c.runtimeClock().source() == "license_server" {
		t.Fatal("downgraded response installed state")
	}
}

func TestUnavailableClockDoesNotAuthorizeOrTriggerFinalOSSPhase(t *testing.T) {
	term := time.Now().Add(time.Hour)
	p := &ExpiryPolicy{Version: 1, Kind: "paid", TermEndsAt: term, GraceDays: 14}
	clock := &authorityClock{tick: func() time.Time { return time.Time{} }, origin: time.Now(), at: time.Now(), trusted: true}
	l := &License{ExpiresAt: p.cutoff(), Policy: p, clock: clock}
	if l.IsValid() || l.ExpiryState().Phase != PhaseAuthorityUnavailable || clock.source() != "unavailable" {
		t.Fatal("clock failure extended entitlement or pretended to authorize final handoff")
	}
	c := &Client{license: l}
	if got := c.HealthStatus(); got.Status != "time_unavailable" || got.ClockSource != "unavailable" || got.EvaluatedAt != nil {
		t.Fatalf("clock failure health misleading: %+v", got)
	}
}

func TestAuthorityClockDoesNotAuthorizeDifferentCachedPayload(t *testing.T) {
	c := newTestClient(t, "http://127.0.0.1:1", t.TempDir())
	oldFile, oldSig := runtimePair(t, c, time.Now().Add(time.Hour))
	c.saveCache(oldFile, oldSig)
	newFile, _ := signDetached(t, rsaKey1, &SignedLicense{Version: 1, LicenseKey: c.licenseKey, MachineFingerprint: c.fingerprint, ExpiresAt: time.Now().Add(time.Hour), Tier: TierStarter})
	nonce, _ := timeNonce()
	a, b := signedTimeFor(t, nonce, c.licenseKey, c.fingerprint, newFile, time.Now().UTC(), nil)
	grant, err := verifyAuthorityTime(a, b, nonce, c.licenseKey, c.fingerprint, newFile)
	if err != nil {
		t.Fatal(err)
	}
	clock := c.runtimeClock()
	if err := clock.accept(grant, clock.tick()); err != nil {
		t.Fatal(err)
	}
	c.requireAuthorityTime = true
	if _, err := c.LoadCachedLicense(); err == nil {
		t.Fatal("fresh clock for lower-capacity payload restored an older higher-capacity cache")
	}
}

func TestDefinitiveRejectionInvalidatesAnchoredCacheEligibility(t *testing.T) {
	var phase atomic.Int32
	var c *Client
	var file, signature string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch phase.Load() {
		case 1:
			_ = json.NewEncoder(w).Encode(VerifyResponse{Valid: false, Error: "license is suspended"})
		case 2:
			w.WriteHeader(http.StatusServiceUnavailable)
		default:
			a, b := signedTimeFor(t, r.URL.Query().Get("time_nonce"), c.licenseKey, c.fingerprint, file, time.Now().UTC(), nil)
			_ = json.NewEncoder(w).Encode(VerifyResponse{Valid: true, LicenseFile: file, LicenseSignature: signature, TimeFile: a, TimeSignature: b})
		}
	}))
	defer server.Close()
	c = newTestClient(t, server.URL, t.TempDir())
	c.requireAuthorityTime = true
	file, signature = runtimePair(t, c, time.Now().Add(time.Hour))
	if _, err := c.ActivateOrVerify(context.Background()); err != nil {
		t.Fatal(err)
	}
	before := c.runtimeClock().now()
	phase.Store(1)
	if _, err := c.ActivateOrVerify(context.Background()); FailureClassOf(err) != ClassDefinitive {
		t.Fatalf("expected definitive rejection: %v", err)
	}
	// Recreate the exact on-disk state left by a failed unlink, or a restored
	// stale cache. Its signature is valid; the server has rejected its use.
	c.saveCache(file, signature)
	if _, err := c.LoadCachedLicense(); err == nil || c.IsValid() {
		t.Fatal("definitively rejected cache resurrected in an anchored process")
	}
	if c.runtimeClock().now().Before(before) || c.runtimeClock().source() != "license_server" {
		t.Fatal("invalidating entitlement must retain the trusted time anchor")
	}
	phase.Store(2)
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if _, _, err := c.ActivateOrVerifyResilient(ctx); err == nil || c.GetLicense() != nil {
		t.Fatal("transient retry restored rejected cached entitlement")
	}
}
