package license

import (
	"errors"
	"testing"
	"time"
)

func TestPaidUTCExpiryPolicyBoundaries(t *testing.T) {
	term := time.Date(2026, 11, 5, 12, 30, 0, 0, time.UTC)
	p := &ExpiryPolicy{Version: 1, Kind: "paid", TermEndsAt: term, GraceDays: 14}
	if err := p.validate(time.Date(2026, 11, 20, 0, 0, 0, 0, time.UTC)); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		at                     string
		phase                  Phase
		day                    int
		valid, manage, migrate bool
	}{
		{"2026-11-05T12:29:59Z", PhaseActive, 0, true, true, true},
		{"2026-11-05T12:30:00Z", PhaseExpirationDay, 0, true, true, true},
		{"2026-11-06T00:00:00Z", PhaseGrace, 1, true, true, true},
		{"2026-11-12T23:59:59Z", PhaseGrace, 7, true, true, true},
		{"2026-11-13T00:00:00Z", PhaseReducedRoles, 8, true, true, true},
		{"2026-11-14T00:00:00Z", PhaseRBACReadOnly, 9, true, false, true},
		{"2026-11-15T00:00:00Z", PhaseTieringReadOnly, 10, true, false, false},
		{"2026-11-19T23:59:59Z", PhaseTieringReadOnly, 14, true, false, false},
		{"2026-11-20T00:00:00Z", PhaseOSS, 0, false, false, false},
	} {
		t.Run(tc.at, func(t *testing.T) {
			now, err := time.Parse(time.RFC3339, tc.at)
			if err != nil {
				t.Fatal(err)
			}
			tick := time.Now()
			l := &License{Policy: p, ExpiresAt: p.cutoff(), Features: []string{FeatureRBAC, FeatureTieredStorage}, clock: &authorityClock{tick: func() time.Time { return tick }, origin: now, at: tick, trusted: true}}
			got := l.ExpiryState()
			if got.Phase != tc.phase || got.GraceDay != tc.day || l.IsValid() != tc.valid || l.CanManageRBAC() != tc.manage || l.CanMigrateTieredStorage() != tc.migrate {
				t.Fatalf("state=%+v valid=%v management=%v migration=%v", got, l.IsValid(), l.CanManageRBAC(), l.CanMigrateTieredStorage())
			}
			if tc.valid && !l.HasFeature(FeatureRBAC) {
				t.Fatal("management restriction removed data authorization entitlement")
			}
		})
	}
	// Host locale and DST offsets do not redefine a UTC calendar day.
	at := time.Date(2026, 11, 13, 0, 0, 0, 0, time.UTC)
	if p.state(at.In(time.FixedZone("operator", -3*3600))).Phase != PhaseReducedRoles {
		t.Fatal("operator timezone changed phase")
	}
}

func TestTrialExpiryNeverGetsPaidGrace(t *testing.T) {
	term := time.Date(2026, 11, 5, 12, 30, 0, 0, time.UTC)
	p := &ExpiryPolicy{Version: 1, Kind: "trial", TermEndsAt: term}
	if err := p.validate(term); err != nil {
		t.Fatal(err)
	}
	if !p.state(term.Add(-time.Nanosecond)).Valid || p.state(term).Valid || p.state(term.Add(7*24*time.Hour)).Valid {
		t.Fatal("trial boundary/grace incorrect")
	}
	for _, bad := range []*ExpiryPolicy{{Version: 2, Kind: "paid", TermEndsAt: term, GraceDays: 14}, {Version: 1, Kind: "trial", TermEndsAt: term, GraceDays: 14}, {Version: 1, Kind: "paid", TermEndsAt: term, GraceDays: 0}} {
		if bad.validate(term) == nil {
			t.Fatalf("invalid policy accepted: %+v", bad)
		}
	}
	legacy := &License{ExpiresAt: time.Now().Add(-time.Minute)}
	if legacy.IsValid() {
		t.Fatal("legacy signed expiry silently acquired extra grace")
	}
}

func TestSignedPolicyCannotContradictFinalExpiry(t *testing.T) {
	withTestPublicKey(t, &rsaKey1.PublicKey)
	term := time.Date(2026, 11, 5, 12, 0, 0, 0, time.UTC)
	file, sig := signDetached(t, rsaKey1, &SignedLicense{Version: 1, LicenseKey: "test", ExpiresAt: term, Policy: &ExpiryPolicy{Version: 1, Kind: "paid", TermEndsAt: term, GraceDays: 14}})
	if _, err := VerifyLicenseFile(file, sig); !errors.Is(err, ErrMalformedSignedLicense) {
		t.Fatalf("contradictory policy was not rejected: %v", err)
	}
}
