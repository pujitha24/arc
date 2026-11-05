package license

import (
	"testing"
	"time"
)

func TestLicenseChangedGrantIsPendingBeforeAnyFeatureGateOpens(t *testing.T) {
	l := &License{Tier: TierProfessional, MaxCores: 32, MaxMachines: 5, Features: []string{FeatureClustering}, Status: "active", ExpiresAt: time.Now().Add(time.Hour)}
	c := &Client{license: l}
	c.PinRuntimeLicense()
	refresh := *l
	refresh.ExpiresAt = refresh.ExpiresAt.Add(time.Hour)
	c.mu.Lock()
	c.storeRuntimeLicenseLocked(&refresh)
	c.mu.Unlock()
	if !c.CanUseClustering() || c.PendingRuntimeLicense() != nil {
		t.Fatal("time-only refresh interrupted runtime")
	}
	replacement := refresh
	replacement.MaxCores = 2
	replacement.MaxMachines = 3
	c.mu.Lock()
	c.storeRuntimeLicenseLocked(&replacement)
	c.mu.Unlock()
	if c.GetLicense() != nil || c.CanUseClustering() || c.PendingRuntimeLicense() != &replacement {
		t.Fatal("replacement exposed capacity before reconstruction")
	}
}
