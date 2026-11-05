package main

import (
	"context"
	"testing"
	"time"
)

func TestLicenseMaintenanceFailureCanResumeRecovery(t *testing.T) {
	requests := make(chan licenseMaintenancePause)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	resumed := make(chan struct{})
	go func() { p := <-requests; p.wait(ctx); close(resumed) }()
	resume, err := pauseLicenseMaintenance(ctx, requests)
	if err != nil {
		t.Fatal(err)
	}
	select {
	case <-resumed:
		t.Fatal("maintenance ran inside drain barrier")
	default:
	}
	// A drain failure must resume rather than cancel the only recovery worker.
	resume()
	resume()
	select {
	case <-resumed:
	case <-time.After(time.Second):
		t.Fatal("recovery remained stopped")
	}
}
