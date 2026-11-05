package ingest

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestLicenseDrainJoinsAlreadyAdmittedMQTTRequest(t *testing.T) {
	b := &ArrowBuffer{}
	b.TrackLiveAdmission()
	_, release, err := b.AdmitRequest(context.Background(), 0)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if !errors.Is(b.CloseLiveAdmission(ctx), context.DeadlineExceeded) {
		t.Fatal("drain skipped active request")
	}
	if _, _, err := b.AdmitRequest(context.Background(), 0); !errors.Is(err, ErrIngestFenced) {
		t.Fatal("admitted request after close")
	}
	release()
	release()
	if err := b.CloseLiveAdmission(context.Background()); err != nil {
		t.Fatal(err)
	}
}
