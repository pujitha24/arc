package cluster

import (
	"context"
	"testing"
	"time"
)

func TestLicenseAdmissionDrainsWholeRequest(t *testing.T) {
	a := NewServiceAdmission(func() bool { return true })
	finish, ok := a.Enter()
	if !ok {
		t.Fatal("request refused")
	}
	done := make(chan error, 1)
	go func() { done <- a.CloseAndWait(context.Background()) }()
	deadline := time.Now().Add(time.Second)
	for {
		a.mu.Lock()
		closed := a.closed
		a.mu.Unlock()
		if closed {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("close not observed")
		}
		time.Sleep(time.Millisecond)
	}
	if _, ok := a.Enter(); ok {
		t.Fatal("admission reopened")
	}
	select {
	case <-done:
		t.Fatal("drain returned before admitted request")
	default:
	}
	finish()
	finish()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("drain stuck")
	}
}
