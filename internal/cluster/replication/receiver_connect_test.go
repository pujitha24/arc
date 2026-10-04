package replication

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/rs/zerolog"
)

// A writer that accepts the connection and then stalls mid-TLS-handshake must
// not hold connect() after the receiver's context is cancelled.
func TestReceiverConnect_CancelInterruptsAStalledHandshake(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	accepted := make(chan struct{})
	release := make(chan struct{})
	defer close(release)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		close(accepted)
		<-release
		conn.Close()
	}()

	r := NewReceiver(&ReceiverConfig{
		ReaderID:     "reader-1",
		WriterAddr:   ln.Addr().String(),
		SharedSecret: "test-cluster-secret-32-bytes-long!",
		TLSConfig:    &tls.Config{InsecureSkipVerify: true}, //nolint:gosec // test peer
		Logger:       zerolog.Nop(),
	})
	var cancel context.CancelFunc
	r.ctx, cancel = context.WithCancel(context.Background())
	defer cancel()
	go func() {
		<-accepted
		cancel()
	}()

	start := time.Now()
	err = r.connect()
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v, want errors.Is(context.Canceled)", err)
	}
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Fatalf("took %v; cancellation did not interrupt the handshake", elapsed)
	}
}
