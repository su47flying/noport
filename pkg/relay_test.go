package pkg

import (
	"io"
	"net"
	"sync"
	"testing"
	"time"
)

func TestRelayStatsDirections(t *testing.T) {
	a, aPeer := net.Pipe()
	b, bPeer := net.Pipe()
	defer aPeer.Close()
	defer bPeer.Close()

	bufPool := &sync.Pool{New: func() any { return make([]byte, 1024) }}
	done := make(chan RelayStats, 1)
	go func() {
		done <- Relay(a, b, bufPool)
	}()

	if _, err := aPeer.Write([]byte("to-b")); err != nil {
		t.Fatalf("write a peer: %v", err)
	}
	gotB := make([]byte, 4)
	if _, err := io.ReadFull(bPeer, gotB); err != nil {
		t.Fatalf("read b peer: %v", err)
	}
	if string(gotB) != "to-b" {
		t.Fatalf("b peer got %q, want to-b", string(gotB))
	}

	if _, err := bPeer.Write([]byte("to-a")); err != nil {
		t.Fatalf("write b peer: %v", err)
	}
	gotA := make([]byte, 4)
	if _, err := io.ReadFull(aPeer, gotA); err != nil {
		t.Fatalf("read a peer: %v", err)
	}
	if string(gotA) != "to-a" {
		t.Fatalf("a peer got %q, want to-a", string(gotA))
	}

	_ = aPeer.Close()
	_ = bPeer.Close()

	select {
	case stats := <-done:
		if stats.AToB.Bytes != 4 {
			t.Fatalf("AToB bytes = %d, want 4", stats.AToB.Bytes)
		}
		if stats.BToA.Bytes != 4 {
			t.Fatalf("BToA bytes = %d, want 4", stats.BToA.Bytes)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Relay did not return")
	}
}
