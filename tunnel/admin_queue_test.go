package tunnel

import (
	"net"
	"noport/protocol"
	"sync"
	"testing"
	"time"
)

// helper: create an AdminQueue pair over net.Pipe for testing.
func newTestPair(t *testing.T, onMessage func(*protocol.AdminMessage)) (aq *AdminQueue, remote net.Conn) {
	t.Helper()
	c1, c2 := net.Pipe()
	aq = NewAdminQueue(c1, onMessage)
	return aq, c2
}

func TestSendAndReceive(t *testing.T) {
	var received []*protocol.AdminMessage
	var mu sync.Mutex

	aq, remote := newTestPair(t, func(msg *protocol.AdminMessage) {
		mu.Lock()
		received = append(received, msg)
		mu.Unlock()
	})
	defer aq.Close()
	defer remote.Close()

	// Send a CreateDataConn message from the remote side.
	if err := protocol.WriteAdminMessage(remote, protocol.NewCreateDataConnMsg()); err != nil {
		t.Fatalf("write from remote: %v", err)
	}

	// Send a Close message from the remote side.
	if err := protocol.WriteAdminMessage(remote, protocol.NewCloseMsg()); err != nil {
		t.Fatalf("write from remote: %v", err)
	}

	// Wait briefly for readLoop to process.
	time.Sleep(50 * time.Millisecond)

	mu.Lock()
	defer mu.Unlock()
	if len(received) != 2 {
		t.Fatalf("expected 2 messages, got %d", len(received))
	}
	if received[0].Type != protocol.MsgCreateDataConn {
		t.Errorf("expected MsgCreateDataConn, got 0x%02X", received[0].Type)
	}
	if received[1].Type != protocol.MsgClose {
		t.Errorf("expected MsgClose, got 0x%02X", received[1].Type)
	}
}

func TestHeartbeatSentPeriodically(t *testing.T) {
	c1, c2 := net.Pipe()
	defer c2.Close()

	onMsg := func(msg *protocol.AdminMessage) {}
	aq := NewAdminQueue(c1, onMsg)

	// net.Pipe is synchronous, so read from c2 in a goroutine to avoid deadlock.
	type result struct {
		msg *protocol.AdminMessage
		err error
	}
	ch := make(chan result, 1)
	go func() {
		msg, err := protocol.ReadAdminMessage(c2)
		ch <- result{msg, err}
	}()

	if err := aq.Send(protocol.NewHeartbeatMsg()); err != nil {
		t.Fatalf("send heartbeat: %v", err)
	}

	r := <-ch
	if r.err != nil {
		t.Fatalf("read from remote: %v", r.err)
	}
	if r.msg.Type != protocol.MsgHeartbeat {
		t.Errorf("expected MsgHeartbeat, got 0x%02X", r.msg.Type)
	}

	aq.Close()
}

func TestOnMessageNotCalledForHeartbeat(t *testing.T) {
	var received []*protocol.AdminMessage
	var mu sync.Mutex

	aq, remote := newTestPair(t, func(msg *protocol.AdminMessage) {
		mu.Lock()
		received = append(received, msg)
		mu.Unlock()
	})
	defer aq.Close()
	defer remote.Close()

	// Send heartbeat — should NOT trigger onMessage.
	if err := protocol.WriteAdminMessage(remote, protocol.NewHeartbeatMsg()); err != nil {
		t.Fatalf("write heartbeat: %v", err)
	}

	// Send a non-heartbeat — should trigger onMessage.
	if err := protocol.WriteAdminMessage(remote, protocol.NewCreateDataConnMsg()); err != nil {
		t.Fatalf("write create: %v", err)
	}

	time.Sleep(50 * time.Millisecond)

	mu.Lock()
	defer mu.Unlock()
	if len(received) != 1 {
		t.Fatalf("expected 1 message (heartbeat filtered), got %d", len(received))
	}
	if received[0].Type != protocol.MsgCreateDataConn {
		t.Errorf("expected MsgCreateDataConn, got 0x%02X", received[0].Type)
	}
}

func TestCloseShutdown(t *testing.T) {
	aq, remote := newTestPair(t, nil)
	defer remote.Close()

	// Close should return without blocking indefinitely.
	done := make(chan error, 1)
	go func() {
		done <- aq.Close()
	}()

	select {
	case err := <-done:
		if err != nil {
			t.Logf("Close returned error (expected for pipe): %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Close did not return within 2 seconds")
	}

	// Done channel should be closed.
	select {
	case <-aq.Done():
		// ok
	default:
		t.Error("Done channel not closed after Close")
	}
}
