package tunnel

import (
	"errors"
	"net"
	"testing"
)

func newPipeConn(t *testing.T) (net.Conn, net.Conn) {
	t.Helper()
	c1, c2 := net.Pipe()
	t.Cleanup(func() {
		c1.Close()
		c2.Close()
	})
	return c1, c2
}

func TestNewDataQueue(t *testing.T) {
	dq := NewDataQueue(nil, false)
	if dq == nil {
		t.Fatal("expected non-nil DataQueue")
	}
	if dq.Size() != 0 {
		t.Fatalf("expected empty pool, got size %d", dq.Size())
	}
}

func TestAddConn(t *testing.T) {
	dq := NewDataQueue(nil, true)

	c1, _ := newPipeConn(t)
	session, err := dq.AddConn(c1)
	if err != nil {
		t.Fatalf("AddConn failed: %v", err)
	}
	if session == nil {
		t.Fatal("expected non-nil session")
	}
	if dq.Size() != 1 {
		t.Fatalf("expected pool size 1, got %d", dq.Size())
	}

	c2, _ := newPipeConn(t)
	_, err = dq.AddConn(c2)
	if err != nil {
		t.Fatalf("AddConn failed: %v", err)
	}
	if dq.Size() != 2 {
		t.Fatalf("expected pool size 2, got %d", dq.Size())
	}
}

func TestGetSessionLeastLoaded(t *testing.T) {
	dq := NewDataQueue(nil, false)

	c1, _ := newPipeConn(t)
	s1, _ := dq.AddConn(c1)
	c2, _ := newPipeConn(t)
	s2, _ := dq.AddConn(c2)
	c3, _ := newPipeConn(t)
	s3, _ := dq.AddConn(c3)

	// All sessions have 0 streams — should return a valid session
	got, err := dq.GetSession()
	if err != nil {
		t.Fatalf("GetSession failed: %v", err)
	}
	if got != s1 && got != s2 && got != s3 {
		t.Fatalf("GetSession returned unknown session %p", got)
	}

	// Simulate load on s1 by directly adding fake streams to its map
	s1.mu.Lock()
	s1.streams[100] = newMuxStream(100, s1)
	s1.streams[101] = newMuxStream(101, s1)
	s1.mu.Unlock()

	s2.mu.Lock()
	s2.streams[200] = newMuxStream(200, s2)
	s2.mu.Unlock()

	// s3 has 0 streams, s2 has 1, s1 has 2 — should pick s3
	got, err = dq.GetSession()
	if err != nil {
		t.Fatalf("GetSession failed: %v", err)
	}
	if got != s3 {
		t.Fatalf("GetSession should return least loaded session s3, got %p (s1=%p s2=%p s3=%p)",
			got, s1, s2, s3)
	}
}

func TestGetSessionEmptyPool(t *testing.T) {
	dq := NewDataQueue(nil, false)

	_, err := dq.GetSession()
	if !errors.Is(err, ErrNoConnections) {
		t.Fatalf("expected ErrNoConnections, got %v", err)
	}
}

func TestRemoveSession(t *testing.T) {
	dq := NewDataQueue(nil, false)

	c1, _ := newPipeConn(t)
	s1, _ := dq.AddConn(c1)
	c2, _ := newPipeConn(t)
	_, _ = dq.AddConn(c2)

	if dq.Size() != 2 {
		t.Fatalf("expected pool size 2, got %d", dq.Size())
	}

	dq.RemoveSession(s1)
	if dq.Size() != 1 {
		t.Fatalf("expected pool size 1 after remove, got %d", dq.Size())
	}

	// Removing same session again is a no-op
	dq.RemoveSession(s1)
	if dq.Size() != 1 {
		t.Fatalf("expected pool size 1 after duplicate remove, got %d", dq.Size())
	}
}

func TestClose(t *testing.T) {
	dq := NewDataQueue(nil, true)

	c1, _ := newPipeConn(t)
	_, _ = dq.AddConn(c1)
	c2, _ := newPipeConn(t)
	_, _ = dq.AddConn(c2)

	err := dq.Close()
	if err != nil {
		t.Fatalf("Close failed: %v", err)
	}

	if dq.Size() != 0 {
		t.Fatalf("expected pool size 0 after close, got %d", dq.Size())
	}

	// AddConn on closed pool should fail
	c3, _ := newPipeConn(t)
	_, err = dq.AddConn(c3)
	if !errors.Is(err, ErrPoolClosed) {
		t.Fatalf("expected ErrPoolClosed, got %v", err)
	}

	// GetSession on closed pool should fail
	_, err = dq.GetSession()
	if !errors.Is(err, ErrPoolClosed) {
		t.Fatalf("expected ErrPoolClosed on GetSession, got %v", err)
	}

	// Double close is safe
	err = dq.Close()
	if err != nil {
		t.Fatalf("double Close failed: %v", err)
	}
}

func TestSessions(t *testing.T) {
	dq := NewDataQueue(nil, false)

	c1, _ := newPipeConn(t)
	s1, _ := dq.AddConn(c1)
	c2, _ := newPipeConn(t)
	s2, _ := dq.AddConn(c2)

	sessions := dq.Sessions()
	if len(sessions) != 2 {
		t.Fatalf("expected 2 sessions, got %d", len(sessions))
	}
	if sessions[0] != s1 || sessions[1] != s2 {
		t.Fatal("sessions snapshot does not match expected sessions")
	}
}
