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

func TestGetSessionChecksOutIdleSessionExclusively(t *testing.T) {
	dq := NewDataQueue(nil, false)

	c1, _ := newPipeConn(t)
	s1, _ := dq.AddConn(c1)
	c2, _ := newPipeConn(t)
	s2, _ := dq.AddConn(c2)
	c3, _ := newPipeConn(t)
	s3, _ := dq.AddConn(c3)

	// All sessions have 0 streams — should return and lease one idle session.
	got, err := dq.GetSession()
	if err != nil {
		t.Fatalf("GetSession failed: %v", err)
	}
	if got != s1 && got != s2 && got != s3 {
		t.Fatalf("GetSession returned unknown session %p", got)
	}
	if total, idle, busy := dq.PoolStats(); total != 3 || idle != 2 || busy != 1 {
		t.Fatalf("after first checkout stats = total:%d idle:%d busy:%d, want 3/2/1", total, idle, busy)
	}

	// The leased session must not be returned again.
	for i := 0; i < 2; i++ {
		next, err := dq.GetSession()
		if err != nil {
			t.Fatalf("GetSession[%d] failed: %v", i, err)
		}
		if next == got {
			t.Fatal("leased session was returned a second time")
		}
	}
	if _, err := dq.GetSession(); !errors.Is(err, ErrNoConnections) {
		t.Fatalf("expected ErrNoConnections after all sessions checked out, got %v", err)
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

func TestCloseSessionRetiresCheckedOutConnection(t *testing.T) {
	dq := NewDataQueue(nil, false)

	c1, _ := newPipeConn(t)
	s1, _ := dq.AddConn(c1)
	c2, _ := newPipeConn(t)
	_, _ = dq.AddConn(c2)

	got, err := dq.GetSession()
	if err != nil {
		t.Fatalf("GetSession failed: %v", err)
	}
	if got != s1 {
		t.Fatalf("expected first session, got %p want %p", got, s1)
	}

	dq.CloseSession(got)
	if got := dq.Size(); got != 1 {
		t.Fatalf("expected pool size 1 after retiring checked-out session, got %d", got)
	}
	if total, idle, busy := dq.PoolStats(); total != 1 || idle != 1 || busy != 0 {
		t.Fatalf("stats after CloseSession = total:%d idle:%d busy:%d, want 1/1/0", total, idle, busy)
	}
}

func TestCloseIdleExcessOnlyClosesIdle(t *testing.T) {
	dq := NewDataQueue(nil, false)

	for i := 0; i < 5; i++ {
		c, _ := newPipeConn(t)
		if _, err := dq.AddConn(c); err != nil {
			t.Fatalf("AddConn[%d]: %v", i, err)
		}
	}

	leased, err := dq.GetSession()
	if err != nil {
		t.Fatalf("GetSession failed: %v", err)
	}

	closed := dq.CloseIdleExcess(2)
	if closed != 2 {
		t.Fatalf("CloseIdleExcess closed %d, want 2", closed)
	}
	if total, idle, busy := dq.PoolStats(); total != 3 || idle != 2 || busy != 1 {
		t.Fatalf("stats after trim = total:%d idle:%d busy:%d, want 3/2/1", total, idle, busy)
	}

	// The checked-out session was busy and must not be trimmed.
	dq.CloseSession(leased)
	if total, idle, busy := dq.PoolStats(); total != 2 || idle != 2 || busy != 0 {
		t.Fatalf("stats after retiring busy session = total:%d idle:%d busy:%d, want 2/2/0", total, idle, busy)
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
