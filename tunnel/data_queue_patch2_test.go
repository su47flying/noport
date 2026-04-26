package tunnel

import (
	"testing"
	"time"
)

// addThree adds three sessions and returns them in pool order.
func addThree(t *testing.T, dq *DataQueue) []*MuxSession {
	t.Helper()
	out := make([]*MuxSession, 0, 3)
	for i := 0; i < 3; i++ {
		c1, _ := newPipeConn(t)
		s, err := dq.AddConn(c1)
		if err != nil {
			t.Fatalf("AddConn[%d]: %v", i, err)
		}
		out = append(out, s)
	}
	return out
}

func TestGetSessionForTargetNonHeavyUsesSharedPool(t *testing.T) {
	dq := NewDataQueue(nil, true)
	defer dq.Close()
	hh := NewHeavyHostSet(time.Hour)
	defer hh.Close()

	sessions := addThree(t, dq)

	// All three are equally idle, so the picker may return any of them,
	// but it must NOT reserve any for the host.
	got, reserved, err := dq.GetSessionForTarget("api.example.com:443", hh)
	if err != nil {
		t.Fatalf("GetSessionForTarget: %v", err)
	}
	if reserved {
		t.Fatal("non-heavy host should not produce a reservation")
	}
	found := false
	for _, s := range sessions {
		if s == got {
			found = true
		}
	}
	if !found {
		t.Fatal("returned session not in pool")
	}
	if len(dq.reservations) != 0 {
		t.Fatalf("expected 0 reservations, got %v", dq.reservations)
	}
}

func TestGetSessionForTargetHeavyReservesAndReuses(t *testing.T) {
	dq := NewDataQueue(nil, true)
	defer dq.Close()
	hh := NewHeavyHostSet(time.Hour)
	defer hh.Close()

	addThree(t, dq)
	hh.Mark("video.example.com")

	first, reserved, err := dq.GetSessionForTarget("video.example.com:443", hh)
	if err != nil {
		t.Fatalf("first GetSessionForTarget: %v", err)
	}
	if !reserved {
		t.Fatal("heavy host should produce a reservation on first call")
	}

	// Subsequent calls for the same host MUST return the same session.
	for i := 0; i < 5; i++ {
		again, reserved2, err := dq.GetSessionForTarget("video.example.com:8443", hh)
		if err != nil {
			t.Fatalf("repeat[%d]: %v", i, err)
		}
		if !reserved2 {
			t.Fatalf("repeat[%d]: expected reserved=true", i)
		}
		if again != first {
			t.Fatalf("repeat[%d]: got different session %d, want %d",
				i, again.ID(), first.ID())
		}
	}
}

func TestNonHeavyTrafficSkipsReservedSession(t *testing.T) {
	dq := NewDataQueue(nil, true)
	defer dq.Close()
	hh := NewHeavyHostSet(time.Hour)
	defer hh.Close()

	sessions := addThree(t, dq)
	hh.Mark("video.example.com")

	// Reserve one session for the heavy host.
	dedicated, _, err := dq.GetSessionForTarget("video.example.com:443", hh)
	if err != nil {
		t.Fatalf("reserve: %v", err)
	}

	// Non-heavy traffic should never land on the dedicated session.
	for i := 0; i < 30; i++ {
		s, _, err := dq.GetSessionForTarget("api.example.com:443", hh)
		if err != nil {
			t.Fatalf("non-heavy[%d]: %v", i, err)
		}
		if s == dedicated {
			t.Fatalf("non-heavy traffic landed on dedicated session %d",
				dedicated.ID())
		}
	}

	// Same goes for the legacy GetSession() entry point.
	for i := 0; i < 30; i++ {
		s, err := dq.GetSession()
		if err != nil {
			t.Fatalf("legacy[%d]: %v", i, err)
		}
		if s == dedicated {
			t.Fatalf("legacy GetSession returned dedicated session")
		}
	}

	// Sanity: at least one non-dedicated session is still selectable.
	// (Tie-breaking among equally-idle sessions is deterministic, so we
	// don't require *every* non-dedicated session to be picked.)
	picked := false
	for i := 0; i < 30; i++ {
		s, _ := dq.GetSession()
		for _, sess := range sessions {
			if sess == s && sess != dedicated {
				picked = true
			}
		}
	}
	if !picked {
		t.Errorf("no non-dedicated session was ever selected")
	}
}

func TestHeavyHostWithExhaustedPoolFallsBackCleanly(t *testing.T) {
	dq := NewDataQueue(nil, true)
	defer dq.Close()
	hh := NewHeavyHostSet(time.Hour)
	defer hh.Close()

	c1, _ := newPipeConn(t)
	only, _ := dq.AddConn(c1)
	hh.Mark("a.example.com")

	// First heavy host claims the only session.
	got, reserved, err := dq.GetSessionForTarget("a.example.com:443", hh)
	if err != nil {
		t.Fatalf("first heavy: %v", err)
	}
	if got != only || !reserved {
		t.Fatalf("expected the sole session reserved")
	}

	// Second heavy host has no unreserved session left → must error so
	// the caller can trigger pool replenishment via admin.
	hh.Mark("b.example.com")
	_, _, err = dq.GetSessionForTarget("b.example.com:443", hh)
	if err == nil {
		t.Fatal("expected ErrNoConnections when no unreserved session")
	}

	// Non-heavy traffic should also error, since the only session is
	// reserved away — caller will replenish.
	_, _, err = dq.GetSessionForTarget("c.example.com:443", hh)
	if err == nil {
		t.Fatal("expected error for non-heavy with all sessions reserved")
	}
}

func TestReleaseExpiredReservationsReturnsSessionToSharedPool(t *testing.T) {
	dq := NewDataQueue(nil, true)
	defer dq.Close()
	hh := NewHeavyHostSet(20 * time.Millisecond)
	defer hh.Close()

	addThree(t, dq)
	hh.Mark("video.example.com")
	dedicated, _, err := dq.GetSessionForTarget("video.example.com:443", hh)
	if err != nil {
		t.Fatalf("reserve: %v", err)
	}

	// Wait for the heavy mark to expire, then trigger cleanup.
	time.Sleep(40 * time.Millisecond)
	dq.ReleaseExpiredReservations(hh)

	if len(dq.reservations) != 0 {
		t.Fatalf("expected reservations cleared, got %v", dq.reservations)
	}

	// Now non-heavy traffic may legitimately land on `dedicated` again.
	hits := 0
	for i := 0; i < 100; i++ {
		s, _ := dq.GetSession()
		if s == dedicated {
			hits++
		}
	}
	if hits == 0 {
		t.Fatal("freed session never reselected by shared pool")
	}
}
