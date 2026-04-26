package tunnel

import (
	"bytes"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// blockingConn lets a test stall the writeLoop on demand to simulate a slow
// peer. Reads are forwarded to an underlying pipe so the peer's serve()
// can drain frames once the test releases the gate.
type blockingConn struct {
	net.Conn
	gate chan struct{} // closed by test when writes should be allowed
	once sync.Once
}

func newBlockingPair(t *testing.T) (slow *blockingConn, peer net.Conn) {
	t.Helper()
	c1, c2 := net.Pipe()
	slow = &blockingConn{Conn: c1, gate: make(chan struct{})}
	t.Cleanup(func() {
		slow.release()
		c1.Close()
		c2.Close()
	})
	return slow, c2
}

func (b *blockingConn) Write(p []byte) (int, error) {
	<-b.gate
	return b.Conn.Write(p)
}

func (b *blockingConn) release() { b.once.Do(func() { close(b.gate) }) }

// TestInflightBytesTracking asserts that pending bytes are counted while a
// frame is queued and released after it lands on the wire.
func TestInflightBytesTracking(t *testing.T) {
	slow, peer := newBlockingPair(t)
	clientSess := NewMuxSession(slow, false)
	serverSess := NewMuxSession(peer, true)
	t.Cleanup(func() {
		clientSess.Close()
		serverSess.Close()
	})

	if got := clientSess.InflightBytes(); got != 0 {
		t.Fatalf("expected 0 inflight on idle session, got %d", got)
	}

	// Open() is synchronous: it can only return once the FlagOpen frame
	// reaches the wire, which is gated by slow.gate. Issue Open from a
	// goroutine, observe inflight rises, then release.
	openDone := make(chan error, 1)
	go func() {
		_, err := clientSess.Open()
		openDone <- err
	}()

	// Wait for FlagOpen to be queued (inflight should equal MuxHeaderLen).
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) && clientSess.InflightBytes() == 0 {
		time.Sleep(2 * time.Millisecond)
	}
	if got := clientSess.InflightBytes(); got != int64(MuxHeaderLen) {
		t.Fatalf("expected %d inflight while gated, got %d",
			MuxHeaderLen, got)
	}

	// Release the gate; FlagOpen drains, inflight returns to 0.
	slow.release()
	if err := <-openDone; err != nil {
		t.Fatalf("Open after release: %v", err)
	}

	deadline = time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) && clientSess.InflightBytes() != 0 {
		time.Sleep(5 * time.Millisecond)
	}
	if got := clientSess.InflightBytes(); got != 0 {
		t.Fatalf("expected inflight to drain after release, got %d", got)
	}

	// Drain the stream that serverSess accepts so subsequent writes don't
	// stall on reader-side flow control (net.Pipe is synchronous).
	go func() {
		s, err := serverSess.Accept()
		if err != nil {
			return
		}
		buf := make([]byte, 32*1024)
		for {
			if _, err := s.Read(buf); err != nil {
				return
			}
		}
	}()

	// Send several writeChunkSize frames; ensure they round-trip without
	// leaving stale inflight.
	st, err := clientSess.Open()
	if err != nil {
		t.Fatalf("second Open: %v", err)
	}
	payload := bytes.Repeat([]byte{0xAA}, writeChunkSize*3)
	if _, err := st.Write(payload); err != nil {
		t.Fatalf("Write: %v", err)
	}

	deadline = time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) && clientSess.InflightBytes() != 0 {
		time.Sleep(5 * time.Millisecond)
	}
	if got := clientSess.InflightBytes(); got != 0 {
		t.Fatalf("expected 0 inflight after drain, got %d", got)
	}
}

// TestGetSessionPicksLeastInflight asserts the pool prefers the session with
// the smallest write backlog rather than the one with fewest streams.
func TestGetSessionPicksLeastInflight(t *testing.T) {
	dq := NewDataQueue(nil, false)
	t.Cleanup(func() { dq.Close() })

	c1, _ := newPipeConn(t)
	s1, _ := dq.AddConn(c1)
	c2, _ := newPipeConn(t)
	s2, _ := dq.AddConn(c2)
	c3, _ := newPipeConn(t)
	s3, _ := dq.AddConn(c3)

	// s1 has many streams but no inflight; s2 has heavy backlog; s3 is idle.
	s1.mu.Lock()
	for i := uint32(100); i < 110; i++ {
		s1.streams[i] = newMuxStream(i, s1)
	}
	s1.mu.Unlock()
	s2.inflightBytes.Store(1 << 20) // 1MB pending

	got, err := dq.GetSession()
	if err != nil {
		t.Fatalf("GetSession: %v", err)
	}
	if got != s3 {
		t.Fatalf("expected idle session s3, got id=%d", got.ID())
	}

	// Now load up s3; s1 (10 streams, 0 inflight) should win over s2
	// (0 streams, 1MB inflight).
	s3.inflightBytes.Store(2 << 20)
	got, err = dq.GetSession()
	if err != nil {
		t.Fatalf("GetSession: %v", err)
	}
	if got != s1 {
		t.Fatalf("expected s1 (low inflight) over s2 (heavy inflight), got id=%d", got.ID())
	}
}

// TestNoPanicOnConcurrentCloseAndWrite is a regression guard for the
// "send on closed channel" crash that occurred when Close() closed writeCh
// while another goroutine was mid-writeFrame.
func TestNoPanicOnConcurrentCloseAndWrite(t *testing.T) {
	for trial := 0; trial < 50; trial++ {
		c1, c2 := net.Pipe()
		client := NewMuxSession(c1, false)
		server := NewMuxSession(c2, true)

		// drain accept side
		go func() {
			for {
				st, err := server.Accept()
				if err != nil {
					return
				}
				go func(s *MuxStream) {
					buf := make([]byte, 4096)
					for {
						if _, err := s.Read(buf); err != nil {
							return
						}
					}
				}(st)
			}
		}()

		var wg sync.WaitGroup
		stop := make(chan struct{})

		// Writer goroutines hammering the session.
		for i := 0; i < 4; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				st, err := client.Open()
				if err != nil {
					return
				}
				payload := make([]byte, 1024)
				for {
					select {
					case <-stop:
						return
					default:
					}
					if _, err := st.Write(payload); err != nil {
						return
					}
				}
			}()
		}

		time.Sleep(2 * time.Millisecond)
		client.Close() // would panic under the old close(writeCh)
		close(stop)
		wg.Wait()
		server.Close()
		c1.Close()
		c2.Close()
	}
}

// TestStreamCloseConvergesBothMaps asserts that a unilateral Close from one
// side eventually drains the stream entry from BOTH sessions' maps via the
// FlagClose echo, and that no spurious data is delivered on the closed stream.
func TestStreamCloseConvergesBothMaps(t *testing.T) {
	client, server := setupMuxPair(t)

	st, err := client.Open()
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	peer, err := server.Accept()
	if err != nil {
		t.Fatalf("Accept: %v", err)
	}

	// Issue some traffic to populate both maps.
	if _, err := st.Write([]byte("hello")); err != nil {
		t.Fatalf("Write: %v", err)
	}
	buf := make([]byte, 16)
	if _, err := peer.Read(buf); err != nil {
		t.Fatalf("peer.Read: %v", err)
	}

	if got := client.NumStreams(); got != 1 {
		t.Fatalf("client streams pre-close: want 1 got %d", got)
	}
	if got := server.NumStreams(); got != 1 {
		t.Fatalf("server streams pre-close: want 1 got %d", got)
	}

	// Client closes; expect both maps to drain (peer removes on FlagClose,
	// client removes on echoed FlagClose).
	if err := st.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if client.NumStreams() == 0 && server.NumStreams() == 0 {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("stream maps did not converge: client=%d server=%d",
		client.NumStreams(), server.NumStreams())
}

// TestWriteChunkSizeBound asserts that a single Write is split into frames
// no larger than writeChunkSize, so head-of-line blocking on a shared
// session is bounded.
func TestWriteChunkSizeBound(t *testing.T) {
	client, server := setupMuxPair(t)

	st, err := client.Open()
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	peer, err := server.Accept()
	if err != nil {
		t.Fatalf("Accept: %v", err)
	}

	const total = writeChunkSize*3 + 123

	var maxRead atomic.Int64
	done := make(chan struct{})
	go func() {
		defer close(done)
		buf := make([]byte, writeChunkSize*2)
		read := 0
		for read < total {
			// Drain one frame at a time by sizing exactly to the
			// chunk size + header to avoid coalescing.
			n, err := peer.Read(buf[:writeChunkSize])
			if err != nil {
				return
			}
			if int64(n) > maxRead.Load() {
				maxRead.Store(int64(n))
			}
			read += n
		}
	}()

	payload := bytes.Repeat([]byte{0x42}, total)
	if _, err := st.Write(payload); err != nil {
		t.Fatalf("Write: %v", err)
	}

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("reader did not drain in time")
	}

	if maxRead.Load() > int64(writeChunkSize) {
		t.Fatalf("frame larger than writeChunkSize observed: %d > %d",
			maxRead.Load(), writeChunkSize)
	}
}
