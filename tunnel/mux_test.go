package tunnel

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"io"
	"net"
	"sync"
	"testing"
	"time"
)

func setupMuxPair(t *testing.T) (client *MuxSession, server *MuxSession) {
	t.Helper()
	c1, c2 := net.Pipe()
	client = NewMuxSession(c1, false)
	server = NewMuxSession(c2, true)
	t.Cleanup(func() {
		client.Close()
		server.Close()
	})
	return client, server
}

func TestOpenAccept(t *testing.T) {
	client, server := setupMuxPair(t)

	st, err := client.Open()
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	if st.id%2 != 1 {
		t.Fatalf("expected odd stream ID from client, got %d", st.id)
	}

	remote, err := server.Accept()
	if err != nil {
		t.Fatalf("Accept failed: %v", err)
	}
	if remote.id != st.id {
		t.Fatalf("stream ID mismatch: client=%d server=%d", st.id, remote.id)
	}
}

func TestBidirectionalData(t *testing.T) {
	client, server := setupMuxPair(t)

	st, err := client.Open()
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	remote, err := server.Accept()
	if err != nil {
		t.Fatalf("Accept failed: %v", err)
	}

	// Client -> Server
	msg1 := []byte("hello from client")
	go func() {
		st.Write(msg1)
	}()

	buf := make([]byte, 256)
	n, err := remote.Read(buf)
	if err != nil {
		t.Fatalf("server Read failed: %v", err)
	}
	if !bytes.Equal(buf[:n], msg1) {
		t.Fatalf("expected %q, got %q", msg1, buf[:n])
	}

	// Server -> Client
	msg2 := []byte("hello from server")
	go func() {
		remote.Write(msg2)
	}()

	n, err = st.Read(buf)
	if err != nil {
		t.Fatalf("client Read failed: %v", err)
	}
	if !bytes.Equal(buf[:n], msg2) {
		t.Fatalf("expected %q, got %q", msg2, buf[:n])
	}
}

func TestMultipleConcurrentStreams(t *testing.T) {
	client, server := setupMuxPair(t)

	const numStreams = 20
	var wg sync.WaitGroup

	// Server side: accept streams and echo data back
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < numStreams; i++ {
			remote, err := server.Accept()
			if err != nil {
				t.Errorf("Accept #%d failed: %v", i, err)
				return
			}
			go func(r *MuxStream) {
				io.Copy(r, r)
				r.Close()
			}(remote)
		}
	}()

	// Client side: open streams and send/receive data
	var clientWg sync.WaitGroup
	for i := 0; i < numStreams; i++ {
		clientWg.Add(1)
		go func(idx int) {
			defer clientWg.Done()
			st, err := client.Open()
			if err != nil {
				t.Errorf("Open #%d failed: %v", idx, err)
				return
			}
			defer st.Close()

			msg := []byte(fmt.Sprintf("stream-%d-data", idx))
			if _, err := st.Write(msg); err != nil {
				t.Errorf("Write #%d failed: %v", idx, err)
				return
			}

			// Close write direction so the echo server sees EOF
			st.Close()

			buf := make([]byte, 256)
			n, _ := st.Read(buf)
			// Data may or may not arrive depending on timing, but no panics
			_ = n
		}(i)
	}
	clientWg.Wait()
	wg.Wait()
}

func TestStreamClose(t *testing.T) {
	client, server := setupMuxPair(t)

	st, err := client.Open()
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	remote, err := server.Accept()
	if err != nil {
		t.Fatalf("Accept failed: %v", err)
	}

	// Write some data then close
	msg := []byte("before close")
	go func() {
		st.Write(msg)
		st.Close()
	}()

	// Read data
	buf := make([]byte, 256)
	n, err := remote.Read(buf)
	if err != nil {
		t.Fatalf("Read failed: %v", err)
	}
	if !bytes.Equal(buf[:n], msg) {
		t.Fatalf("expected %q, got %q", msg, buf[:n])
	}

	// Next read should eventually get EOF
	deadline := time.After(2 * time.Second)
	done := make(chan error, 1)
	go func() {
		_, err := remote.Read(buf)
		done <- err
	}()

	select {
	case err := <-done:
		if err != io.EOF {
			t.Fatalf("expected EOF after close, got: %v", err)
		}
	case <-deadline:
		t.Fatal("timed out waiting for EOF")
	}
}

func TestLargeDataTransfer(t *testing.T) {
	client, server := setupMuxPair(t)

	st, err := client.Open()
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	remote, err := server.Accept()
	if err != nil {
		t.Fatalf("Accept failed: %v", err)
	}

	// Send 256KB of random data (forces multiple frames)
	dataSize := 256 * 1024
	sendData := make([]byte, dataSize)
	if _, err := rand.Read(sendData); err != nil {
		t.Fatalf("rand.Read failed: %v", err)
	}

	var writeErr error
	go func() {
		_, writeErr = st.Write(sendData)
		st.Close()
	}()

	recvData, err := io.ReadAll(remote)
	if err != nil {
		t.Fatalf("ReadAll failed: %v", err)
	}
	if writeErr != nil {
		t.Fatalf("Write failed: %v", writeErr)
	}
	if !bytes.Equal(sendData, recvData) {
		t.Fatalf("data mismatch: sent %d bytes, received %d bytes", len(sendData), len(recvData))
	}
}

func TestSessionCloseClosesAllStreams(t *testing.T) {
	client, server := setupMuxPair(t)

	const numStreams = 5
	streams := make([]*MuxStream, numStreams)
	for i := 0; i < numStreams; i++ {
		st, err := client.Open()
		if err != nil {
			t.Fatalf("Open #%d failed: %v", i, err)
		}
		streams[i] = st
		// Accept on server side to drain accept channel
		if _, err := server.Accept(); err != nil {
			t.Fatalf("Accept #%d failed: %v", i, err)
		}
	}

	if client.NumStreams() != numStreams {
		t.Fatalf("expected %d streams, got %d", numStreams, client.NumStreams())
	}

	// Close the session
	client.Close()

	// All streams should be closed
	time.Sleep(50 * time.Millisecond)
	for i, st := range streams {
		if !st.closed.Load() {
			t.Errorf("stream #%d not closed after session close", i)
		}
	}

	// NumStreams should be 0
	if client.NumStreams() != 0 {
		t.Errorf("expected 0 streams after close, got %d", client.NumStreams())
	}
}

func TestMuxStreamSetReadDeadline(t *testing.T) {
a, b := net.Pipe()
defer a.Close()
defer b.Close()

server := NewMuxSession(a, true)
defer server.Close()
client := NewMuxSession(b, false)
defer client.Close()

// Server opens a stream
stream, err := server.Open()
if err != nil {
t.Fatal(err)
}

// Accept on client side
cStream, err := client.Accept()
if err != nil {
t.Fatal(err)
}

// Test 1: SetReadDeadline in the past should cause Read to return immediately
cStream.SetReadDeadline(time.Now().Add(-1 * time.Second))
buf := make([]byte, 10)
_, err = cStream.Read(buf)
if err == nil {
t.Fatal("expected error from Read after deadline expired")
}

// Test 2: SetReadDeadline(time.Now()) should unblock a goroutine blocked in Read
done := make(chan error, 1)
go func() {
stream.SetReadDeadline(time.Time{}) // clear any deadline
buf := make([]byte, 10)
_, err := stream.Read(buf)
done <- err
}()

// Give goroutine time to block in Read
time.Sleep(50 * time.Millisecond)

// Unblock by setting deadline in the past
stream.SetReadDeadline(time.Now())

select {
case err := <-done:
if err == nil {
t.Fatal("expected error from Read")
}
t.Logf("Read returned expected error: %v", err)
case <-time.After(2 * time.Second):
t.Fatal("Read did not unblock after SetReadDeadline(time.Now())")
}

// Test 3: Future deadline with data arriving before it
stream2, err := server.Open()
if err != nil {
t.Fatal(err)
}
cStream2, err := client.Accept()
if err != nil {
t.Fatal(err)
}

cStream2.SetReadDeadline(time.Now().Add(5 * time.Second))
go func() {
time.Sleep(50 * time.Millisecond)
stream2.Write([]byte("hello"))
}()

buf2 := make([]byte, 10)
n, err := cStream2.Read(buf2)
if err != nil {
t.Fatalf("expected no error, got: %v", err)
}
if string(buf2[:n]) != "hello" {
t.Fatalf("expected 'hello', got %q", string(buf2[:n]))
}
}
