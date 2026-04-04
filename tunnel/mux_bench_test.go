package tunnel

import (
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// newMuxPair creates a connected client/server MuxSession pair over net.Pipe.
func newMuxPair(b *testing.B) (client *MuxSession, server *MuxSession) {
	c1, c2 := net.Pipe()
	b.Cleanup(func() { c1.Close(); c2.Close() })
	client = NewMuxSession(c1, false)
	server = NewMuxSession(c2, true)
	b.Cleanup(func() { client.Close(); server.Close() })
	return
}

// echoServer accepts streams from sess and echoes all data back.
func echoServer(sess *MuxSession, done <-chan struct{}) {
	for {
		stream, err := sess.Accept()
		if err != nil {
			return
		}
		go func(s *MuxStream) {
			defer s.Close()
			buf := make([]byte, 64*1024)
			for {
				select {
				case <-done:
					return
				default:
				}
				n, err := s.Read(buf)
				if n > 0 {
					if _, werr := s.Write(buf[:n]); werr != nil {
						return
					}
				}
				if err != nil {
					return
				}
			}
		}(stream)
	}
}

// sinkServer accepts streams and discards all incoming data.
func sinkServer(sess *MuxSession) {
	for {
		stream, err := sess.Accept()
		if err != nil {
			return
		}
		go func(s *MuxStream) {
			defer s.Close()
			io.Copy(io.Discard, s)
		}(stream)
	}
}

// BenchmarkMuxStreamThroughput measures single large-stream throughput
// over a MuxSession, reporting bytes/sec.
func BenchmarkMuxStreamThroughput(b *testing.B) {
	client, server := newMuxPair(b)

	// Server: accept one stream, read everything, discard.
	go sinkServer(server)

	stream, err := client.Open()
	if err != nil {
		b.Fatalf("Open: %v", err)
	}
	defer stream.Close()

	chunk := make([]byte, 64*1024)
	for i := range chunk {
		chunk[i] = byte(i)
	}

	b.SetBytes(int64(len(chunk)))
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		if _, err := stream.Write(chunk); err != nil {
			b.Fatalf("Write: %v", err)
		}
	}

	b.StopTimer()
}

// BenchmarkMuxConcurrentStreams measures head-of-line blocking: 1 large
// video-like stream + 20 concurrent small request/response streams.
func BenchmarkMuxConcurrentStreams(b *testing.B) {
	client, server := newMuxPair(b)
	done := make(chan struct{})
	b.Cleanup(func() { close(done) })

	// Server: echo all data back on every accepted stream.
	go echoServer(server, done)

	const (
		bigChunk      = 64 * 1024
		smallPayload  = 1024
		numSmall      = 20
	)

	bigData := make([]byte, bigChunk)
	for i := range bigData {
		bigData[i] = 0xAB
	}
	smallData := make([]byte, smallPayload)
	for i := range smallData {
		smallData[i] = 0xCD
	}

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		// Open large stream and start writing continuously.
		bigStream, err := client.Open()
		if err != nil {
			b.Fatalf("Open big: %v", err)
		}

		var stopBig atomic.Bool
		bigDone := make(chan struct{})
		go func() {
			defer close(bigDone)
			readBuf := make([]byte, bigChunk)
			for !stopBig.Load() {
				io.ReadFull(bigStream, readBuf)
			}
		}()
		go func() {
			for !stopBig.Load() {
				if _, err := bigStream.Write(bigData); err != nil {
					return
				}
			}
		}()

		// Give the large stream a moment to saturate the pipe.
		time.Sleep(time.Millisecond)

		// Launch N small request/response round-trips concurrently.
		var wg sync.WaitGroup
		wg.Add(numSmall)
		for j := 0; j < numSmall; j++ {
			go func() {
				defer wg.Done()
				s, err := client.Open()
				if err != nil {
					b.Errorf("Open small: %v", err)
					return
				}
				defer s.Close()

				if _, err := s.Write(smallData); err != nil {
					b.Errorf("Write small: %v", err)
					return
				}
				resp := make([]byte, smallPayload)
				if _, err := io.ReadFull(s, resp); err != nil {
					b.Errorf("Read small: %v", err)
					return
				}
			}()
		}
		wg.Wait()

		// Tear down the large stream for this iteration.
		stopBig.Store(true)
		bigStream.Close()
		<-bigDone
	}

	b.StopTimer()
}

// BenchmarkMuxWriteFrameLatency measures writeFrame latency under
// contention from 10 concurrent goroutines sending 4KB payloads.
func BenchmarkMuxWriteFrameLatency(b *testing.B) {
	client, server := newMuxPair(b)

	// Drain the server side so writes don't block.
	go sinkServer(server)

	stream, err := client.Open()
	if err != nil {
		b.Fatalf("Open: %v", err)
	}
	defer stream.Close()

	// Wait briefly for the server to accept the stream.
	time.Sleep(time.Millisecond)

	const (
		payloadSize  = 4 * 1024
		numWriters   = 10
	)

	payload := make([]byte, payloadSize)
	for i := range payload {
		payload[i] = byte(i)
	}

	b.SetBytes(int64(payloadSize))
	b.ResetTimer()

	// Spread b.N writes across numWriters goroutines.
	var wg sync.WaitGroup
	wg.Add(numWriters)
	perWriter := b.N / numWriters
	remainder := b.N % numWriters

	for w := 0; w < numWriters; w++ {
		count := perWriter
		if w < remainder {
			count++
		}
		go func(n int) {
			defer wg.Done()
			for i := 0; i < n; i++ {
				if _, err := stream.Write(payload); err != nil {
					b.Errorf("Write: %v", err)
					return
				}
			}
		}(count)
	}
	wg.Wait()

	b.StopTimer()
}
