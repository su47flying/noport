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

func setupMuxPair(t *testing.T) (clientSess *MuxSession, serverSess *MuxSession) {
t.Helper()
c1, c2 := net.Pipe()
var err error
// c1 = dialer side (smux client), c2 = listener side (smux server)
clientSess, err = NewMuxSession(c1, false)
if err != nil {
t.Fatalf("NewMuxSession client: %v", err)
}
serverSess, err = NewMuxSession(c2, true)
if err != nil {
t.Fatalf("NewMuxSession server: %v", err)
}
t.Cleanup(func() {
clientSess.Close()
serverSess.Close()
})
return clientSess, serverSess
}

func TestOpenAccept(t *testing.T) {
clientSess, serverSess := setupMuxPair(t)

// Server (TCP listener) opens stream, client (TCP dialer) accepts
st, err := serverSess.Open()
if err != nil {
t.Fatalf("Open failed: %v", err)
}
defer st.Close()

remote, err := clientSess.Accept()
if err != nil {
t.Fatalf("Accept failed: %v", err)
}
defer remote.Close()
}

func TestBidirectionalData(t *testing.T) {
clientSess, serverSess := setupMuxPair(t)

st, err := serverSess.Open()
if err != nil {
t.Fatalf("Open failed: %v", err)
}
remote, err := clientSess.Accept()
if err != nil {
t.Fatalf("Accept failed: %v", err)
}

// Server -> Client
msg1 := []byte("hello from server")
go func() {
st.Write(msg1)
}()

buf := make([]byte, 256)
n, err := remote.Read(buf)
if err != nil {
t.Fatalf("client Read failed: %v", err)
}
if !bytes.Equal(buf[:n], msg1) {
t.Fatalf("expected %q, got %q", msg1, buf[:n])
}

// Client -> Server
msg2 := []byte("hello from client")
go func() {
remote.Write(msg2)
}()

n, err = st.Read(buf)
if err != nil {
t.Fatalf("server Read failed: %v", err)
}
if !bytes.Equal(buf[:n], msg2) {
t.Fatalf("expected %q, got %q", msg2, buf[:n])
}
}

func TestMultipleConcurrentStreams(t *testing.T) {
clientSess, serverSess := setupMuxPair(t)

const numStreams = 20
var wg sync.WaitGroup

// Client side: accept streams and echo data back
wg.Add(1)
go func() {
defer wg.Done()
for i := 0; i < numStreams; i++ {
remote, err := clientSess.Accept()
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

// Server side: open streams and send/receive data
var serverWg sync.WaitGroup
for i := 0; i < numStreams; i++ {
serverWg.Add(1)
go func(idx int) {
defer serverWg.Done()
st, err := serverSess.Open()
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

st.Close()
buf := make([]byte, 256)
n, _ := st.Read(buf)
_ = n
}(i)
}
serverWg.Wait()
wg.Wait()
}

func TestStreamClose(t *testing.T) {
clientSess, serverSess := setupMuxPair(t)

st, err := serverSess.Open()
if err != nil {
t.Fatalf("Open failed: %v", err)
}
remote, err := clientSess.Accept()
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
clientSess, serverSess := setupMuxPair(t)

st, err := serverSess.Open()
if err != nil {
t.Fatalf("Open failed: %v", err)
}
remote, err := clientSess.Accept()
if err != nil {
t.Fatalf("Accept failed: %v", err)
}

// Send 256KB of random data
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
clientSess, serverSess := setupMuxPair(t)

const numStreams = 5
for i := 0; i < numStreams; i++ {
_, err := serverSess.Open()
if err != nil {
t.Fatalf("Open #%d failed: %v", i, err)
}
if _, err := clientSess.Accept(); err != nil {
t.Fatalf("Accept #%d failed: %v", i, err)
}
}

if serverSess.NumStreams() != numStreams {
t.Fatalf("expected %d streams, got %d", numStreams, serverSess.NumStreams())
}

serverSess.Close()

time.Sleep(50 * time.Millisecond)
if !serverSess.IsClosed() {
t.Error("session should be closed")
}
if serverSess.NumStreams() != 0 {
t.Errorf("expected 0 streams after close, got %d", serverSess.NumStreams())
}
}

func TestMuxStreamSetReadDeadline(t *testing.T) {
c1, c2 := net.Pipe()
defer c1.Close()
defer c2.Close()

serverSess, err := NewMuxSession(c2, true)
if err != nil {
t.Fatal(err)
}
defer serverSess.Close()
clientSess, err := NewMuxSession(c1, false)
if err != nil {
t.Fatal(err)
}
defer clientSess.Close()

stream, err := serverSess.Open()
if err != nil {
t.Fatal(err)
}
cStream, err := clientSess.Accept()
if err != nil {
t.Fatal(err)
}

// Test 1: SetReadDeadline in the past should cause Read to return with timeout
cStream.SetReadDeadline(time.Now().Add(-1 * time.Second))
buf := make([]byte, 10)
_, err = cStream.Read(buf)
if err == nil {
t.Fatal("expected error from Read after deadline expired")
}

// Test 2: Future deadline with data arriving before it
stream2, err := serverSess.Open()
if err != nil {
t.Fatal(err)
}
cStream2, err := clientSess.Accept()
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

_ = stream // keep reference alive
}
