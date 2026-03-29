package crypto

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"io"
	"net"
	"sync"
	"testing"

	"golang.org/x/crypto/hkdf"
)

func TestXORRoundTrip(t *testing.T) {
	key := []byte("secretkey")
	plaintext := []byte("Hello, World! This is a test of the XOR cipher round-trip.")

	// Encrypt via xorWriter
	var encrypted bytes.Buffer
	c, err := NewXORCipher(key)
	if err != nil {
		t.Fatalf("NewXORCipher: %v", err)
	}
	sw := &xorStreamWrapper{key: c.(*xorCipher).key}
	w := sw.WrapWriter(&encrypted)
	n, err := w.Write(plaintext)
	if err != nil {
		t.Fatalf("Write: %v", err)
	}
	if n != len(plaintext) {
		t.Fatalf("Write: wrote %d, want %d", n, len(plaintext))
	}

	// Encrypted data should differ from plaintext
	if bytes.Equal(encrypted.Bytes(), plaintext) {
		t.Fatal("encrypted data should differ from plaintext")
	}

	// Decrypt via xorReader
	r := sw.WrapReader(&encrypted)
	decrypted, err := io.ReadAll(r)
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	if !bytes.Equal(decrypted, plaintext) {
		t.Errorf("round-trip failed: got %q, want %q", decrypted, plaintext)
	}
}

func TestXORKeyLengths(t *testing.T) {
	tests := []struct {
		name string
		key  []byte
	}{
		{"single byte key", []byte{0xAB}},
		{"short key", []byte("hi")},
		{"long key", []byte("this-is-a-much-longer-key-for-testing-purposes")},
	}

	plaintext := []byte("The quick brown fox jumps over the lazy dog")

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sw := &xorStreamWrapper{key: tt.key}

			var encrypted bytes.Buffer
			w := sw.WrapWriter(&encrypted)
			if _, err := w.Write(plaintext); err != nil {
				t.Fatalf("Write: %v", err)
			}

			r := sw.WrapReader(bytes.NewReader(encrypted.Bytes()))
			decrypted, err := io.ReadAll(r)
			if err != nil {
				t.Fatalf("ReadAll: %v", err)
			}
			if !bytes.Equal(decrypted, plaintext) {
				t.Errorf("round-trip failed with key %q", tt.key)
			}
		})
	}
}

func TestXORSymmetry(t *testing.T) {
	key := []byte("symmetry")
	data := []byte("XOR applied twice should return the original data")

	// First XOR pass
	buf1 := make([]byte, len(data))
	for i, b := range data {
		buf1[i] = b ^ key[i%len(key)]
	}

	// Second XOR pass
	buf2 := make([]byte, len(buf1))
	for i, b := range buf1 {
		buf2[i] = b ^ key[i%len(key)]
	}

	if !bytes.Equal(buf2, data) {
		t.Errorf("XOR symmetry broken: got %q, want %q", buf2, data)
	}
}

func TestXOREmptyKeyError(t *testing.T) {
	_, err := NewXORCipher([]byte{})
	if err == nil {
		t.Fatal("expected error for empty key, got nil")
	}

	_, err = NewXORCipher(nil)
	if err == nil {
		t.Fatal("expected error for nil key, got nil")
	}
}

func TestXORWrapConn(t *testing.T) {
	key := []byte("connkey")
	plaintext := []byte("data over the wire")

	c, err := NewXORCipher(key)
	if err != nil {
		t.Fatalf("NewXORCipher: %v", err)
	}

	// net.Pipe gives us two connected in-memory conns
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()

	wrappedClient := c.WrapConn(client)
	wrappedServer := c.WrapConn(server)

	// Write from client, read from server
	done := make(chan error, 1)
	go func() {
		_, err := wrappedClient.Write(plaintext)
		done <- err
	}()

	buf := make([]byte, len(plaintext))
	n, err := io.ReadFull(wrappedServer, buf)
	if err != nil {
		t.Fatalf("ReadFull: %v", err)
	}
	if n != len(plaintext) {
		t.Fatalf("read %d bytes, want %d", n, len(plaintext))
	}
	if !bytes.Equal(buf, plaintext) {
		t.Errorf("WrapConn round-trip failed: got %q, want %q", buf, plaintext)
	}

	if err := <-done; err != nil {
		t.Fatalf("Write goroutine error: %v", err)
	}
}

func TestXORRegistry(t *testing.T) {
	key := []byte("registrykey")

	c, err := NewCipher("xor", key)
	if err != nil {
		t.Fatalf("NewCipher(xor): %v", err)
	}
	if c.Name() != "xor" {
		t.Errorf("Name() = %q, want %q", c.Name(), "xor")
	}
}

func TestXORName(t *testing.T) {
	c, err := NewXORCipher([]byte("k"))
	if err != nil {
		t.Fatalf("NewXORCipher: %v", err)
	}
	if c.Name() != "xor" {
		t.Errorf("Name() = %q, want %q", c.Name(), "xor")
	}
}

// ---------- ChaCha20-Poly1305 cipher tests ----------

func TestChaCha20RoundTrip(t *testing.T) {
	key := []byte("my-secret-password")
	c, err := NewCipher("chacha20", key)
	if err != nil {
		t.Fatal(err)
	}
	if c.Name() != "chacha20" {
		t.Fatalf("expected name chacha20, got %s", c.Name())
	}

	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()

	wConn := c.WrapConn(client)
	rConn := c.WrapConn(server)

	msg := []byte("hello chacha20-poly1305!")
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		if _, err := wConn.Write(msg); err != nil {
			t.Errorf("write error: %v", err)
		}
	}()

	buf := make([]byte, 128)
	n, err := rConn.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(buf[:n], msg) {
		t.Fatalf("round trip: got %q, want %q", buf[:n], msg)
	}
	wg.Wait()
}

func TestChaCha20MultipleWrites(t *testing.T) {
	key := []byte("multi-write-key")
	c, err := NewCipher("chacha20", key)
	if err != nil {
		t.Fatal(err)
	}

	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()

	wConn := c.WrapConn(client)
	rConn := c.WrapConn(server)

	messages := []string{"first", "second", "third message here"}
	go func() {
		for _, m := range messages {
			if _, err := wConn.Write([]byte(m)); err != nil {
				t.Errorf("write %q: %v", m, err)
				return
			}
		}
	}()

	for _, want := range messages {
		buf := make([]byte, 256)
		n, err := rConn.Read(buf)
		if err != nil {
			t.Fatal(err)
		}
		if string(buf[:n]) != want {
			t.Fatalf("got %q, want %q", buf[:n], want)
		}
	}
}

func TestChaCha20LargeData(t *testing.T) {
	key := []byte("large-data-key")
	c, err := NewCipher("chacha20", key)
	if err != nil {
		t.Fatal(err)
	}

	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()

	wConn := c.WrapConn(client)
	rConn := c.WrapConn(server)

	// 50KB — exceeds maxFrameSize (16KB), forces multiple frames
	dataSize := 50 * 1024
	original := make([]byte, dataSize)
	if _, err := rand.Read(original); err != nil {
		t.Fatal(err)
	}

	var writeErr error
	go func() {
		_, writeErr = wConn.Write(original)
	}()

	var received []byte
	buf := make([]byte, 4096)
	for len(received) < dataSize {
		n, err := rConn.Read(buf)
		if err != nil {
			t.Fatalf("read error after %d bytes: %v", len(received), err)
		}
		received = append(received, buf[:n]...)
	}

	if writeErr != nil {
		t.Fatalf("write error: %v", writeErr)
	}
	if !bytes.Equal(received, original) {
		t.Fatal("large data mismatch")
	}
}

func TestChaCha20SmallReadBuffer(t *testing.T) {
	key := []byte("small-buf-key")
	c, err := NewCipher("chacha20", key)
	if err != nil {
		t.Fatal(err)
	}

	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()

	wConn := c.WrapConn(client)
	rConn := c.WrapConn(server)

	msg := []byte("this is a longer message that will be read in tiny chunks")
	go func() { wConn.Write(msg) }()

	// Read in very small chunks to exercise buffering.
	var received []byte
	buf := make([]byte, 3)
	for len(received) < len(msg) {
		n, err := rConn.Read(buf)
		if err != nil {
			t.Fatal(err)
		}
		received = append(received, buf[:n]...)
	}
	if !bytes.Equal(received, msg) {
		t.Fatalf("got %q, want %q", received, msg)
	}
}

func TestChaCha20KeyDerivationConsistent(t *testing.T) {
	key := []byte("deterministic-key")

	derive := func() [32]byte {
		var out [32]byte
		r := hkdf.New(sha256.New, key, []byte("noport-salt"), []byte("noport-chacha20"))
		if _, err := io.ReadFull(r, out[:]); err != nil {
			t.Fatal(err)
		}
		return out
	}

	a := derive()
	b := derive()
	if a != b {
		t.Fatal("HKDF derivation is not deterministic")
	}

	// Also verify through the factory.
	c1, err := NewChaCha20Cipher(key)
	if err != nil {
		t.Fatal(err)
	}
	c2, err := NewChaCha20Cipher(key)
	if err != nil {
		t.Fatal(err)
	}
	k1 := c1.(*chacha20Cipher).key
	k2 := c2.(*chacha20Cipher).key
	if k1 != k2 {
		t.Fatal("NewChaCha20Cipher key derivation not deterministic")
	}
}

func TestChaCha20EmptyKey(t *testing.T) {
	_, err := NewCipher("chacha20", []byte{})
	if err == nil {
		t.Fatal("expected error for empty key")
	}

	_, err = NewCipher("chacha20", nil)
	if err == nil {
		t.Fatal("expected error for nil key")
	}
}

func TestChaCha20Registry(t *testing.T) {
	key := []byte("registry-test")
	c, err := NewCipher("chacha20", key)
	if err != nil {
		t.Fatalf("NewCipher(chacha20) failed: %v", err)
	}
	if c.Name() != "chacha20" {
		t.Fatalf("expected name chacha20, got %s", c.Name())
	}
}

func TestChaCha20BidirectionalPipe(t *testing.T) {
	key := []byte("bidir-key")
	c, err := NewCipher("chacha20", key)
	if err != nil {
		t.Fatal(err)
	}

	s, cl := net.Pipe()
	defer s.Close()
	defer cl.Close()

	sConn := c.WrapConn(s)
	cConn := c.WrapConn(cl)

	// Client writes, server reads, then server writes back.
	go func() {
		buf := make([]byte, 256)
		n, err := sConn.Read(buf)
		if err != nil {
			t.Errorf("server read: %v", err)
			return
		}
		reply := append([]byte("echo:"), buf[:n]...)
		if _, err := sConn.Write(reply); err != nil {
			t.Errorf("server write: %v", err)
		}
	}()

	msg := []byte("ping")
	if _, err := cConn.Write(msg); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 256)
	n, err := cConn.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	want := "echo:ping"
	if string(buf[:n]) != want {
		t.Fatalf("got %q, want %q", buf[:n], want)
	}
}
