package crypto

import (
	"fmt"
	"io"
	"net"
	"sync"
)

// Cipher wraps a net.Conn with encryption/decryption
type Cipher interface {
	// WrapConn wraps a plain net.Conn, returning an encrypted conn.
	// Both reads and writes on the returned conn are encrypted/decrypted.
	WrapConn(conn net.Conn) net.Conn

	// Name returns the cipher scheme name (e.g., "xor", "chacha20")
	Name() string
}

// StreamWrapper wraps an io.Reader and io.Writer with encryption
type StreamWrapper interface {
	WrapReader(r io.Reader) io.Reader
	WrapWriter(w io.Writer) io.Writer
}

// registry stores available ciphers
var (
	mu      sync.RWMutex
	ciphers = make(map[string]CipherFactory)
)

// CipherFactory creates a Cipher from a key
type CipherFactory func(key []byte) (Cipher, error)

// Register registers a cipher factory by scheme name
func Register(name string, factory CipherFactory) {
	mu.Lock()
	defer mu.Unlock()
	ciphers[name] = factory
}

// NewCipher creates a cipher by scheme name and key
func NewCipher(scheme string, key []byte) (Cipher, error) {
	mu.RLock()
	factory, ok := ciphers[scheme]
	mu.RUnlock()
	if !ok {
		return nil, fmt.Errorf("unknown cipher scheme: %s", scheme)
	}
	return factory(key)
}

// encryptedConn wraps a net.Conn with a StreamWrapper
type encryptedConn struct {
	net.Conn
	reader io.Reader
	writer io.Writer
}

func (c *encryptedConn) Read(p []byte) (int, error) {
	return c.reader.Read(p)
}

func (c *encryptedConn) Write(p []byte) (int, error) {
	return c.writer.Write(p)
}

// WrapConnWith wraps a net.Conn using a StreamWrapper
func WrapConnWith(conn net.Conn, sw StreamWrapper) net.Conn {
	return &encryptedConn{
		Conn:   conn,
		reader: sw.WrapReader(conn),
		writer: sw.WrapWriter(conn),
	}
}
