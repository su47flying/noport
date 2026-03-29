package crypto

import (
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"sync"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/hkdf"
)

const (
	maxFrameSize     = 16384 // 16KB max plaintext per frame
	nonceCounterSize = 12    // chacha20poly1305 nonce size
	noncePrefixSize  = 4     // random prefix per connection
	frameLenSize     = 2     // bytes for the ciphertext length header
)

func init() {
	Register("chacha20", NewChaCha20Cipher)
}

type chacha20Cipher struct {
	key [32]byte
}

// NewChaCha20Cipher creates a ChaCha20-Poly1305 AEAD cipher.
// The provided key is run through HKDF-SHA256 to derive a 256-bit key.
func NewChaCha20Cipher(key []byte) (Cipher, error) {
	if len(key) == 0 {
		return nil, fmt.Errorf("chacha20 cipher: key must not be empty")
	}
	c := &chacha20Cipher{}
	hkdfReader := hkdf.New(sha256.New, key, []byte("noport-salt"), []byte("noport-chacha20"))
	if _, err := io.ReadFull(hkdfReader, c.key[:]); err != nil {
		return nil, fmt.Errorf("chacha20 key derivation: %w", err)
	}
	return c, nil
}

func (c *chacha20Cipher) Name() string { return "chacha20" }

func (c *chacha20Cipher) WrapConn(conn net.Conn) net.Conn {
	return &chacha20Conn{
		Conn: conn,
		key:  c.key,
	}
}

// chacha20Conn wraps a net.Conn with ChaCha20-Poly1305 AEAD encryption.
// A random 4-byte nonce prefix is exchanged at connection start (one per direction).
type chacha20Conn struct {
	net.Conn
	key [32]byte

	// writer state
	wMu      sync.Mutex
	wInit    bool
	wCounter uint64
	wAEAD    cipher.AEAD
	wPrefix  [noncePrefixSize]byte

	// reader state
	rMu      sync.Mutex
	rInit    bool
	rCounter uint64
	rAEAD    cipher.AEAD
	rPrefix  [noncePrefixSize]byte
	rBuf     []byte // buffered decrypted plaintext
}

func (c *chacha20Conn) initWriter() error {
	if c.wInit {
		return nil
	}
	if _, err := rand.Read(c.wPrefix[:]); err != nil {
		return fmt.Errorf("chacha20: generate nonce prefix: %w", err)
	}
	aead, err := chacha20poly1305.New(c.key[:])
	if err != nil {
		return fmt.Errorf("chacha20: create AEAD: %w", err)
	}
	// Send the nonce prefix in the clear so the reader can reconstruct nonces.
	if _, err := c.Conn.Write(c.wPrefix[:]); err != nil {
		return fmt.Errorf("chacha20: send nonce prefix: %w", err)
	}
	c.wAEAD = aead
	c.wInit = true
	return nil
}

func (c *chacha20Conn) initReader() error {
	if c.rInit {
		return nil
	}
	if _, err := io.ReadFull(c.Conn, c.rPrefix[:]); err != nil {
		return fmt.Errorf("chacha20: read nonce prefix: %w", err)
	}
	aead, err := chacha20poly1305.New(c.key[:])
	if err != nil {
		return fmt.Errorf("chacha20: create AEAD: %w", err)
	}
	c.rAEAD = aead
	c.rInit = true
	return nil
}

// makeNonce builds a 12-byte nonce from a 4-byte prefix and an 8-byte big-endian counter.
func makeNonce(prefix [noncePrefixSize]byte, counter uint64) [nonceCounterSize]byte {
	var nonce [nonceCounterSize]byte
	copy(nonce[:noncePrefixSize], prefix[:])
	binary.BigEndian.PutUint64(nonce[noncePrefixSize:], counter)
	return nonce
}

func (c *chacha20Conn) Write(p []byte) (int, error) {
	c.wMu.Lock()
	defer c.wMu.Unlock()

	if err := c.initWriter(); err != nil {
		return 0, err
	}

	totalWritten := 0
	for len(p) > 0 {
		chunk := p
		if len(chunk) > maxFrameSize {
			chunk = chunk[:maxFrameSize]
		}
		p = p[len(chunk):]

		nonce := makeNonce(c.wPrefix, c.wCounter)
		c.wCounter++

		ciphertext := c.wAEAD.Seal(nil, nonce[:], chunk, nil)

		// Write frame: [2-byte ciphertext length][ciphertext]
		var header [frameLenSize]byte
		binary.BigEndian.PutUint16(header[:], uint16(len(ciphertext)))
		if _, err := c.Conn.Write(header[:]); err != nil {
			return totalWritten, err
		}
		if _, err := c.Conn.Write(ciphertext); err != nil {
			return totalWritten, err
		}
		totalWritten += len(chunk)
	}
	return totalWritten, nil
}

func (c *chacha20Conn) Read(p []byte) (int, error) {
	c.rMu.Lock()
	defer c.rMu.Unlock()

	// Return buffered data first.
	if len(c.rBuf) > 0 {
		n := copy(p, c.rBuf)
		c.rBuf = c.rBuf[n:]
		return n, nil
	}

	if err := c.initReader(); err != nil {
		return 0, err
	}

	// Read one frame.
	var header [frameLenSize]byte
	if _, err := io.ReadFull(c.Conn, header[:]); err != nil {
		return 0, err
	}
	ctLen := binary.BigEndian.Uint16(header[:])
	ct := make([]byte, ctLen)
	if _, err := io.ReadFull(c.Conn, ct); err != nil {
		return 0, err
	}

	nonce := makeNonce(c.rPrefix, c.rCounter)
	c.rCounter++

	plaintext, err := c.rAEAD.Open(nil, nonce[:], ct, nil)
	if err != nil {
		return 0, fmt.Errorf("chacha20: decrypt frame: %w", err)
	}

	n := copy(p, plaintext)
	if n < len(plaintext) {
		c.rBuf = plaintext[n:]
	}
	return n, nil
}
