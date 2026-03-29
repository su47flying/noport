package crypto

import (
	"fmt"
	"io"
	"net"
)

// xorCipher implements Cipher using XOR encryption.
type xorCipher struct {
	key []byte
}

func init() {
	Register("xor", NewXORCipher)
}

// NewXORCipher creates an XOR cipher with the given key.
func NewXORCipher(key []byte) (Cipher, error) {
	if len(key) == 0 {
		return nil, fmt.Errorf("xor cipher: key must not be empty")
	}
	keyCopy := make([]byte, len(key))
	copy(keyCopy, key)
	return &xorCipher{key: keyCopy}, nil
}

func (c *xorCipher) Name() string { return "xor" }

func (c *xorCipher) WrapConn(conn net.Conn) net.Conn {
	sw := &xorStreamWrapper{key: c.key}
	return WrapConnWith(conn, sw)
}

// xorStreamWrapper implements StreamWrapper for XOR.
type xorStreamWrapper struct {
	key []byte
}

func (sw *xorStreamWrapper) WrapReader(r io.Reader) io.Reader {
	return &xorReader{reader: r, key: sw.key}
}

func (sw *xorStreamWrapper) WrapWriter(w io.Writer) io.Writer {
	return &xorWriter{writer: w, key: sw.key}
}

// xorReader XORs data on read.
type xorReader struct {
	reader io.Reader
	key    []byte
	pos    int
}

func (r *xorReader) Read(p []byte) (int, error) {
	n, err := r.reader.Read(p)
	for i := 0; i < n; i++ {
		p[i] ^= r.key[r.pos%len(r.key)]
		r.pos++
	}
	return n, err
}

// xorWriter XORs data on write.
type xorWriter struct {
	writer io.Writer
	key    []byte
	pos    int
}

func (w *xorWriter) Write(p []byte) (int, error) {
	buf := make([]byte, len(p))
	for i := 0; i < len(p); i++ {
		buf[i] = p[i] ^ w.key[w.pos%len(w.key)]
		w.pos++
	}
	return w.writer.Write(buf)
}
