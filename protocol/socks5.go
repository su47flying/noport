package protocol

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strconv"
)

const (
	Socks5Version = 0x05

	AuthNone   = 0x00
	AuthReject = 0xFF

	CmdConnect = 0x01

	AddrIPv4   = 0x01
	AddrDomain = 0x03
	AddrIPv6   = 0x04

	RepSuccess          = 0x00
	RepGeneralFailure   = 0x01
	RepConnNotAllowed   = 0x02
	RepNetworkUnreach   = 0x03
	RepHostUnreach      = 0x04
	RepConnRefused      = 0x05
	RepTTLExpired       = 0x06
	RepCmdNotSupported  = 0x07
	RepAddrNotSupported = 0x08
)

// Socks5Request represents a parsed SOCKS5 CONNECT request.
type Socks5Request struct {
	AddrType byte
	Addr     string
	Port     uint16
}

// Target returns "host:port" string.
func (r *Socks5Request) Target() string {
	return net.JoinHostPort(r.Addr, strconv.Itoa(int(r.Port)))
}

// HandleSocks5Handshake performs the SOCKS5 authentication handshake.
// Reads client greeting, selects "no auth", returns nil on success.
func HandleSocks5Handshake(rw io.ReadWriter) error {
	// Read version and number of methods.
	header := make([]byte, 2)
	if _, err := io.ReadFull(rw, header); err != nil {
		return fmt.Errorf("socks5 handshake: read header: %w", err)
	}
	if header[0] != Socks5Version {
		return fmt.Errorf("socks5 handshake: unsupported version %d", header[0])
	}

	nMethods := int(header[1])
	methods := make([]byte, nMethods)
	if _, err := io.ReadFull(rw, methods); err != nil {
		return fmt.Errorf("socks5 handshake: read methods: %w", err)
	}

	for _, m := range methods {
		if m == AuthNone {
			_, err := rw.Write([]byte{Socks5Version, AuthNone})
			return err
		}
	}

	// No acceptable method found.
	rw.Write([]byte{Socks5Version, AuthReject})
	return fmt.Errorf("socks5 handshake: no acceptable auth method")
}

// ReadSocks5Request reads a SOCKS5 request after handshake.
// Only supports CONNECT command. Returns parsed request.
func ReadSocks5Request(r io.Reader) (*Socks5Request, error) {
	// Read [version, cmd, rsv, atyp].
	header := make([]byte, 4)
	if _, err := io.ReadFull(r, header); err != nil {
		return nil, fmt.Errorf("socks5 request: read header: %w", err)
	}
	if header[0] != Socks5Version {
		return nil, fmt.Errorf("socks5 request: unsupported version %d", header[0])
	}
	if header[1] != CmdConnect {
		return nil, fmt.Errorf("socks5 request: unsupported command 0x%02x", header[1])
	}

	req := &Socks5Request{AddrType: header[3]}

	switch req.AddrType {
	case AddrIPv4:
		buf := make([]byte, 4)
		if _, err := io.ReadFull(r, buf); err != nil {
			return nil, fmt.Errorf("socks5 request: read ipv4: %w", err)
		}
		req.Addr = net.IP(buf).String()

	case AddrDomain:
		lenBuf := make([]byte, 1)
		if _, err := io.ReadFull(r, lenBuf); err != nil {
			return nil, fmt.Errorf("socks5 request: read domain length: %w", err)
		}
		domain := make([]byte, lenBuf[0])
		if _, err := io.ReadFull(r, domain); err != nil {
			return nil, fmt.Errorf("socks5 request: read domain: %w", err)
		}
		req.Addr = string(domain)

	case AddrIPv6:
		buf := make([]byte, 16)
		if _, err := io.ReadFull(r, buf); err != nil {
			return nil, fmt.Errorf("socks5 request: read ipv6: %w", err)
		}
		req.Addr = net.IP(buf).String()

	default:
		return nil, fmt.Errorf("socks5 request: unsupported address type 0x%02x", req.AddrType)
	}

	// Read 2-byte port (big endian).
	portBuf := make([]byte, 2)
	if _, err := io.ReadFull(r, portBuf); err != nil {
		return nil, fmt.Errorf("socks5 request: read port: %w", err)
	}
	req.Port = binary.BigEndian.Uint16(portBuf)

	return req, nil
}

// WriteSocks5Reply writes a SOCKS5 reply to the client.
// bindAddr and bindPort are typically zero for CONNECT responses.
func WriteSocks5Reply(w io.Writer, rep byte, bindAddr net.IP, bindPort uint16) error {
	ip4 := bindAddr.To4()
	if ip4 == nil {
		ip4 = net.IPv4zero.To4()
	}

	buf := make([]byte, 10)
	buf[0] = Socks5Version
	buf[1] = rep
	buf[2] = 0x00
	buf[3] = AddrIPv4
	copy(buf[4:8], ip4)
	binary.BigEndian.PutUint16(buf[8:10], bindPort)

	_, err := w.Write(buf)
	return err
}
