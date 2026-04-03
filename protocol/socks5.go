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

	AuthNone     = 0x00
	AuthUserPass = 0x02
	AuthReject   = 0xFF

	AuthUserPassVersion = 0x01
	AuthSuccess         = 0x00
	AuthFailure         = 0x01

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
// If user is non-empty, requires username/password auth (0x02).
// Otherwise accepts no-auth (0x00).
func HandleSocks5Handshake(rw io.ReadWriter, user, pass string) error {
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

	if user != "" {
		// Require username/password auth
		found := false
		for _, m := range methods {
			if m == AuthUserPass {
				found = true
				break
			}
		}
		if !found {
			rw.Write([]byte{Socks5Version, AuthReject})
			return fmt.Errorf("socks5 handshake: client does not support user/pass auth")
		}

		// Select user/pass method
		if _, err := rw.Write([]byte{Socks5Version, AuthUserPass}); err != nil {
			return err
		}

		// RFC 1929: read sub-negotiation [ver, ulen, user, plen, pass]
		verBuf := make([]byte, 2)
		if _, err := io.ReadFull(rw, verBuf); err != nil {
			return fmt.Errorf("socks5 auth: read version: %w", err)
		}
		if verBuf[0] != AuthUserPassVersion {
			rw.Write([]byte{AuthUserPassVersion, AuthFailure})
			return fmt.Errorf("socks5 auth: unsupported auth version %d", verBuf[0])
		}

		uLen := int(verBuf[1])
		uBuf := make([]byte, uLen)
		if _, err := io.ReadFull(rw, uBuf); err != nil {
			return fmt.Errorf("socks5 auth: read username: %w", err)
		}

		pLenBuf := make([]byte, 1)
		if _, err := io.ReadFull(rw, pLenBuf); err != nil {
			return fmt.Errorf("socks5 auth: read pass length: %w", err)
		}
		pBuf := make([]byte, int(pLenBuf[0]))
		if _, err := io.ReadFull(rw, pBuf); err != nil {
			return fmt.Errorf("socks5 auth: read password: %w", err)
		}

		if string(uBuf) != user || string(pBuf) != pass {
			rw.Write([]byte{AuthUserPassVersion, AuthFailure})
			return fmt.Errorf("socks5 auth: invalid credentials")
		}

		_, err := rw.Write([]byte{AuthUserPassVersion, AuthSuccess})
		return err
	}

	// No auth required — accept 0x00
	for _, m := range methods {
		if m == AuthNone {
			_, err := rw.Write([]byte{Socks5Version, AuthNone})
			return err
		}
	}

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

// Socks5Dial performs a complete SOCKS5 client handshake on an existing connection:
// greeting → auth (optional) → CONNECT request → read reply.
// Returns nil on success (connection is ready for relaying).
func Socks5Dial(rw io.ReadWriter, target, user, pass string) error {
	host, portStr, err := net.SplitHostPort(target)
	if err != nil {
		return fmt.Errorf("socks5 dial: invalid target %q: %w", target, err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return fmt.Errorf("socks5 dial: invalid port in %q: %w", target, err)
	}

	// Step 1: Send greeting
	if user != "" {
		_, err = rw.Write([]byte{Socks5Version, 2, AuthNone, AuthUserPass})
	} else {
		_, err = rw.Write([]byte{Socks5Version, 1, AuthNone})
	}
	if err != nil {
		return fmt.Errorf("socks5 dial: write greeting: %w", err)
	}

	// Step 2: Read server method selection
	methodReply := make([]byte, 2)
	if _, err := io.ReadFull(rw, methodReply); err != nil {
		return fmt.Errorf("socks5 dial: read method reply: %w", err)
	}
	if methodReply[0] != Socks5Version {
		return fmt.Errorf("socks5 dial: server version %d", methodReply[0])
	}

	// Step 3: Handle auth if required
	switch methodReply[1] {
	case AuthNone:
		// no auth needed
	case AuthUserPass:
		if user == "" {
			return fmt.Errorf("socks5 dial: server requires auth but no credentials")
		}
		// RFC 1929: send [ver, ulen, user, plen, pass]
		authBuf := make([]byte, 0, 3+len(user)+len(pass))
		authBuf = append(authBuf, AuthUserPassVersion, byte(len(user)))
		authBuf = append(authBuf, []byte(user)...)
		authBuf = append(authBuf, byte(len(pass)))
		authBuf = append(authBuf, []byte(pass)...)
		if _, err := rw.Write(authBuf); err != nil {
			return fmt.Errorf("socks5 dial: write auth: %w", err)
		}
		authReply := make([]byte, 2)
		if _, err := io.ReadFull(rw, authReply); err != nil {
			return fmt.Errorf("socks5 dial: read auth reply: %w", err)
		}
		if authReply[1] != AuthSuccess {
			return fmt.Errorf("socks5 dial: auth failed (status %d)", authReply[1])
		}
	case AuthReject:
		return fmt.Errorf("socks5 dial: server rejected all auth methods")
	default:
		return fmt.Errorf("socks5 dial: unsupported auth method 0x%02x", methodReply[1])
	}

	// Step 4: Send CONNECT request with domain address
	req := make([]byte, 0, 7+len(host))
	req = append(req, Socks5Version, CmdConnect, 0x00, AddrDomain)
	req = append(req, byte(len(host)))
	req = append(req, []byte(host)...)
	req = append(req, byte(port>>8), byte(port))
	if _, err := rw.Write(req); err != nil {
		return fmt.Errorf("socks5 dial: write connect: %w", err)
	}

	// Step 5: Read reply [ver, rep, rsv, atyp, addr..., port]
	reply := make([]byte, 4)
	if _, err := io.ReadFull(rw, reply); err != nil {
		return fmt.Errorf("socks5 dial: read reply header: %w", err)
	}
	if reply[1] != RepSuccess {
		return fmt.Errorf("socks5 dial: connect failed (rep=0x%02x)", reply[1])
	}

	// Skip bind address
	switch reply[3] {
	case AddrIPv4:
		skip := make([]byte, 4+2)
		io.ReadFull(rw, skip)
	case AddrDomain:
		dLen := make([]byte, 1)
		io.ReadFull(rw, dLen)
		skip := make([]byte, int(dLen[0])+2)
		io.ReadFull(rw, skip)
	case AddrIPv6:
		skip := make([]byte, 16+2)
		io.ReadFull(rw, skip)
	default:
		skip := make([]byte, 4+2)
		io.ReadFull(rw, skip)
	}

	return nil
}
