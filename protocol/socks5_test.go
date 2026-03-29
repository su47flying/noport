package protocol

import (
	"bytes"
	"encoding/binary"
	"net"
	"testing"
)

func TestHandshakeSuccess(t *testing.T) {
	// Client offers two methods: 0x01, 0x00. Server should pick 0x00.
	input := []byte{0x05, 0x02, 0x01, 0x00}
	buf := &bytes.Buffer{}
	buf.Write(input)

	if err := HandleSocks5Handshake(buf); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	resp := buf.Bytes()
	if len(resp) != 2 || resp[0] != 0x05 || resp[1] != 0x00 {
		t.Fatalf("unexpected response: %x", resp)
	}
}

func TestHandshakeWrongVersion(t *testing.T) {
	input := []byte{0x04, 0x01, 0x00}
	buf := &bytes.Buffer{}
	buf.Write(input)

	err := HandleSocks5Handshake(buf)
	if err == nil {
		t.Fatal("expected error for wrong version")
	}
}

func TestHandshakeNoAcceptableAuth(t *testing.T) {
	// Client only offers method 0x02 (username/password), not 0x00.
	input := []byte{0x05, 0x01, 0x02}
	buf := &bytes.Buffer{}
	buf.Write(input)

	err := HandleSocks5Handshake(buf)
	if err == nil {
		t.Fatal("expected error for no acceptable auth")
	}

	resp := buf.Bytes()
	if len(resp) != 2 || resp[0] != 0x05 || resp[1] != 0xFF {
		t.Fatalf("expected reject response, got: %x", resp)
	}
}

func TestReadRequestIPv4(t *testing.T) {
	var buf bytes.Buffer
	// header: version=5, cmd=CONNECT, rsv=0, atyp=IPv4
	buf.Write([]byte{0x05, 0x01, 0x00, 0x01})
	// IPv4: 192.168.1.1
	buf.Write(net.IPv4(192, 168, 1, 1).To4())
	// Port: 8080
	portBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(portBytes, 8080)
	buf.Write(portBytes)

	req, err := ReadSocks5Request(&buf)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if req.AddrType != AddrIPv4 {
		t.Fatalf("expected AddrIPv4, got 0x%02x", req.AddrType)
	}
	if req.Addr != "192.168.1.1" {
		t.Fatalf("expected 192.168.1.1, got %s", req.Addr)
	}
	if req.Port != 8080 {
		t.Fatalf("expected port 8080, got %d", req.Port)
	}
	if req.Target() != "192.168.1.1:8080" {
		t.Fatalf("unexpected target: %s", req.Target())
	}
}

func TestReadRequestDomain(t *testing.T) {
	var buf bytes.Buffer
	domain := "example.com"
	buf.Write([]byte{0x05, 0x01, 0x00, 0x03})
	buf.WriteByte(byte(len(domain)))
	buf.WriteString(domain)
	portBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(portBytes, 443)
	buf.Write(portBytes)

	req, err := ReadSocks5Request(&buf)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if req.AddrType != AddrDomain {
		t.Fatalf("expected AddrDomain, got 0x%02x", req.AddrType)
	}
	if req.Addr != domain {
		t.Fatalf("expected %s, got %s", domain, req.Addr)
	}
	if req.Port != 443 {
		t.Fatalf("expected port 443, got %d", req.Port)
	}
	if req.Target() != "example.com:443" {
		t.Fatalf("unexpected target: %s", req.Target())
	}
}

func TestReadRequestIPv6(t *testing.T) {
	var buf bytes.Buffer
	buf.Write([]byte{0x05, 0x01, 0x00, 0x04})
	ip := net.ParseIP("::1")
	buf.Write(ip.To16())
	portBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(portBytes, 80)
	buf.Write(portBytes)

	req, err := ReadSocks5Request(&buf)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if req.AddrType != AddrIPv6 {
		t.Fatalf("expected AddrIPv6, got 0x%02x", req.AddrType)
	}
	if req.Addr != "::1" {
		t.Fatalf("expected ::1, got %s", req.Addr)
	}
	if req.Port != 80 {
		t.Fatalf("expected port 80, got %d", req.Port)
	}
}

func TestWriteReply(t *testing.T) {
	var buf bytes.Buffer
	err := WriteSocks5Reply(&buf, RepSuccess, net.IPv4(127, 0, 0, 1), 1080)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	data := buf.Bytes()
	if len(data) != 10 {
		t.Fatalf("expected 10 bytes, got %d", len(data))
	}
	if data[0] != 0x05 {
		t.Fatalf("expected version 5, got %d", data[0])
	}
	if data[1] != RepSuccess {
		t.Fatalf("expected rep 0x00, got 0x%02x", data[1])
	}
	if data[3] != AddrIPv4 {
		t.Fatalf("expected atyp IPv4, got 0x%02x", data[3])
	}
	ip := net.IP(data[4:8])
	if !ip.Equal(net.IPv4(127, 0, 0, 1)) {
		t.Fatalf("expected 127.0.0.1, got %s", ip)
	}
	port := binary.BigEndian.Uint16(data[8:10])
	if port != 1080 {
		t.Fatalf("expected port 1080, got %d", port)
	}
}

func TestWriteReplyNilAddr(t *testing.T) {
	var buf bytes.Buffer
	err := WriteSocks5Reply(&buf, RepGeneralFailure, nil, 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	data := buf.Bytes()
	ip := net.IP(data[4:8])
	if !ip.Equal(net.IPv4zero.To4()) {
		t.Fatalf("expected 0.0.0.0, got %s", ip)
	}
}
