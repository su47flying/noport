package main

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"noport/client"
	_ "noport/crypto"
	"noport/pkg"
	"noport/server"
)

// TestE2E tests the complete SOCKS5 proxy chain:
// curl → SOCKS5 → Server → encrypted tunnel → Client → target HTTP server
func TestE2E(t *testing.T) {
	for _, cipher := range []string{"xor", "chacha20"} {
		t.Run(cipher, func(t *testing.T) {
			testE2EWithCipher(t, cipher)
		})
	}
}

func testE2EWithCipher(t *testing.T, cipherName string) {
	pkg.InitLogger(true)

	// 1. Start a test HTTP server (the actual target)
	targetSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "hello from target")
	}))
	defer targetSrv.Close()

	// 2. Find free ports for admin, data, and socks5
	adminPort := getFreePort(t)
	dataPort := getFreePort(t)
	socks5Port := getFreePort(t)

	// 3. Create and start Server
	serverCfg := &pkg.Config{
		Listens: []pkg.Endpoint{
			{Scheme: "socks5", Host: "", Port: socks5Port, Raw: fmt.Sprintf("socks5://:%d", socks5Port)},
		},
		Remotes: []pkg.Endpoint{
			{Scheme: "admin", Host: "", Port: adminPort, Raw: fmt.Sprintf("admin://:%d", adminPort)},
			{Scheme: cipherName, Host: "", Port: dataPort, Raw: fmt.Sprintf("%s://:%d", cipherName, dataPort)},
		},
		Key:   "test-key-123",
		Debug: true,
	}

	srv, err := server.New(serverCfg)
	if err != nil {
		t.Fatalf("server.New: %v", err)
	}

	srvDone := make(chan error, 1)
	go func() {
		srvDone <- srv.Run()
	}()
	defer func() {
		srv.Shutdown()
		<-srvDone
	}()

	// Give server time to start all listeners
	time.Sleep(300 * time.Millisecond)

	// 4. Create and start Client
	clientCfg := &pkg.Config{
		Connects: []pkg.Endpoint{
			{Scheme: cipherName, Host: "127.0.0.1", Port: dataPort, Raw: fmt.Sprintf("%s://127.0.0.1:%d", cipherName, dataPort)},
			{Scheme: "admin", Host: "127.0.0.1", Port: adminPort, Raw: fmt.Sprintf("admin://127.0.0.1:%d", adminPort)},
		},
		Key:   "test-key-123",
		Debug: true,
	}

	cli, err := client.New(clientCfg)
	if err != nil {
		t.Fatalf("client.New: %v", err)
	}

	cliDone := make(chan error, 1)
	go func() {
		cliDone <- cli.Run()
	}()
	defer func() {
		cli.Shutdown()
		<-cliDone
	}()

	// Give client time to connect and establish data connections
	time.Sleep(1 * time.Second)

	// 5. Make SOCKS5 request through the proxy
	socks5Addr := fmt.Sprintf("127.0.0.1:%d", socks5Port)
	proxyConn, err := net.DialTimeout("tcp", socks5Addr, 5*time.Second)
	if err != nil {
		t.Fatalf("dial socks5: %v", err)
	}
	defer proxyConn.Close()

	// Set an overall deadline for the SOCKS5 exchange
	proxyConn.SetDeadline(time.Now().Add(10 * time.Second))

	// SOCKS5 handshake: [version=5, nmethods=1, method=0(no auth)]
	if _, err := proxyConn.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		t.Fatalf("socks5 handshake write: %v", err)
	}

	// Read handshake response [version=5, method=0]
	hsResp := make([]byte, 2)
	if _, err := io.ReadFull(proxyConn, hsResp); err != nil {
		t.Fatalf("socks5 handshake read: %v", err)
	}
	if hsResp[0] != 0x05 || hsResp[1] != 0x00 {
		t.Fatalf("unexpected handshake response: %v", hsResp)
	}

	// Parse target server's host:port
	targetHost, targetPort := parseHostPort(t, targetSrv.URL)

	// SOCKS5 CONNECT request
	connectReq := buildSocks5ConnectRequest(targetHost, targetPort)
	if _, err := proxyConn.Write(connectReq); err != nil {
		t.Fatalf("socks5 connect write: %v", err)
	}

	// Read CONNECT response (at least 10 bytes for IPv4 reply)
	connResp := make([]byte, 10)
	if _, err := io.ReadFull(proxyConn, connResp); err != nil {
		t.Fatalf("socks5 connect read: %v", err)
	}
	if connResp[1] != 0x00 {
		t.Fatalf("socks5 connect failed with reply code: %d", connResp[1])
	}

	// 6. Send HTTP request through the established tunnel
	httpReq := fmt.Sprintf("GET / HTTP/1.1\r\nHost: %s:%d\r\nConnection: close\r\n\r\n", targetHost, targetPort)
	if _, err := proxyConn.Write([]byte(httpReq)); err != nil {
		t.Fatalf("http request write: %v", err)
	}

	// Read HTTP response using http.ReadResponse which respects Content-Length
	// (the mux stream doesn't support half-close, so io.ReadAll would block)
	bufReader := bufio.NewReader(proxyConn)
	resp, err := http.ReadResponse(bufReader, &http.Request{Method: "GET"})
	if err != nil {
		t.Fatalf("http response read: %v", err)
	}
	body, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		t.Fatalf("http body read: %v", err)
	}

	if resp.StatusCode != 200 {
		t.Fatalf("unexpected status code: %d", resp.StatusCode)
	}
	if !strings.Contains(string(body), "hello from target") {
		t.Fatalf("unexpected response body: %s", string(body))
	}

	t.Logf("E2E test passed with cipher %s", cipherName)
}

func getFreePort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("getFreePort: %v", err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	ln.Close()
	return port
}

func parseHostPort(t *testing.T, rawURL string) (string, uint16) {
	t.Helper()
	u, err := url.Parse(rawURL)
	if err != nil {
		t.Fatalf("parse URL %q: %v", rawURL, err)
	}
	host, portStr, err := net.SplitHostPort(u.Host)
	if err != nil {
		t.Fatalf("split host:port %q: %v", u.Host, err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		t.Fatalf("parse port %q: %v", portStr, err)
	}
	return host, uint16(port)
}

func buildSocks5ConnectRequest(host string, port uint16) []byte {
	ip := net.ParseIP(host)
	if ip != nil && ip.To4() != nil {
		// IPv4: [VER=5, CMD=CONNECT=1, RSV=0, ATYP=IPv4=1, IP(4), PORT(2)]
		req := []byte{0x05, 0x01, 0x00, 0x01}
		req = append(req, ip.To4()...)
		req = append(req, byte(port>>8), byte(port))
		return req
	}
	// Domain: [VER=5, CMD=CONNECT=1, RSV=0, ATYP=DOMAIN=3, LEN, DOMAIN..., PORT(2)]
	req := []byte{0x05, 0x01, 0x00, 0x03, byte(len(host))}
	req = append(req, []byte(host)...)
	req = append(req, byte(port>>8), byte(port))
	return req
}
