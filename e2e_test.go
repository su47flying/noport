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

// TestE2ESocks5Auth tests SOCKS5 with username/password authentication.
func TestE2ESocks5Auth(t *testing.T) {
	pkg.InitLogger(true)

	targetSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "auth-ok")
	}))
	defer targetSrv.Close()

	adminPort := getFreePort(t)
	dataPort := getFreePort(t)
	socks5Port := getFreePort(t)

	serverCfg := &pkg.Config{
		Listens: []pkg.Endpoint{
			{Scheme: "socks5", Host: "", Port: socks5Port, User: "myuser", Pass: "mypass"},
		},
		Remotes: []pkg.Endpoint{
			{Scheme: "admin", Host: "", Port: adminPort},
			{Scheme: "xor", Host: "", Port: dataPort},
		},
		Key:   "test-key",
		Debug: true,
	}

	srv, err := server.New(serverCfg)
	if err != nil {
		t.Fatalf("server.New: %v", err)
	}
	srvDone := make(chan error, 1)
	go func() { srvDone <- srv.Run() }()
	defer func() { srv.Shutdown(); <-srvDone }()
	time.Sleep(300 * time.Millisecond)

	clientCfg := &pkg.Config{
		Connects: []pkg.Endpoint{
			{Scheme: "xor", Host: "127.0.0.1", Port: dataPort},
			{Scheme: "admin", Host: "127.0.0.1", Port: adminPort},
		},
		Key:   "test-key",
		Debug: true,
	}
	cli, err := client.New(clientCfg)
	if err != nil {
		t.Fatalf("client.New: %v", err)
	}
	cliDone := make(chan error, 1)
	go func() { cliDone <- cli.Run() }()
	defer func() { cli.Shutdown(); <-cliDone }()
	time.Sleep(1 * time.Second)

	// Test with CORRECT credentials
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", socks5Port), 5*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(10 * time.Second))

	// Offer user/pass auth
	conn.Write([]byte{0x05, 0x01, 0x02})
	resp := make([]byte, 2)
	io.ReadFull(conn, resp)
	if resp[1] != 0x02 {
		t.Fatalf("expected method 0x02, got 0x%02x", resp[1])
	}

	// Send credentials
	auth := []byte{0x01, 6}
	auth = append(auth, []byte("myuser")...)
	auth = append(auth, 6)
	auth = append(auth, []byte("mypass")...)
	conn.Write(auth)

	authResp := make([]byte, 2)
	io.ReadFull(conn, authResp)
	if authResp[1] != 0x00 {
		t.Fatalf("auth failed: %x", authResp)
	}

	// CONNECT
	targetHost, targetPort := parseHostPort(t, targetSrv.URL)
	conn.Write(buildSocks5ConnectRequest(targetHost, targetPort))
	connResp := make([]byte, 10)
	io.ReadFull(conn, connResp)
	if connResp[1] != 0x00 {
		t.Fatalf("connect failed: %d", connResp[1])
	}

	// HTTP through tunnel
	fmt.Fprintf(conn, "GET / HTTP/1.1\r\nHost: %s:%d\r\nConnection: close\r\n\r\n", targetHost, targetPort)
	httpResp, _ := http.ReadResponse(bufio.NewReader(conn), &http.Request{Method: "GET"})
	body, _ := io.ReadAll(httpResp.Body)
	httpResp.Body.Close()
	if string(body) != "auth-ok" {
		t.Fatalf("unexpected body: %s", string(body))
	}

	// Test with WRONG credentials — should fail
	conn2, _ := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", socks5Port), 5*time.Second)
	defer conn2.Close()
	conn2.SetDeadline(time.Now().Add(5 * time.Second))
	conn2.Write([]byte{0x05, 0x01, 0x02})
	io.ReadFull(conn2, resp)

	badAuth := []byte{0x01, 6}
	badAuth = append(badAuth, []byte("myuser")...)
	badAuth = append(badAuth, 3)
	badAuth = append(badAuth, []byte("bad")...)
	conn2.Write(badAuth)
	io.ReadFull(conn2, authResp)
	if authResp[1] != 0x01 {
		t.Fatalf("expected auth failure, got 0x%02x", authResp[1])
	}

	t.Log("SOCKS5 auth E2E passed")
}

// TestE2EHTTPProxy tests the HTTP CONNECT proxy through the tunnel.
func TestE2EHTTPProxy(t *testing.T) {
	pkg.InitLogger(true)

	targetSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "http-proxy-ok")
	}))
	defer targetSrv.Close()

	adminPort := getFreePort(t)
	dataPort := getFreePort(t)
	httpPort := getFreePort(t)

	serverCfg := &pkg.Config{
		Listens: []pkg.Endpoint{
			{Scheme: "http", Host: "", Port: httpPort},
		},
		Remotes: []pkg.Endpoint{
			{Scheme: "admin", Host: "", Port: adminPort},
			{Scheme: "xor", Host: "", Port: dataPort},
		},
		Key:   "test-key",
		Debug: true,
	}

	srv, err := server.New(serverCfg)
	if err != nil {
		t.Fatalf("server.New: %v", err)
	}
	srvDone := make(chan error, 1)
	go func() { srvDone <- srv.Run() }()
	defer func() { srv.Shutdown(); <-srvDone }()
	time.Sleep(300 * time.Millisecond)

	clientCfg := &pkg.Config{
		Connects: []pkg.Endpoint{
			{Scheme: "xor", Host: "127.0.0.1", Port: dataPort},
			{Scheme: "admin", Host: "127.0.0.1", Port: adminPort},
		},
		Key:   "test-key",
		Debug: true,
	}
	cli, err := client.New(clientCfg)
	if err != nil {
		t.Fatalf("client.New: %v", err)
	}
	cliDone := make(chan error, 1)
	go func() { cliDone <- cli.Run() }()
	defer func() { cli.Shutdown(); <-cliDone }()
	time.Sleep(1 * time.Second)

	// Use HTTP CONNECT through the proxy
	proxyURL, _ := url.Parse(fmt.Sprintf("http://127.0.0.1:%d", httpPort))
	httpClient := &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyURL(proxyURL),
		},
		Timeout: 10 * time.Second,
	}

	resp, err := httpClient.Get(targetSrv.URL)
	if err != nil {
		t.Fatalf("http get: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if string(body) != "http-proxy-ok" {
		t.Fatalf("unexpected body: %s", string(body))
	}
	t.Log("HTTP proxy E2E passed")
}

// TestE2EForwarder tests the forwarder chain:
// client → forwarder SOCKS5 → upstream SOCKS5 (server+tunnel) → target
func TestE2EForwarder(t *testing.T) {
	pkg.InitLogger(true)

	targetSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "forwarder-ok")
	}))
	defer targetSrv.Close()

	// Start a full server+client tunnel as the upstream
	adminPort := getFreePort(t)
	dataPort := getFreePort(t)
	upstreamSocks5Port := getFreePort(t)

	serverCfg := &pkg.Config{
		Listens: []pkg.Endpoint{
			{Scheme: "socks5", Host: "", Port: upstreamSocks5Port},
		},
		Remotes: []pkg.Endpoint{
			{Scheme: "admin", Host: "", Port: adminPort},
			{Scheme: "xor", Host: "", Port: dataPort},
		},
		Key:   "test-key",
		Debug: true,
	}
	srv, err := server.New(serverCfg)
	if err != nil {
		t.Fatalf("server.New: %v", err)
	}
	srvDone := make(chan error, 1)
	go func() { srvDone <- srv.Run() }()
	defer func() { srv.Shutdown(); <-srvDone }()
	time.Sleep(300 * time.Millisecond)

	clientCfg := &pkg.Config{
		Connects: []pkg.Endpoint{
			{Scheme: "xor", Host: "127.0.0.1", Port: dataPort},
			{Scheme: "admin", Host: "127.0.0.1", Port: adminPort},
		},
		Key:   "test-key",
		Debug: true,
	}
	cli, err := client.New(clientCfg)
	if err != nil {
		t.Fatalf("client.New: %v", err)
	}
	cliDone := make(chan error, 1)
	go func() { cliDone <- cli.Run() }()
	defer func() { cli.Shutdown(); <-cliDone }()
	time.Sleep(1 * time.Second)

	// Start forwarder: -L socks5://:localPort -F socks5://127.0.0.1:upstreamPort
	fwdPort := getFreePort(t)
	fwdCfg := &pkg.Config{
		Listens: []pkg.Endpoint{
			{Scheme: "socks5", Host: "", Port: fwdPort},
		},
		Forwards: []pkg.Endpoint{
			{Scheme: "socks5", Host: "127.0.0.1", Port: upstreamSocks5Port},
		},
		Debug: true,
	}
	fwd, err := server.NewForwarder(fwdCfg)
	if err != nil {
		t.Fatalf("NewForwarder: %v", err)
	}
	fwdDone := make(chan error, 1)
	go func() { fwdDone <- fwd.Run() }()
	defer func() { fwd.Shutdown(); <-fwdDone }()
	time.Sleep(300 * time.Millisecond)

	// Connect through the forwarder
	proxyConn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", fwdPort), 5*time.Second)
	if err != nil {
		t.Fatalf("dial forwarder: %v", err)
	}
	defer proxyConn.Close()
	proxyConn.SetDeadline(time.Now().Add(10 * time.Second))

	// SOCKS5 handshake with forwarder
	proxyConn.Write([]byte{0x05, 0x01, 0x00})
	hsResp := make([]byte, 2)
	io.ReadFull(proxyConn, hsResp)
	if hsResp[1] != 0x00 {
		t.Fatalf("handshake: %x", hsResp)
	}

	targetHost, targetPort := parseHostPort(t, targetSrv.URL)
	proxyConn.Write(buildSocks5ConnectRequest(targetHost, targetPort))
	connResp := make([]byte, 10)
	io.ReadFull(proxyConn, connResp)
	if connResp[1] != 0x00 {
		t.Fatalf("connect failed: %d", connResp[1])
	}

	fmt.Fprintf(proxyConn, "GET / HTTP/1.1\r\nHost: %s:%d\r\nConnection: close\r\n\r\n", targetHost, targetPort)
	httpResp, err := http.ReadResponse(bufio.NewReader(proxyConn), &http.Request{Method: "GET"})
	if err != nil {
		t.Fatalf("http read: %v", err)
	}
	body, _ := io.ReadAll(httpResp.Body)
	httpResp.Body.Close()
	if string(body) != "forwarder-ok" {
		t.Fatalf("unexpected body: %s", string(body))
	}
	t.Log("Forwarder E2E passed")
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
