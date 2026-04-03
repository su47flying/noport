package protocol

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
)

// ReadHTTPRequest reads an HTTP request from the connection using bufio.Reader.
// Returns the parsed request and the buffered reader (which may hold unread data).
func ReadHTTPRequest(r *bufio.Reader) (*http.Request, error) {
	req, err := http.ReadRequest(r)
	if err != nil {
		return nil, fmt.Errorf("http proxy: read request: %w", err)
	}
	return req, nil
}

// HTTPTargetFromRequest extracts the target host:port from an HTTP request.
// For CONNECT: uses req.Host directly (already host:port).
// For plain HTTP: uses Host header, defaults port to 80.
func HTTPTargetFromRequest(req *http.Request) string {
	if req.Method == http.MethodConnect {
		return req.Host
	}
	host := req.Host
	if host == "" {
		host = req.URL.Host
	}
	if _, _, err := net.SplitHostPort(host); err != nil {
		host = net.JoinHostPort(host, "80")
	}
	return host
}

// WriteHTTPConnectOK writes "HTTP/1.1 200 Connection established\r\n\r\n".
func WriteHTTPConnectOK(w io.Writer) error {
	_, err := io.WriteString(w, "HTTP/1.1 200 Connection established\r\n\r\n")
	return err
}

// WriteHTTPError writes an HTTP error response.
func WriteHTTPError(w io.Writer, statusCode int, msg string) {
	fmt.Fprintf(w, "HTTP/1.1 %d %s\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s",
		statusCode, http.StatusText(statusCode), len(msg), msg)
}

// RewriteHTTPRequestToRelative rewrites an absolute-URI request
// (e.g. "GET http://example.com/path") to relative form ("GET /path")
// so it can be forwarded to the origin server.
func RewriteHTTPRequestToRelative(req *http.Request) []byte {
	path := req.URL.RequestURI()
	if req.URL.Scheme != "" {
		// Convert absolute URL to relative path
		path = req.URL.Path
		if req.URL.RawQuery != "" {
			path += "?" + req.URL.RawQuery
		}
		if path == "" {
			path = "/"
		}
	}

	var b strings.Builder
	fmt.Fprintf(&b, "%s %s %s\r\n", req.Method, path, req.Proto)
	// Go's http.ReadRequest moves Host into req.Host and removes from Header
	if req.Host != "" {
		fmt.Fprintf(&b, "Host: %s\r\n", req.Host)
	}
	req.Header.Write(&b)
	b.WriteString("\r\n")
	return []byte(b.String())
}
