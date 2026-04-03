package pkg

import (
	"flag"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
)

// Endpoint represents a parsed URL-scheme endpoint.
type Endpoint struct {
	Scheme string // "xor", "chacha20", "admin", "socks5", "http"
	Host   string // hostname or empty
	Port   int    // port number
	User   string // optional username (for socks5 auth or -F upstream)
	Pass   string // optional password
	Raw    string // original string
}

// Config holds the parsed configuration.
type Config struct {
	Connects []Endpoint // -C flags (client mode)
	Listens  []Endpoint // -L flags (server mode)
	Remotes  []Endpoint // -R flags (server mode)
	Forwards []Endpoint // -F flags (forwarder mode)
	Key      string     // -key encryption key
	Debug    bool       // -debug flag
}

// IsClient returns true if running in client mode (has -C flags).
func (c *Config) IsClient() bool {
	return len(c.Connects) > 0
}

// IsForwarder returns true if running in forwarder mode (has -L and -F, no -C/-R).
func (c *Config) IsForwarder() bool {
	return len(c.Forwards) > 0 && len(c.Listens) > 0
}

// IsServer returns true if running in server mode (has -L and -R flags, not forwarder).
func (c *Config) IsServer() bool {
	return len(c.Remotes) > 0 && len(c.Listens) > 0
}

// GetEndpoint finds the first endpoint with the given scheme from a slice.
func GetEndpoint(endpoints []Endpoint, scheme string) (Endpoint, bool) {
	for _, ep := range endpoints {
		if ep.Scheme == scheme {
			return ep, true
		}
	}
	return Endpoint{}, false
}

// stringSlice implements flag.Value for repeated flag values.
type stringSlice []string

func (s *stringSlice) String() string {
	return strings.Join(*s, ",")
}

func (s *stringSlice) Set(value string) error {
	*s = append(*s, value)
	return nil
}

// parseEndpoint parses a "scheme://[user:pass@]host:port" string into an Endpoint.
func parseEndpoint(raw string) (Endpoint, error) {
	// Ensure scheme separator exists
	if !strings.Contains(raw, "://") {
		return Endpoint{}, fmt.Errorf("invalid endpoint format %q: expected scheme://host:port", raw)
	}

	u, err := url.Parse(raw)
	if err != nil {
		return Endpoint{}, fmt.Errorf("invalid endpoint %q: %w", raw, err)
	}

	scheme := strings.ToLower(u.Scheme)
	switch scheme {
	case "admin", "socks5", "xor", "chacha20", "http":
		// keep as-is
	default:
		scheme = "chacha20"
	}

	host, portStr, err := net.SplitHostPort(u.Host)
	if err != nil {
		return Endpoint{}, fmt.Errorf("invalid endpoint %q: %w", raw, err)
	}

	port, err := strconv.Atoi(portStr)
	if err != nil {
		return Endpoint{}, fmt.Errorf("invalid port in %q: %w", raw, err)
	}

	ep := Endpoint{
		Scheme: scheme,
		Host:   host,
		Port:   port,
		Raw:    raw,
	}

	if u.User != nil {
		ep.User = u.User.Username()
		ep.Pass, _ = u.User.Password()
	}

	return ep, nil
}

// parseEndpoints converts a slice of raw strings into Endpoints.
func parseEndpoints(raws []string) ([]Endpoint, error) {
	eps := make([]Endpoint, 0, len(raws))
	for _, raw := range raws {
		ep, err := parseEndpoint(raw)
		if err != nil {
			return nil, err
		}
		eps = append(eps, ep)
	}
	return eps, nil
}

// ParseConfig parses command line arguments and returns Config.
func ParseConfig() (*Config, error) {
	var connects, listens, remotes stringSlice

	var forwards stringSlice

	flag.Var(&connects, "C", "Client connect endpoint (scheme://host:port), may be repeated")
	flag.Var(&listens, "L", "Listen endpoint (scheme://[user:pass@]host:port), may be repeated")
	flag.Var(&remotes, "R", "Server remote endpoint (scheme://host:port), may be repeated")
	flag.Var(&forwards, "F", "Forward upstream (scheme://[user:pass@]host:port), may be repeated")

	key := flag.String("key", "", "Encryption key")
	debug := flag.Bool("debug", false, "Enable debug logging")

	flag.Parse()

	cfg := &Config{
		Key:   *key,
		Debug: *debug,
	}

	var err error

	if cfg.Connects, err = parseEndpoints(connects); err != nil {
		return nil, fmt.Errorf("parsing -C: %w", err)
	}
	if cfg.Listens, err = parseEndpoints(listens); err != nil {
		return nil, fmt.Errorf("parsing -L: %w", err)
	}
	if cfg.Remotes, err = parseEndpoints(remotes); err != nil {
		return nil, fmt.Errorf("parsing -R: %w", err)
	}
	if cfg.Forwards, err = parseEndpoints(forwards); err != nil {
		return nil, fmt.Errorf("parsing -F: %w", err)
	}

	// Validate: client mode must have an admin endpoint in -C
	if cfg.IsClient() {
		if _, ok := GetEndpoint(cfg.Connects, "admin"); !ok {
			return nil, fmt.Errorf("client mode requires an admin endpoint in -C flags")
		}
	}

	// Validate: server mode (non-forwarder) must have an admin endpoint in -R
	if cfg.IsServer() && !cfg.IsForwarder() {
		if _, ok := GetEndpoint(cfg.Remotes, "admin"); !ok {
			return nil, fmt.Errorf("server mode requires an admin endpoint in -R flags")
		}
	}

	return cfg, nil
}
