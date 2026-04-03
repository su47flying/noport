package client

import (
	"net"
	"noport/pkg"
	"sync"
)

const relayBufSize = 128 << 10 // 128KB

var relayBufPool = sync.Pool{
	New: func() any { return make([]byte, relayBufSize) },
}

// relay copies data bidirectionally between two net.Conn.
// When one direction finishes, the other is terminated promptly.
// Returns (fromB, fromA):
//   - fromB: bytes read from b and written to a
//   - fromA: bytes read from a and written to b
func relay(a, b net.Conn) (fromB int64, fromA int64) {
	stats := pkg.Relay(a, b, &relayBufPool)
	return stats.BToA.Bytes, stats.AToB.Bytes
}
