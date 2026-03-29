package tunnel

import (
	"context"
	"log/slog"
	"net"
	"noport/protocol"
	"sync"
	"time"
)

const (
	HeartbeatInterval = 10 * time.Second
	HeartbeatTimeout  = 30 * time.Second
)

// AdminQueue manages the admin control channel between Server and Client.
// It handles heartbeat keepalive and message dispatching.
type AdminQueue struct {
	conn      net.Conn
	mu        sync.Mutex
	lastRecv  time.Time
	onMessage func(*protocol.AdminMessage)
	ctx       context.Context
	cancel    context.CancelFunc
	done      chan struct{}
}

// NewAdminQueue creates a new admin queue over the given connection.
// onMessage is called for each non-heartbeat message received.
func NewAdminQueue(conn net.Conn, onMessage func(*protocol.AdminMessage)) *AdminQueue {
	ctx, cancel := context.WithCancel(context.Background())
	aq := &AdminQueue{
		conn:      conn,
		lastRecv:  time.Now(),
		onMessage: onMessage,
		ctx:       ctx,
		cancel:    cancel,
		done:      make(chan struct{}),
	}
	go aq.readLoop()
	go aq.heartbeatLoop()
	return aq
}

// Send sends an admin message (thread-safe).
func (aq *AdminQueue) Send(msg *protocol.AdminMessage) error {
	aq.mu.Lock()
	defer aq.mu.Unlock()
	return protocol.WriteAdminMessage(aq.conn, msg)
}

// Close closes the admin queue.
func (aq *AdminQueue) Close() error {
	aq.cancel()
	err := aq.conn.Close()
	<-aq.done
	return err
}

// Done returns a channel that is closed when the admin queue is done.
func (aq *AdminQueue) Done() <-chan struct{} {
	return aq.done
}

// readLoop continuously reads messages from the connection.
func (aq *AdminQueue) readLoop() {
	defer close(aq.done)
	for {
		msg, err := protocol.ReadAdminMessage(aq.conn)
		if err != nil {
			select {
			case <-aq.ctx.Done():
				// Expected shutdown, no need to log an error.
			default:
				slog.Error("admin read error", "err", err)
			}
			aq.cancel()
			return
		}

		aq.mu.Lock()
		aq.lastRecv = time.Now()
		aq.mu.Unlock()

		if msg.Type == protocol.MsgHeartbeat {
			continue
		}
		if aq.onMessage != nil {
			aq.onMessage(msg)
		}
	}
}

// heartbeatLoop sends periodic heartbeat messages and checks for liveness.
func (aq *AdminQueue) heartbeatLoop() {
	ticker := time.NewTicker(HeartbeatInterval)
	defer ticker.Stop()
	for {
		select {
		case <-aq.ctx.Done():
			return
		case <-ticker.C:
			if err := aq.Send(protocol.NewHeartbeatMsg()); err != nil {
				slog.Error("admin heartbeat send error", "err", err)
				aq.cancel()
				_ = aq.conn.Close()
				return
			}
			aq.mu.Lock()
			elapsed := time.Since(aq.lastRecv)
			aq.mu.Unlock()
			if elapsed > HeartbeatTimeout {
				slog.Warn("admin heartbeat timeout", "elapsed", elapsed)
				aq.cancel()
				_ = aq.conn.Close()
				return
			}
		}
	}
}
