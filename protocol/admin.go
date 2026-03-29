package protocol

import (
	"encoding/binary"
	"fmt"
	"io"
)

const (
	AdminMagic     = 0x4E505254 // "NPRT"
	AdminHeaderLen = 13

	MsgCreateDataConn byte = 0x01
	MsgHeartbeat      byte = 0x02
	MsgClose          byte = 0x03
)

// AdminMessage represents a message on the admin channel
type AdminMessage struct {
	Type     byte
	Reserved uint32
	Payload  []byte
}

// WriteAdminMessage writes a framed admin message to w
func WriteAdminMessage(w io.Writer, msg *AdminMessage) error {
	header := make([]byte, AdminHeaderLen)
	binary.BigEndian.PutUint32(header[0:4], AdminMagic)
	binary.BigEndian.PutUint32(header[4:8], uint32(len(msg.Payload)))
	header[8] = msg.Type
	binary.BigEndian.PutUint32(header[9:13], msg.Reserved)

	if _, err := w.Write(header); err != nil {
		return fmt.Errorf("write admin header: %w", err)
	}
	if len(msg.Payload) > 0 {
		if _, err := w.Write(msg.Payload); err != nil {
			return fmt.Errorf("write admin payload: %w", err)
		}
	}
	return nil
}

// ReadAdminMessage reads a framed admin message from r.
// Returns error if magic doesn't match or read fails.
// Enforces a max payload size of 64KB to prevent memory abuse.
func ReadAdminMessage(r io.Reader) (*AdminMessage, error) {
	header := make([]byte, AdminHeaderLen)
	if _, err := io.ReadFull(r, header); err != nil {
		return nil, fmt.Errorf("read admin header: %w", err)
	}

	magic := binary.BigEndian.Uint32(header[0:4])
	if magic != AdminMagic {
		return nil, fmt.Errorf("invalid admin magic: 0x%08X, expected 0x%08X", magic, AdminMagic)
	}

	payloadLen := binary.BigEndian.Uint32(header[4:8])
	if payloadLen > 65536 {
		return nil, fmt.Errorf("admin payload too large: %d bytes", payloadLen)
	}

	msg := &AdminMessage{
		Type:     header[8],
		Reserved: binary.BigEndian.Uint32(header[9:13]),
	}

	if payloadLen > 0 {
		msg.Payload = make([]byte, payloadLen)
		if _, err := io.ReadFull(r, msg.Payload); err != nil {
			return nil, fmt.Errorf("read admin payload: %w", err)
		}
	}

	return msg, nil
}

// NewCreateDataConnMsg creates a CreateDataConn message.
// Payload can optionally contain connection metadata.
func NewCreateDataConnMsg() *AdminMessage {
	return &AdminMessage{Type: MsgCreateDataConn}
}

// NewHeartbeatMsg creates a Heartbeat message
func NewHeartbeatMsg() *AdminMessage {
	return &AdminMessage{Type: MsgHeartbeat}
}

// NewCloseMsg creates a Close message
func NewCloseMsg() *AdminMessage {
	return &AdminMessage{Type: MsgClose}
}
