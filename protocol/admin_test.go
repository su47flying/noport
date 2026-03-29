package protocol

import (
	"bytes"
	"encoding/binary"
	"testing"
)

func TestRoundTrip(t *testing.T) {
	tests := []struct {
		name string
		msg  *AdminMessage
	}{
		{
			name: "empty payload",
			msg:  &AdminMessage{Type: MsgHeartbeat, Reserved: 0},
		},
		{
			name: "with payload",
			msg:  &AdminMessage{Type: MsgCreateDataConn, Reserved: 0, Payload: []byte("hello world")},
		},
		{
			name: "close message",
			msg:  &AdminMessage{Type: MsgClose, Reserved: 0},
		},
		{
			name: "reserved field set",
			msg:  &AdminMessage{Type: MsgHeartbeat, Reserved: 42, Payload: []byte{0xDE, 0xAD}},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var buf bytes.Buffer
			if err := WriteAdminMessage(&buf, tc.msg); err != nil {
				t.Fatalf("WriteAdminMessage: %v", err)
			}

			got, err := ReadAdminMessage(&buf)
			if err != nil {
				t.Fatalf("ReadAdminMessage: %v", err)
			}

			if got.Type != tc.msg.Type {
				t.Errorf("Type = 0x%02X, want 0x%02X", got.Type, tc.msg.Type)
			}
			if got.Reserved != tc.msg.Reserved {
				t.Errorf("Reserved = %d, want %d", got.Reserved, tc.msg.Reserved)
			}
			if !bytes.Equal(got.Payload, tc.msg.Payload) {
				t.Errorf("Payload = %v, want %v", got.Payload, tc.msg.Payload)
			}
		})
	}
}

func TestInvalidMagic(t *testing.T) {
	var buf bytes.Buffer
	header := make([]byte, AdminHeaderLen)
	binary.BigEndian.PutUint32(header[0:4], 0xDEADBEEF) // wrong magic
	binary.BigEndian.PutUint32(header[4:8], 0)
	header[8] = MsgHeartbeat
	binary.BigEndian.PutUint32(header[9:13], 0)
	buf.Write(header)

	_, err := ReadAdminMessage(&buf)
	if err == nil {
		t.Fatal("expected error for invalid magic, got nil")
	}
}

func TestConstructors(t *testing.T) {
	t.Run("NewCreateDataConnMsg", func(t *testing.T) {
		msg := NewCreateDataConnMsg()
		if msg.Type != MsgCreateDataConn {
			t.Errorf("Type = 0x%02X, want 0x%02X", msg.Type, MsgCreateDataConn)
		}
		if msg.Payload != nil {
			t.Errorf("Payload = %v, want nil", msg.Payload)
		}
	})

	t.Run("NewHeartbeatMsg", func(t *testing.T) {
		msg := NewHeartbeatMsg()
		if msg.Type != MsgHeartbeat {
			t.Errorf("Type = 0x%02X, want 0x%02X", msg.Type, MsgHeartbeat)
		}
	})

	t.Run("NewCloseMsg", func(t *testing.T) {
		msg := NewCloseMsg()
		if msg.Type != MsgClose {
			t.Errorf("Type = 0x%02X, want 0x%02X", msg.Type, MsgClose)
		}
	})
}

func TestEmptyPayload(t *testing.T) {
	var buf bytes.Buffer
	msg := &AdminMessage{Type: MsgHeartbeat}
	if err := WriteAdminMessage(&buf, msg); err != nil {
		t.Fatalf("WriteAdminMessage: %v", err)
	}

	// Header only, no payload bytes
	if buf.Len() != AdminHeaderLen {
		t.Errorf("written bytes = %d, want %d", buf.Len(), AdminHeaderLen)
	}

	got, err := ReadAdminMessage(&buf)
	if err != nil {
		t.Fatalf("ReadAdminMessage: %v", err)
	}
	if got.Payload != nil {
		t.Errorf("Payload = %v, want nil", got.Payload)
	}
}

func TestNonEmptyPayload(t *testing.T) {
	payload := []byte("test payload data")
	var buf bytes.Buffer
	msg := &AdminMessage{Type: MsgCreateDataConn, Payload: payload}
	if err := WriteAdminMessage(&buf, msg); err != nil {
		t.Fatalf("WriteAdminMessage: %v", err)
	}

	if buf.Len() != AdminHeaderLen+len(payload) {
		t.Errorf("written bytes = %d, want %d", buf.Len(), AdminHeaderLen+len(payload))
	}

	got, err := ReadAdminMessage(&buf)
	if err != nil {
		t.Fatalf("ReadAdminMessage: %v", err)
	}
	if !bytes.Equal(got.Payload, payload) {
		t.Errorf("Payload = %v, want %v", got.Payload, payload)
	}
}

func TestPayloadTooLarge(t *testing.T) {
	var buf bytes.Buffer
	header := make([]byte, AdminHeaderLen)
	binary.BigEndian.PutUint32(header[0:4], AdminMagic)
	binary.BigEndian.PutUint32(header[4:8], 65537) // exceeds 64KB limit
	header[8] = MsgCreateDataConn
	binary.BigEndian.PutUint32(header[9:13], 0)
	buf.Write(header)

	_, err := ReadAdminMessage(&buf)
	if err == nil {
		t.Fatal("expected error for oversized payload, got nil")
	}
}

func TestPayloadExactLimit(t *testing.T) {
	payload := make([]byte, 65536) // exactly 64KB — should succeed
	var buf bytes.Buffer
	msg := &AdminMessage{Type: MsgHeartbeat, Payload: payload}
	if err := WriteAdminMessage(&buf, msg); err != nil {
		t.Fatalf("WriteAdminMessage: %v", err)
	}

	got, err := ReadAdminMessage(&buf)
	if err != nil {
		t.Fatalf("ReadAdminMessage: %v", err)
	}
	if len(got.Payload) != 65536 {
		t.Errorf("Payload length = %d, want 65536", len(got.Payload))
	}
}
