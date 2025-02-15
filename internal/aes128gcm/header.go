package aes128gcm

import (
	"bytes"
	"encoding"
	"encoding/binary"
	"fmt"
)

var _ encoding.BinaryAppender = (*Header)(nil)
var _ encoding.BinaryMarshaler = (*Header)(nil)
var _ encoding.BinaryUnmarshaler = (*Header)(nil)

type Header struct {
	Salt [16]byte
	// RecordSize must be at least 17 bytes.
	RecordSize uint32
	// KeyID is nil if no key id is specified (i.e. key id length is zero).
	KeyID []byte
}

func (h *Header) Length() int {
	return 16 + 4 + 1 + len(h.KeyID)
}

// AppendBinary implements encoding.BinaryAppender.
func (h *Header) AppendBinary(b []byte) ([]byte, error) {
	b = append(b, h.Salt[:]...)
	b = binary.BigEndian.AppendUint32(b, h.RecordSize)
	b = append(b, byte(len(h.KeyID)))
	if h.KeyID != nil {
		b = append(b, h.KeyID...)
	}
	return b, nil
}

// MarshalBinary implements encoding.BinaryMarshaler.
func (h *Header) MarshalBinary() (data []byte, err error) {
	return h.AppendBinary(nil)
}

// UnmarshalBinary implements encoding.BinaryUnmarshaler.
func (h *Header) UnmarshalBinary(data []byte) error {
	if len(data) < 21 {
		return fmt.Errorf("invalid header length")
	}

	// Valid records always contain at least a padding delimiter octet and a
	// 16-octet authentication tag.
	recordSize := binary.BigEndian.Uint32(data[16:20])
	if recordSize < 17 {
		return fmt.Errorf("invalid record size")
	}

	keyIDLength := int(data[20])
	if len(data) < 20+keyIDLength {
		return fmt.Errorf("invalid key length")
	}

	*h = Header{}

	copy(h.Salt[:], data[0:16])
	h.RecordSize = recordSize
	if keyIDLength > 0 {
		h.KeyID = bytes.Clone(data[21 : 21+keyIDLength])
	}

	return nil
}
