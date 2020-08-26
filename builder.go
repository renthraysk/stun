package stun

import (
	"crypto/sha256"
	"encoding/binary"
	"net"
)

// @TODO Enforce attribute length limits
// @TODO Enforce attributes to each STUN message class they belong

/*
	state enforces the structure of the STUN message.

	Most attributes can appear in any order.
	If Fingerprint attribute is present it must be the last.
	If MessageIntegritySHA256 attribute is present it must be last or succeeded by a Fingerprint attribute
	If MessageIntegrity attribute is present it must be last or succeeded by a MessageIntegritySHA256 or Fingerprint or both.
*/
type state uint

const (
	stOpen state = iota
	stMessageIntegrity
	stMessageIntegritySHA256
	stFingerprint
	stErrInvalidAttributeAppend
	stErrInvalidMessageIntegritySHA256Length
)

const (
	ErrAttrInvalidAttributeAppend          = errorString("invalid attribute appended after MessageIntegrity, MessageIntegritySHA256 or Fingerprint")
	ErrInvalidMessageIntegritySHA256Length = errorString("invalid MessageIntegritySHA256 length")
)

type Builder struct {
	state
	msg []byte
}

func New(t Type, txID TxID) *Builder {
	return &Builder{msg: newHeader(make([]byte, 0, 512), t, txID)}
}

// AppendSoftware appends Software attribute to the STUN message
func (b *Builder) AppendSoftware(name string) {
	if b.state == stOpen {
		b.msg = appendSoftware(b.msg, name)
	} else if b.state < stErrInvalidAttributeAppend {
		b.state = stErrInvalidAttributeAppend
	}
}

// AppendSoftware appends Software attribute to the STUN message.
// Must be the last attribute appended to a STUN message.
func (b *Builder) AppendFingerprint() {
	if b.state < stFingerprint {
		b.state = stFingerprint
		b.msg = appendFingerprint(b.msg)
	} else if b.state < stErrInvalidAttributeAppend {
		b.state = stErrInvalidAttributeAppend
	}
}

func (b *Builder) AppendMessageIntegrity(key []byte) {
	if b.state < stMessageIntegrity {
		b.state = stMessageIntegrity
		b.msg = appendMessageIntegrity(b.msg, key)
	} else if b.state < stErrInvalidAttributeAppend {
		b.state = stErrInvalidAttributeAppend
	}
}

// AppendMessageIntegritySHA256 appends a MessageIntegritySHA256 attribute.
func (b *Builder) AppendMessageIntegritySHA256(key []byte) {
	b.AppendMessageIntegritySHA256Truncated(key, sha256.Size)
}

// AppendMessageIntegritySHA256Truncated appends an optionally truncated MessageIntegritySHA256 attribute.
// n the length of the attribute should be between 16 and 32 inclusive, and divisible by 4.
func (b *Builder) AppendMessageIntegritySHA256Truncated(key []byte, n int) {
	if b.state < stMessageIntegritySHA256 {
		if n > sha256.Size || n < 16 || n%4 != 0 {
			b.state = stErrInvalidMessageIntegritySHA256Length
			return
		}
		b.state = stMessageIntegritySHA256
		b.msg = appendMessageIntegritySHA256(b.msg, key, n)
	} else if b.state < stErrInvalidAttributeAppend {
		b.state = stErrInvalidAttributeAppend
	}
}

func (b *Builder) AppendMappingAddress(addr *net.UDPAddr) {
	if b.state == stOpen {
		b.msg = appendMappedAddress(b.msg, addr.IP, uint16(addr.Port))
	} else if b.state < stErrInvalidAttributeAppend {
		b.state = stErrInvalidAttributeAppend
	}
}

func (b *Builder) AppendXorMappingAddress(addr *net.UDPAddr) {
	if b.state == stOpen {
		b.msg = appendXorMappedAddress(b.msg, addr.IP, uint16(addr.Port))
	} else if b.state < stErrInvalidAttributeAppend {
		b.state = stErrInvalidAttributeAppend
	}
}

func (b *Builder) AppendRealm(realm string) {
	if b.state == stOpen {
		b.msg = appendRealm(b.msg, realm)
	} else if b.state < stErrInvalidAttributeAppend {
		b.state = stErrInvalidAttributeAppend
	}
}

func (b *Builder) AppendNonce(nonce []byte) {
	if b.state == stOpen {
		b.msg = appendNonce(b.msg, nonce)
	} else if b.state < stErrInvalidAttributeAppend {
		b.state = stErrInvalidAttributeAppend
	}
}

func (b *Builder) AppendUserHash(userHash []byte) {
	if b.state == stOpen {
		b.msg = appendUserHash(b.msg, userHash)
	} else if b.state < stErrInvalidAttributeAppend {
		b.state = stErrInvalidAttributeAppend
	}
}

// Bytes return the raw STUN message or an error if one occurred during it's building.
func (b *Builder) Bytes() ([]byte, error) {
	if b.state < stErrInvalidAttributeAppend {
		binary.BigEndian.PutUint16(b.msg[2:4], uint16(len(b.msg)-headerSize))
		return b.msg, nil
	}
	switch b.state {
	case stErrInvalidAttributeAppend:
		return nil, ErrAttrInvalidAttributeAppend

	case stErrInvalidMessageIntegritySHA256Length:
		return nil, ErrInvalidMessageIntegritySHA256Length
	}
	panic("Unreachable")
}
