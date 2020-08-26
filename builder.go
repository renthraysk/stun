package stun

import (
	"encoding/binary"
	"net"
)

// @TODO Enforce attribute length limits
// @TODO Enforce attributes to each STUN message class they belong

type state uint

const (
	stOpen state = iota
	stMessageIntegrity
	stMessageIntegritySHA256
	stFingerprint
	stErrorInvalidAttributeAppend
)

const (
	ErrAttrInvalidAttributeAppend = errorString("invalid attribute appended after MessageIntegrity, MessageIntegritySHA256 or Fingerprint")
)

type Builder struct {
	state
	msg []byte
}

func New(t Type, txID TxID) *Builder {
	return &Builder{msg: newHeader(make([]byte, 0, 512), t, txID)}
}

func (b *Builder) AppendSoftware(name string) {
	if b.state == stOpen {
		b.msg = appendSoftware(b.msg, name)
	} else if b.state < stErrorInvalidAttributeAppend {
		b.state = stErrorInvalidAttributeAppend
	}
}

func (b *Builder) AppendFingerprint() {
	if b.state < stFingerprint {
		b.state = stFingerprint
		b.msg = appendFingerprint(b.msg)
	} else if b.state < stErrorInvalidAttributeAppend {
		b.state = stErrorInvalidAttributeAppend
	}
}

func (b *Builder) AppendMessageIntegrity(key []byte) {
	if b.state < stMessageIntegrity {
		b.state = stMessageIntegrity
		b.msg = appendMessageIntegrity(b.msg, key)
	} else if b.state < stErrorInvalidAttributeAppend {
		b.state = stErrorInvalidAttributeAppend
	}
}

func (b *Builder) AppendMessageIntegritySHA256(key []byte) {
	if b.state < stMessageIntegritySHA256 {
		b.state = stMessageIntegritySHA256
		b.msg = appendMessageIntegritySHA256(b.msg, key)
	} else if b.state < stErrorInvalidAttributeAppend {
		b.state = stErrorInvalidAttributeAppend
	}
}

func (b *Builder) AppendMappingAddress(addr *net.UDPAddr) {
	if b.state == stOpen {
		b.msg = appendMappedAddress(b.msg, addr.IP, uint16(addr.Port))
	} else if b.state < stErrorInvalidAttributeAppend {
		b.state = stErrorInvalidAttributeAppend
	}
}

func (b *Builder) AppendXorMappingAddress(addr *net.UDPAddr) {
	if b.state == stOpen {
		b.msg = appendXorMappedAddress(b.msg, addr.IP, uint16(addr.Port))
	} else if b.state < stErrorInvalidAttributeAppend {
		b.state = stErrorInvalidAttributeAppend
	}
}

func (b *Builder) AppendRealm(realm string) {
	if b.state == stOpen {
		b.msg = appendRealm(b.msg, realm)
	} else if b.state < stErrorInvalidAttributeAppend {
		b.state = stErrorInvalidAttributeAppend
	}
}

func (b *Builder) AppendNonce(nonce []byte) {
	if b.state == stOpen {
		b.msg = appendNonce(b.msg, nonce)
	} else if b.state < stErrorInvalidAttributeAppend {
		b.state = stErrorInvalidAttributeAppend
	}
}

func (b *Builder) AppendUserHash(userHash []byte) {
	if b.state == stOpen {
		b.msg = appendUserHash(b.msg, userHash)
	} else if b.state < stErrorInvalidAttributeAppend {
		b.state = stErrorInvalidAttributeAppend
	}
}

func (b *Builder) Bytes() ([]byte, error) {
	if b.state < stErrorInvalidAttributeAppend {
		binary.BigEndian.PutUint16(b.msg[2:4], uint16(len(b.msg)-headerSize))
		return b.msg, nil
	}
	return nil, ErrAttrInvalidAttributeAppend
}
