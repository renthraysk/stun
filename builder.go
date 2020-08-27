package stun

import (
	"crypto/sha256"
	"encoding/binary"
	"net"
)

// @TODO Enforce attributes to each STUN message class they belong
// @TODO Check for duplicate attributes appended?

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
	stErrInvalidAttributeAppend // Must be first error state
	stErrInvalidMessageIntegritySHA256Length
	stErrUsernameTooLong
	stErrSoftwareTooLong
	stErrRealmTooLong
	stErrNonceTooLong
	stErrInvalidErrorCode
	stErrReasonTooLong
	stErrInvalidUserHashLength
	stErrDomainTooLong
)

type Builder struct {
	state
	msg []byte
}

func New(t Type, txID TxID) *Builder {
	return &Builder{msg: newHeader(make([]byte, 0, 512), t, txID)}
}

// See https://tools.ietf.org/html/rfc8489#section-14.1
func (b *Builder) AppendMappingAddress(addr *net.UDPAddr) {

	if b.state > stOpen {
		if b.state < stErrInvalidAttributeAppend {
			b.state = stErrInvalidAttributeAppend
		}
		return
	}
	b.msg = appendMappedAddress(b.msg, addr.IP, uint16(addr.Port))
}

// https://tools.ietf.org/html/rfc8489#section-14.2
func (b *Builder) AppendXorMappingAddress(addr *net.UDPAddr) {
	if b.state > stOpen {
		if b.state < stErrInvalidAttributeAppend {
			b.state = stErrInvalidAttributeAppend
		}
		return
	}
	b.msg = appendXorMappedAddress(b.msg, addr.IP, uint16(addr.Port))
}

// See https://tools.ietf.org/html/rfc8489#section-14.3
func (b *Builder) AppendUsername(username string) {
	const maxByteLength = 513

	if b.state > stOpen {
		if b.state < stErrInvalidAttributeAppend {
			b.state = stErrInvalidAttributeAppend
		}
		return
	}
	if len(username) > maxByteLength {
		b.state = stErrUsernameTooLong
		return
	}
	b.msg = appendUsername(b.msg, username)
}

// See https://tools.ietf.org/html/rfc8489#section-14.4
func (b *Builder) AppendUserHash(userHash []byte) {
	if b.state > stOpen {
		if b.state < stErrInvalidAttributeAppend {
			b.state = stErrInvalidAttributeAppend
		}
		return
	}
	if len(userHash) != sha256.Size {
		b.state = stErrInvalidUserHashLength
		return
	}
	b.msg = appendUserHash(b.msg, userHash)
}

// See https://tools.ietf.org/html/rfc8489#section-14.5
func (b *Builder) AppendMessageIntegrity(key []byte) {
	if b.state >= stMessageIntegrity {
		if b.state < stErrInvalidAttributeAppend {
			b.state = stErrInvalidAttributeAppend
		}
		return
	}
	b.state = stMessageIntegrity
	b.msg = appendMessageIntegrity(b.msg, key)
}

// AppendMessageIntegritySHA256 appends a MessageIntegritySHA256 attribute.
func (b *Builder) AppendMessageIntegritySHA256(key []byte) {
	b.AppendMessageIntegritySHA256Truncated(key, sha256.Size)
}

// AppendMessageIntegritySHA256Truncated appends an optionally truncated MessageIntegritySHA256 attribute.
// n the length of the attribute should be between 16 and 32 inclusive, and be divisible by 4.
// See https://tools.ietf.org/html/rfc8489#section-14.6
func (b *Builder) AppendMessageIntegritySHA256Truncated(key []byte, n int) {
	if b.state >= stMessageIntegritySHA256 {
		if b.state < stErrInvalidAttributeAppend {
			b.state = stErrInvalidAttributeAppend
		}
		return
	}
	if n > sha256.Size || n < 16 || n%4 != 0 {
		b.state = stErrInvalidMessageIntegritySHA256Length
		return
	}
	b.state = stMessageIntegritySHA256
	b.msg = appendMessageIntegritySHA256(b.msg, key, n)
}

// AppendSoftware appends Software attribute to the STUN message.
// Must be the last attribute appended to a STUN message.
// See https://tools.ietf.org/html/rfc8489#section-14.7
func (b *Builder) AppendFingerprint() {
	if b.state >= stFingerprint {
		if b.state < stErrInvalidAttributeAppend {
			b.state = stErrInvalidAttributeAppend
		}
		return
	}
	b.state = stFingerprint
	b.msg = appendFingerprint(b.msg)
}

// See https://tools.ietf.org/html/rfc8489#section-14.8
func (b *Builder) AppendErrorCode(errorCode ErrorCode, reason string) {
	const maxByteLength = 763

	if b.state > stOpen {
		if b.state < stErrInvalidAttributeAppend {
			b.state = stErrInvalidAttributeAppend
		}
		return
	}
	if errorCode < 300 || errorCode > 699 {
		b.state = stErrInvalidErrorCode
		return
	}
	if len(reason) > maxByteLength {
		b.state = stErrReasonTooLong
		return
	}
	b.msg = appendErrorCode(b.msg, errorCode, reason)
}

// See https://tools.ietf.org/html/rfc8489#section-14.9
func (b *Builder) AppendRealm(realm string) {
	const maxByteLength = 763

	if b.state > stOpen {
		if b.state < stErrInvalidAttributeAppend {
			b.state = stErrInvalidAttributeAppend
		}
		return
	}
	if len(realm) > maxByteLength {
		b.state = stErrRealmTooLong
		return
	}
	b.msg = appendRealm(b.msg, realm)
}

// See https://tools.ietf.org/html/rfc8489#section-14.10
func (b *Builder) AppendNonce(nonce []byte) {
	const maxByteLength = 763

	if b.state > stOpen {
		if b.state < stErrInvalidAttributeAppend {
			b.state = stErrInvalidAttributeAppend
		}
		return
	}
	if len(nonce) > maxByteLength {
		b.state = stErrNonceTooLong
		return
	}
	b.msg = appendNonce(b.msg, nonce)
}

// See https://tools.ietf.org/html/rfc8489#section-14.11
func (b *Builder) AppendPasswordAlgorithms() {
	// @TODO
}

// See https://tools.ietf.org/html/rfc8489#section-14.12
func (b *Builder) AppendPasswordAlgorithm(passwordAlgorithm PasswordAlgorithm, parameters []byte) {
	if b.state > stOpen {
		if b.state < stErrInvalidAttributeAppend {
			b.state = stErrInvalidAttributeAppend
		}
		return
	}
	b.msg = appendPasswordAlgorithm(b.msg, passwordAlgorithm, parameters)
}

// See https://tools.ietf.org/html/rfc8489#section-14.13
func (b *Builder) AppendUnknownAttributes(attributes ...uint16) {
	if b.state > stOpen {
		if b.state < stErrInvalidAttributeAppend {
			b.state = stErrInvalidAttributeAppend
		}
		return
	}
	b.msg = appendUnknownAttributes(b.msg, attributes)
}

// AppendSoftware appends Software attribute to the STUN message
// See https://tools.ietf.org/html/rfc8489#section-14.14
func (b *Builder) AppendSoftware(software string) {
	const maxByteLength = 763

	if b.state == stOpen {
		if len(software) > maxByteLength {
			b.state = stErrSoftwareTooLong
			return
		}
		b.msg = appendSoftware(b.msg, software)
	} else if b.state < stErrInvalidAttributeAppend {
		b.state = stErrInvalidAttributeAppend
	}
}

// See https://tools.ietf.org/html/rfc8489#section-14.15
func (b *Builder) AppendAlternateServer(ip net.IP, port uint16) {
	if b.state == stOpen {
		b.msg = appendAlternateServer(b.msg, ip, port)
	} else if b.state < stErrInvalidAttributeAppend {
		b.state = stErrInvalidAttributeAppend
	}
}

// See https://tools.ietf.org/html/rfc8489#section-14.16
func (b *Builder) AppendAlternateDomain(domain string) {
	const maxDomainLength = 255

	if b.state == stOpen {
		if len(domain) > maxDomainLength {
			b.state = stErrDomainTooLong
			return
		}
		b.msg = appendAlternateDomain(b.msg, domain)
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
		return nil, ErrInvalidAttributeSequence
	case stErrInvalidMessageIntegritySHA256Length:
		return nil, ErrInvalidMessageIntegritySHA256Length
	case stErrUsernameTooLong:
		return nil, ErrUsernameTooLong
	case stErrSoftwareTooLong:
		return nil, ErrSoftwareTooLong
	case stErrRealmTooLong:
		return nil, ErrRealmTooLong
	case stErrNonceTooLong:
		return nil, ErrNonceTooLong
	case stErrInvalidErrorCode:
		return nil, ErrInvalidErrorCode
	case stErrReasonTooLong:
		return nil, ErrReasonTooLong
	case stErrInvalidUserHashLength:
		return nil, ErrInvalidUserHashLength
	case stErrDomainTooLong:
		return nil, ErrDomainTooLong
	}
	panic("Unreachable")
}
