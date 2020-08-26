package stun

import (
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/binary"
	"hash"
	"hash/crc32"
)

const (
	ErrMalformedAttribute       = errorString("malformed attribute")
	ErrNotASTUNMessage          = errorString("not a stun message")
	ErrFingerprint              = errorString("fingerprint check failed")
	ErrMessageIntegrity         = errorString("messageintegrity check failed")
	ErrMessageIntegritySHA256   = errorString("messageintegritysha256 check failed")
	ErrUnknownPasswordAlgorithm = errorString("unknown password algorithm")
	ErrUsernameTooLong          = errorString("username too long")
	ErrRealmTooLong             = errorString("realm too long")
	ErrMissingUsername          = errorString("missing username")
	ErrMissingRealm             = errorString("missing realm")
)

type Message []byte

func (m Message) Type() Type     { return Type(binary.BigEndian.Uint16(m[:2])) }
func (m Message) AttrSize() int  { return int(binary.BigEndian.Uint16(m[2:4])) }
func (m Message) TxID() (t TxID) { copy(t[:], m[8:]); return }

func attrType(a []byte) attr { return attr(binary.BigEndian.Uint16(a[:2])) }
func attrSize(a []byte) int  { return int(uint(binary.BigEndian.Uint16(a[2:4]))) }

var key = []byte{31: 0}

func Parse(in []byte) (Message, error) {

	if len(in) < headerSize {
		return nil, ErrNotASTUNMessage
	}
	// Top two bits must be 0
	if in[0] > 0x3F {
		return nil, ErrNotASTUNMessage
	}
	// Magic Cookie
	if binary.BigEndian.Uint32(in[4:8]) != magicCookie {
		return nil, ErrNotASTUNMessage
	}
	// Size (and should be multiple of 4)
	if s := int(binary.BigEndian.Uint16(in[2:4])); s+headerSize != len(in) || s%4 != 0 {
		return nil, ErrNotASTUNMessage
	}
	n := headerSize // number of bytes parsed
	for attr := in[headerSize:]; len(attr) > 4; attr = in[n:] {
		s := attrSize(attr)
		switch attrType(attr) {

		case attrUsername:
		case attrRealm:
		case attrPasswordAlgorithms:

		case attrFingerprint:
			// fingerprint must be the last attribute, len(attr) != attrFingerpintSize provides that condition
			if s != 4 || len(attr) != fingerprintSize || !validateFingerprint(in[:n], attr[4:8]) {
				return nil, ErrFingerprint
			}

		case attrMessageIntegrity:
			if s != sha1.Size || len(attr) < 4+sha1.Size {
				return nil, ErrMessageIntegrity
			}
			attr = attr[4:]
			if len(attr) > sha1.Size {
				// Only fingerprint and messageintegritySHA256 attributes are allowed to follow messageintegrity attribute
				a := attr[sha1.Size:]
				if len(a) < fingerprintSize {
					return nil, ErrMessageIntegrity
				}
				switch attrType(a) {
				case attrFingerprint:
					// ignore everything after messageintegrity and fingerprint attributes
					in = in[:n+4+sha1.Size+fingerprintSize]
				case attrMessageIntegritySHA256:
					nn := 4 + attrSize(a)
					if len(a) < nn {
						return nil, ErrMessageIntegrity
					}
					if a = a[nn:]; len(a) < fingerprintSize || attrType(a) != attrFingerprint {
						return nil, ErrMessageIntegrity
					}
					in = in[:n+nn+fingerprintSize]
				default:
					return nil, ErrMessageIntegrity
				}
				attr = attr[:sha1.Size]
			}
			if !validateHMAC(in[:n], attr, sha1.New, key) {
				return nil, ErrMessageIntegrity
			}

		case attrMessageIntegritySHA256:
			// The value will be at most 32 bytes, but it MUST be at least 16 bytes and MUST be a multiple of 4 bytes.
			if s > sha256.Size || s < 16 || s%4 != 0 {
				return nil, ErrMessageIntegritySHA256
			}
			attr = attr[4:]
			if s > len(attr) {
				return nil, ErrMessageIntegritySHA256
			}
			if s < len(attr) {
				// Only fingerprint attribute is allowed to follow messageintegritysha256 attribute
				if a := attr[s:]; len(a) < fingerprintSize || attrType(a) != attrFingerprint {
					return nil, ErrMessageIntegritySHA256
				}
				// ignore everything after messageintegritysha256 and fingerprint attributes
				in = in[:n+4+s+fingerprintSize]
				attr = attr[:s]
			}
			if !validateHMAC(in[:n], attr, sha256.New, key) {
				return nil, ErrMessageIntegritySHA256
			}
		}
		s += 7 // 2 byte attr, 2 byte length, 3 for padding round up
		n += s - (s % 4)
	}
	//
	return Message(in), nil
}

// validateFingerprint is called when fingerprint attribute is encountered.
// m slice spans the STUN message header plus all currently parsed attributes
// a slice spans the fingerprint attribute
func validateFingerprint(m []byte, a []byte) bool {
	// fingerprint attribute is always last so header size is correct
	return crc32.ChecksumIEEE(m)^binary.BigEndian.Uint32(a) == fingerprintXor
}

// validateHMAC is called when either MessageInterity or MessageIntegritySHA256 attribute is encountered.
// m slice spans the STUN message header plus all currently parsed attributes
// a slice spans the MessageIntegrity/SHA256 attribute
func validateHMAC(m []byte, a []byte, h func() hash.Hash, key []byte) bool {
	var b [sha256.Size]byte

	n := len(a)
	binary.BigEndian.PutUint16(b[:2], uint16(len(m)-headerSize+4+n))
	mac := hmac.New(h, key)
	mac.Write(m[:2]) // STUN message type
	mac.Write(b[:2]) // patched STUN header attr length
	mac.Write(m[4:]) // rest of STUN message
	x := mac.Sum(b[:0])
	return hmac.Equal(a, x[:n])
}

func setAttrSize(m []byte) {
	binary.BigEndian.PutUint16(m[2:4], uint16(len(m)-headerSize))
}
