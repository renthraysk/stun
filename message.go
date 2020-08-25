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
	ErrMalformedAttribute     = errorString("malformed attribute")
	ErrNotASTUNMessage        = errorString("not a stun message")
	ErrFingerprint            = errorString("fingerprint check failed")
	ErrMessageIntegrity       = errorString("messageintegrity check failed")
	ErrMessageIntegritySHA256 = errorString("messageintegritysha256 check failed")

	ErrUnknownPasswordAlgorithm = errorString("unknown password algorithm")
)

type Message []byte

func (m Message) Type() Type              { return Type(binary.BigEndian.Uint16(m[:2])) }
func (m Message) AttrSize() int           { return int(binary.BigEndian.Uint16(m[2:4])) }
func (m Message) setAttrSize()            { binary.BigEndian.PutUint16(m[2:4], uint16(len(m)-headerSize)) }
func (m Message) TxID() (t TxID)          { copy(t[:], m[8:]); return }
func (m Message) cookieTxID(n int) []byte { return m[4 : 4+n] }

func attrType(a []byte) attr { return attr(binary.BigEndian.Uint16(a[:2])) }
func attrSize(a []byte) int  { return int(uint(binary.BigEndian.Uint16(a[2:4]))) }

var key = []byte{31: 0}

func Parse(in []byte) (Message, error) {

	const attrFingerprintSize = 8

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
	// Size
	if int(binary.BigEndian.Uint16(in[2:4]))+headerSize != len(in) {
		return nil, ErrNotASTUNMessage
	}

	n := headerSize // number of bytes parsed
	for attr := in[headerSize:]; len(attr) > 4; attr = in[n:] {
		s := attrSize(attr)
		switch attrType(attr) {

		case attrUsername, attrRealm, attrNonce:

		case attrPasswordAlgorithms:
			if s != 4 || binary.BigEndian.Uint16(attr[6:8]) != 0 {
				return nil, ErrUnknownPasswordAlgorithm
			}
			switch binary.BigEndian.Uint16(attr[4:6]) {
			case passwordAlgorithmMD5:
			case passwordAlgorithmSHA256:
			default:
				return nil, ErrUnknownPasswordAlgorithm
			}

		case attrFingerprint:
			// len(attr) == attrFingerprintSize when last attribute which fingerprint attribute must be
			if s != 4 || len(attr) != attrFingerprintSize || !validateFingerprint(in[:n], attr[:attrFingerprintSize]) {
				return nil, ErrFingerprint
			}

		case attrMessageIntegrity:
			const attrMessageIntegritySize = 4 + sha1.Size

			if s != sha1.Size || len(attr) < attrMessageIntegritySize {
				return nil, ErrMessageIntegrity
			}
			if len(attr) > attrMessageIntegritySize {
				// Only fingerprint attribute is allowed to follow messageintegrity attribute
				if a := attr[4+sha1.Size:]; len(a) < attrFingerprintSize || attrType(a) != attrFingerprint {
					return nil, ErrMessageIntegrity
				}
				in = in[:n+attrMessageIntegritySize+attrFingerprintSize] // ignore everything after messageintegrity and fingerprint attributes
				attr = attr[:attrMessageIntegritySize]
			}
			if !validateHMAC(in[:n], attr, sha1.New, key) {
				return nil, ErrMessageIntegrity
			}

		case attrMessageIntegritySHA256:
			const attrMessageIntegritySHA256Size = 4 + sha256.Size

			if s != sha256.Size || len(attr) < attrMessageIntegritySHA256Size {
				return nil, ErrMessageIntegritySHA256
			}
			if len(attr) > attrMessageIntegritySHA256Size {
				// Only fingerprint attribute is allowed to follow messageintegritysha256 attribute
				if a := attr[attrMessageIntegritySHA256Size:]; len(a) < attrFingerprintSize || attrType(a) != attrFingerprint {
					return nil, ErrMessageIntegritySHA256
				}
				in = in[:n+attrMessageIntegritySHA256Size+attrFingerprintSize] // ignore everything after messageintegritysha256 and fingerprint attributes
				attr = attr[:attrMessageIntegritySHA256Size]
			}
			if !validateHMAC(in[:n], attr, sha256.New, key) {
				return nil, ErrMessageIntegritySHA256
			}
		}
		n += (s + 7) &^ 3
	}
	//
	return Message(in), nil
}

// validateFingerprint is called when fingerprint attribute is encountered.
// m slice spans the STUN message header plus all currently parsed attributes
// a slice spans the fingerprint attribute
func validateFingerprint(m []byte, a []byte) bool {
	// Allocation free method, and crc32.IEEETable being public is unpleasant.
	t := crc32.MakeTable(crc32.IEEE)
	x := crc32.Update(0, t, m)          // STUN message. Should be no need to patch length as fingerprint can only be the last attr.
	x = crc32.Update(x, t, a[:4])       // attribute & length
	x = crc32.Update(x, t, zeroPad[:4]) // dummy zero value
	return x^fingerPrintXor == binary.BigEndian.Uint32(a[4:8])
}

// validateHMAC is called when either MessageInterity or MessageIntegritySHA256 attribute is encountered.
// m slice spans the STUN message header plus all currently parsed attributes
// a slice spans the MessageIntegrity/SHA256 attribute
func validateHMAC(m []byte, a []byte, h func() hash.Hash, key []byte) bool {
	var b [sha256.Size]byte

	mac := hmac.New(h, key)
	n := mac.Size()
	binary.BigEndian.PutUint16(b[:2], uint16(len(m)-headerSize+4+n))
	mac.Write(m[:2])       // STUN message type
	mac.Write(b[:2])       // patched STUN header attr length
	mac.Write(m[4:])       // rest of STUN message
	mac.Write(a[:4])       // attribute & length
	mac.Write(zeroPad[:n]) // dummy zero value
	return hmac.Equal(a[4:4+n], mac.Sum(b[:0]))
}
