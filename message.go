package stun

import (
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/binary"
	"hash"
	"hash/crc32"
)

type Message []byte

func (m Message) Type() Type              { return Type(binary.BigEndian.Uint16(m[:2])) }
func (m Message) AttrSize() int           { return int(binary.BigEndian.Uint16(m[2:4])) }
func (m Message) SetAttrSize()            { binary.BigEndian.PutUint16(m[2:4], uint16(len(m)-headerSize)) }
func (m Message) TxID() (t TxID)          { copy(t[:], m[8:]); return }
func (m Message) cookieTxID(n int) []byte { return m[4 : 4+n] }

func attrType(a []byte) attr { return attr(binary.BigEndian.Uint16(a[:2])) }
func attrSize(a []byte) int  { return int(uint(binary.BigEndian.Uint16(a[2:4]))) }

var key = []byte{31: 0}

func Parse(in []byte) (Message, bool) {
	if len(in) < headerSize {
		return nil, false
	}
	// Top two bits must be 0
	if in[0] > 0x3F {
		return nil, false
	}
	// Magic Cookie
	if binary.BigEndian.Uint32(in[4:8]) != magicCookie {
		return nil, false
	}
	// Size
	if int(binary.BigEndian.Uint16(in[2:4]))+headerSize != len(in) {
		return nil, false
	}

	n := headerSize // number of bytes parsed
	for attr := in[headerSize:]; len(attr) > 4; attr = in[n:] {
		s := attrSize(attr)
		switch attrType(attr) {

		case attrUsername, attrRealm, attrNonce:

		case attrPasswordAlgorithms:
			if s != 4 || binary.BigEndian.Uint16(attr[6:8]) != 0 {
				return nil, false
			}
			switch binary.BigEndian.Uint16(attr[4:6]) {
			case 0x0000:
				return nil, false
			case passwordAlgorithmMD5:
			case passwordAlgorithmSHA256:
			default:
				return nil, false
			}

		case attrFingerprint:
			// len(attr) == 8 when last attribute
			if s != 4 || len(attr) != 8 || !validateFingerprint(in[:n], attr[:8]) {
				return nil, false
			}

		case attrMessageIntegrity:
			if s != sha1.Size || len(attr) < 4+sha1.Size {
				return nil, false
			}
			if len(attr) > 4+sha1.Size {
				if a := attr[4+sha1.Size:]; len(a) < 8 || attrType(a) != attrFingerprint || attrSize(a) != 4 {
					return nil, false
				}
				in = in[:n+4+sha1.Size+8] // ignore everything after mac+fingerprint
				attr = attr[:4+sha1.Size]
			}
			if !validateHMAC(in[:n], attr, sha1.New, key) {
				return nil, false
			}

		case attrMessageIntegritySHA256:
			if s != sha256.Size || len(attr) < 4+sha256.Size {
				return nil, false
			}
			if len(attr) > 4+sha256.Size {
				if a := attr[4+sha256.Size:]; len(a) < 8 || attrType(a) != attrFingerprint || attrSize(a) != 4 {
					return nil, false
				}
				in = in[:n+4+sha256.Size+8] // ignore everything after mac+fingerprint
				attr = attr[:4+sha256.Size]
			}
			if !validateHMAC(in[:n], attr, sha256.New, key) {
				return nil, false
			}
		}
		n += (s + 7) &^ 3
	}
	if n != len(in) {
		return nil, false
	}
	return Message(in), true
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
