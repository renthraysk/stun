package stun

import (
	"crypto/sha1"
	"crypto/sha256"
	"encoding/binary"
)

func attributeType(a []byte) attr { return attr(binary.BigEndian.Uint16(a[:2])) }
func attributeSize(a []byte) int  { return int(uint(binary.BigEndian.Uint16(a[2:4]))) }

var key = []byte{31: 0}

func (m *Message) Unmarshal(in []byte) error {

	if len(in) < headerSize {
		return ErrNotASTUNMessage
	}
	// Top two bits must be 0
	if in[0] > 0x3F {
		return ErrNotASTUNMessage
	}
	// Magic Cookie
	if binary.BigEndian.Uint32(in[4:8]) != magicCookie {
		return ErrNotASTUNMessage
	}
	// Size (and should be multiple of 4)
	if s := int(binary.BigEndian.Uint16(in[2:4])); s+headerSize != len(in) || s%4 != 0 {
		return ErrNotASTUNMessage
	}

	bytesParsed := headerSize
	for attrs := in[headerSize:]; len(attrs) > 4; attrs = in[bytesParsed:] {
		attrType, attrSize := attributeType(attrs), attributeSize(attrs)
		attrValue := attrs[4:]
		if len(attrValue) < attrSize {
			return ErrUnexpectedEOF
		}
		switch attrType {

		case attrFingerprint:
			if attrSize != 4 {
				return ErrFingerprint
			}
			// fingerprint must be the last attribute, len(attrValue) > 4 provides that condition
			if len(attrValue) > 4 {
				return ErrInvalidAttributeSequence
			}
			if !validateFingerprint(in[:bytesParsed], attrValue[:4]) {
				return ErrFingerprint
			}

		case attrMessageIntegrity:
			if attrSize != sha1.Size {
				return ErrMessageIntegrity
			}
			if len(attrValue) > sha1.Size {
				// Only fingerprint and messageintegritySHA256 attributes are allowed to follow messageintegrity attribute
				a := attrValue[sha1.Size:]
				if len(a) < fingerprintSize {
					return ErrUnexpectedEOF
				}
				switch attributeType(a) {
				case attrFingerprint:
					// ignore everything after messageintegrity and fingerprint attributes
					in = in[:bytesParsed+4+sha1.Size+fingerprintSize]
				case attrMessageIntegritySHA256:
					n := 4 + attributeSize(a)
					if len(a) < n {
						return ErrUnexpectedEOF
					}
					if a = a[n:]; len(a) > 0 {
						if len(a) < fingerprintSize {
							return ErrUnexpectedEOF
						}
						if attributeType(a) != attrFingerprint {
							return ErrInvalidAttributeSequence
						}
						n += fingerprintSize
					}
					// ignore everything after messageintegritysha256 and fingerprint attributes
					in = in[:bytesParsed+4+sha1.Size+n]
				default:
					return ErrInvalidAttributeSequence
				}
				attrValue = attrValue[:sha1.Size]
			}
			if !validateHMAC(in[:bytesParsed], attrValue, sha1.New, key) {
				return ErrMessageIntegrity
			}

		case attrMessageIntegritySHA256:
			// The value will be at most 32 bytes, but it MUST be at least 16 bytes and MUST be a multiple of 4 bytes.
			if attrSize > sha256.Size || attrSize < 16 || attrSize%4 != 0 {
				return ErrMessageIntegritySHA256
			}
			if len(attrValue) > attrSize {
				// Only fingerprint attribute is allowed to follow messageintegritysha256 attribute
				if a := attrValue[attrSize:]; len(a) < fingerprintSize || attributeType(a) != attrFingerprint {
					return ErrInvalidAttributeSequence
				}
				// ignore everything after messageintegritysha256 and fingerprint attributes
				in = in[:bytesParsed+4+attrSize+fingerprintSize]
				attrValue = attrValue[:attrSize]
			}
			if !validateHMAC(in[:bytesParsed], attrValue, sha256.New, key) {
				return ErrMessageIntegritySHA256
			}
		}
		attrSize += 7 // 2 byte attr, 2 byte length, 3 for padding round up
		bytesParsed += attrSize - (attrSize % 4)
	}

	m.typ = Type(binary.BigEndian.Uint16(in[:2]))
	copy(m.txID[:], in[8:])

	return nil
}
