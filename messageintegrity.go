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
	fingerprintSize        = 8
	fingerprintXor  uint32 = 0x5354554e
)

func appendFingerprint(m []byte) []byte {
	binary.BigEndian.PutUint16(m[2:4], uint16(len(m)-headerSize+fingerprintSize))
	return appendAttributeUint32(m, attrFingerprint, crc32.ChecksumIEEE(m)^fingerprintXor)
}

// validateFingerprint is called when fingerprint attribute is encountered.
// m slice spans the STUN message header plus all currently parsed attributes
// a slice spans the fingerprint attribute
func validateFingerprint(m []byte, a []byte) bool {
	// fingerprint attribute is always last so header size is correct
	return crc32.ChecksumIEEE(m)^binary.BigEndian.Uint32(a) == fingerprintXor
}

func appendHMAC(m []byte, a attr, h func() hash.Hash, key []byte) []byte {
	mac := hmac.New(h, key)
	n := mac.Size()
	binary.BigEndian.PutUint16(m[2:4], uint16(len(m)-headerSize+4+n))
	mac.Write(m)
	m = append(m, byte(a>>8), byte(a), byte(n>>8), byte(n))
	return mac.Sum(m)
}

// validateHMAC is called when either MessageIntegrity or MessageIntegritySHA256 attribute is encountered.
// m slice spans the STUN message header plus all currently parsed attributes
// a slice spans the MessageIntegrity/SHA256 attribute
func validateHMAC(m []byte, a []byte, h func() hash.Hash, key []byte) bool {
	var b [sha256.Size]byte

	mac := hmac.New(h, key)
	n := mac.Size()
	binary.BigEndian.PutUint16(b[:2], uint16(len(m)-headerSize+4+n))
	mac.Write(m[:2]) // STUN message type
	mac.Write(b[:2]) // patched STUN header attr length
	mac.Write(m[4:]) // rest of STUN message until the MessageIntegrity/SHA256 attribute
	return hmac.Equal(a, mac.Sum(b[:0]))
}

func appendMessageIntegrity(m []byte, key []byte) []byte {
	return appendHMAC(m, attrMessageIntegrity, sha1.New, key)
}

func appendMessageIntegritySHA256(m []byte, key []byte) []byte {
	return appendHMAC(m, attrMessageIntegritySHA256, sha256.New, key)
}
