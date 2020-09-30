package stun

import (
	"crypto/hmac"
	"crypto/md5"
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
func validateFingerprint(m []byte, crc uint32) bool {
	// fingerprint attribute is always last so header size is correct
	return crc32.ChecksumIEEE(m)^crc == fingerprintXor
}

func appendLongTermKey(b []byte, h hash.Hash, username, realm, password []byte) []byte {
	keyMaterial := make([]byte, len(username)+1+len(realm)+1+len(password))
	i := copy(keyMaterial, username)
	keyMaterial[i] = ':'
	i++
	i += copy(keyMaterial[i:], realm)
	keyMaterial[i] = ':'
	i++
	copy(keyMaterial[i:], password)
	h.Write(keyMaterial)
	return h.Sum(b)
}

func appendLongTermKeyString(b []byte, h hash.Hash, username, realm, password string) []byte {
	keyMaterial := make([]byte, len(username)+1+len(realm)+1+len(password))
	i := copy(keyMaterial, username)
	keyMaterial[i] = ':'
	i++
	i += copy(keyMaterial[i:], realm)
	keyMaterial[i] = ':'
	i++
	copy(keyMaterial[i:], password)
	h.Write(keyMaterial)
	return h.Sum(b)
}

func appendLongTermKeyMD5(b, username, realm, password []byte) []byte {
	return appendLongTermKey(b, md5.New(), username, realm, password)
}

func appendLongTermKeyMD5String(b []byte, username, realm, password string) []byte {
	return appendLongTermKeyString(b, md5.New(), username, realm, password)
}

func appendMessageIntegrity(m []byte, key []byte) []byte {
	binary.BigEndian.PutUint16(m[2:4], uint16(len(m)-headerSize+4+sha1.Size))
	mac := hmac.New(sha1.New, key)
	mac.Write(m)
	m = append(m, byte(attrMessageIntegrity>>8), byte(attrMessageIntegrity), byte(sha1.Size>>8), byte(sha1.Size))
	return mac.Sum(m)
}

// validateHMACSHA1 is called when MessageIntegritySHA256 attribute is encountered.
// message slice spans the STUN message header plus all currently parsed attributes
// attrValue slice spans the MessageIntegritySHA256 attribute
func validateHMACSHA1(message, attrValue []byte, keygen keyGenerator) bool {
	var b [sha1.Size]byte

	key, err := keygen.Generate(b[:0])
	if err != nil {
		return false
	}
	binary.BigEndian.PutUint16(b[:2], uint16(len(message)-headerSize+4+sha1.Size))
	mac := hmac.New(sha1.New, key)
	mac.Write(message[:2]) // STUN message type
	mac.Write(b[:2])       // patched STUN header attr length
	mac.Write(message[4:]) // rest of STUN message until the MessageIntegrity attribute
	return hmac.Equal(attrValue, mac.Sum(b[:0]))
}

// SHA256

func appendLongTermKeySHA256(b, username, realm, password []byte) []byte {
	return appendLongTermKey(b, sha256.New(), username, realm, password)
}

func appendLongTermKeySHA256String(b []byte, username, realm, password string) []byte {
	return appendLongTermKeyString(b, sha256.New(), username, realm, password)
}

func appendMessageIntegritySHA256(m []byte, key []byte, length int) []byte {
	binary.BigEndian.PutUint16(m[2:4], uint16(len(m)-headerSize+4+length))
	mac := hmac.New(sha256.New, key)
	mac.Write(m)
	m = append(m, byte(attrMessageIntegritySHA256>>8), byte(attrMessageIntegritySHA256), byte(length>>8), byte(length))
	m = mac.Sum(m)
	return m[:len(m)-sha256.Size+length]
}

// validateHMACSHA256 is called when MessageIntegritySHA256 attribute is encountered.
// message slice spans the STUN message header plus all currently parsed attributes
// attrValue slice spans the MessageIntegritySHA256 attribute value
func validateHMACSHA256(message []byte, attrValue []byte, keygen keyGenerator) bool {
	var b [sha256.Size]byte

	length := len(attrValue)
	if length > sha256.Size || length < 16 || length%4 != 0 {
		return false
	}
	key, err := keygen.Generate(b[:0])
	if err != nil {
		return false
	}
	binary.BigEndian.PutUint16(b[:2], uint16(len(message)-headerSize+4+length))
	mac := hmac.New(sha256.New, key)
	mac.Write(message[:2]) // STUN message type
	mac.Write(b[:2])       // patched STUN header attr length
	mac.Write(message[4:]) // rest of STUN message until the MessageIntegritySHA256 attribute
	x := mac.Sum(b[:0])
	return hmac.Equal(attrValue, x[:length])
}
