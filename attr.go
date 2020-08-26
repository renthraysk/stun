package stun

import (
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/binary"
	"hash"
	"hash/crc32"
)

type attr uint16

const (
	attrMappedAddress          attr = 0x0001
	attrUsername               attr = 0x0006
	attrMessageIntegrity       attr = 0x0008
	attrErrorCode              attr = 0x0009
	attrUnknownAttributes      attr = 0x000A
	attrChannelNumber          attr = 0x000C
	attrLifeTime               attr = 0x000D
	attrXorPeerAddress         attr = 0x0012
	attrData                   attr = 0x0013
	attrRealm                  attr = 0x0014
	attrNonce                  attr = 0x0015
	attrXorRelayedAddress      attr = 0x0016
	attrRequestedAddressFamily attr = 0x0017
	attrMessageIntegritySHA256 attr = 0x001C
	attrUserHash               attr = 0x001E
	attrXorMappedAddress       attr = 0x0020
	attrReservationToken       attr = 0x0022
	attrPriority               attr = 0x0024
	attrUseCandidate           attr = 0x0025
	attrPadding                attr = 0x0026
	attrResponsePort           attr = 0x0027
	attrConnectionID           attr = 0x002A

	attrPasswordAlgorithms attr = 0x8002
	attrSoftware           attr = 0x8022
	attrFingerprint        attr = 0x8028
)

type passwordAlgorithm uint16

const (
	passwordAlgorithmMD5    passwordAlgorithm = 0x0001
	passwordAlgorithmSHA256 passwordAlgorithm = 0x0002
)

const (
	fingerprintSize        = 8
	fingerprintXor  uint32 = 0x5354554e
)

var (
	zeroPad = [sha256.Size]byte{}
	colon   = [1]byte{':'}
)

func newHeader(buf []byte, t Type, txID [12]byte) []byte {
	m := append(buf[:0], byte(t>>8), byte(t), 0, 0, byte(magicCookie>>24), byte(magicCookie>>16&0xFF), byte(magicCookie>>8&0xFF), byte(magicCookie&0xFF))
	return append(m, txID[:]...)
}

func appendAttribute(m []byte, a attr, b []byte) []byte {
	n := len(b)
	m = append(m, byte(a>>8), byte(a), byte(n>>8), byte(n))
	m = append(m, b...)
	if i := n & 3; i != 0 {
		m = append(m, zeroPad[i:4]...)
	}
	return m
}

func appendAttributeString(m []byte, a attr, s string) []byte {
	n := len(s)
	m = append(m, byte(a>>8), byte(a), byte(n>>8), byte(n))
	m = append(m, s...)
	if i := n & 3; i != 0 {
		m = append(m, zeroPad[i:4]...)
	}
	return m
}

func appendAttributeUint32(m []byte, a attr, x uint32) []byte {
	return append(m, byte(a>>8), byte(a), 0, 4, byte(x>>24), byte(x>>16), byte(x>>8), byte(x))
}

func appendSoftware(m []byte, s string) []byte {
	return appendAttributeString(m, attrSoftware, s)
}

func appendFingerprint(m []byte) []byte {
	binary.BigEndian.PutUint16(m[2:4], uint16(len(m)-headerSize+fingerprintSize))
	return appendAttributeUint32(m, attrFingerprint, crc32.ChecksumIEEE(m)^fingerprintXor)
}

func appendRealm(m []byte, r string) []byte {
	return appendAttributeString(m, attrRealm, r)
}

func appendNonce(m []byte, nonce []byte) []byte {
	return appendAttribute(m, attrNonce, nonce)
}

func appendUserHash(m []byte, userhash []byte) []byte {
	return appendAttribute(m, attrUserHash, userhash)
}

func appendHMAC(m []byte, a attr, h func() hash.Hash, key []byte, n int) []byte {
	mac := hmac.New(h, key)
	binary.BigEndian.PutUint16(m[2:4], uint16(len(m)-headerSize+4+n))
	mac.Write(m)
	m = append(m, byte(a>>8), byte(a), byte(n>>8), byte(n))
	if n == mac.Size() {
		return mac.Sum(m)
	}
	x := mac.Sum(nil)
	return append(m, x[:n]...)
}

func appendMessageIntegrity(m []byte, key []byte) []byte {
	return appendHMAC(m, attrMessageIntegrity, sha1.New, key, sha1.Size)
}

func appendMessageIntegritySHA256(m []byte, key []byte, n int) []byte {
	return appendHMAC(m, attrMessageIntegritySHA256, sha256.New, key, n)
}
