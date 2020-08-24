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

//go:generate stringer -type attr -trimprefix attr

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

const (
	passwordAlgorithmMD5    = 0x0001
	passwordAlgorithmSHA256 = 0x0002
)

const (
	fingerPrintXor uint32 = 0x5354554e
)

var (
	zeroPad = [sha256.Size]byte{}
	colon   = [1]byte{':'}
)

func newHeader(buf []byte, t Type, txID [12]byte) Message {
	m := append(buf[:0], byte(t>>8), byte(t), 0, 0, byte(magicCookie>>24), byte(magicCookie>>16&0xFF), byte(magicCookie>>8&0xFF), byte(magicCookie&0xFF))
	return append(m, txID[:]...)
}

func appendAttribute(m Message, a attr, b []byte) Message {
	n := len(b)
	m = append(m, byte(a>>8), byte(a), byte(n>>8), byte(n))
	m = append(m, b...)
	if i := n & 3; i != 0 {
		return append(m, zeroPad[i:4]...)
	}
	return m
}

func appendAttributeString(m Message, a attr, s string) Message {
	n := len(s)
	m = append(m, byte(a>>8), byte(a), byte(n>>8), byte(n))
	m = append(m, s...)
	if i := n & 3; i != 0 {
		m = append(m, zeroPad[i:4]...)
	}
	m.setAttrSize()
	return m
}

func appendAttributeUint32(m Message, a attr, x uint32) Message {
	m = append(m, byte(a>>8), byte(a), 0, 4, byte(x>>24), byte(x>>16), byte(x>>8), byte(x))
	m.setAttrSize()
	return m
}

func appendSoftware(m Message, s string) Message {
	return appendAttributeString(m, attrSoftware, s)
}

func appendFingerprint(m Message) Message {
	m = appendAttributeUint32(m, attrFingerprint, 0)
	binary.BigEndian.PutUint32(m[len(m)-4:], crc32.ChecksumIEEE(m)^fingerPrintXor)
	return m
}

func appendRealm(m Message, r string) Message {
	return appendAttributeString(m, attrRealm, r)
}

func appendNonce(m Message, nonce []byte) Message {
	return appendAttribute(m, attrNonce, nonce)
}

func appendHMAC(m Message, a attr, h func() hash.Hash, key []byte) Message {
	mac := hmac.New(h, key)
	n := mac.Size()
	m = append(m, byte(a>>8), byte(a), byte(n>>8), byte(n))
	m = append(m, zeroPad[:n]...)
	m.setAttrSize()
	mac.Write(m)
	return mac.Sum(m[:len(m)-n])
}

func appendMessageIntegrity(m, key []byte) []byte {
	return appendHMAC(m, attrMessageIntegrity, sha1.New, key)
}

func appendMessageIntegritySHA256(m, key []byte) []byte {
	return appendHMAC(m, attrMessageIntegritySHA256, sha256.New, key)
}
