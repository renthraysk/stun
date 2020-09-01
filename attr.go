package stun

import (
	"crypto/sha256"
)

/*
	Low level attribute appenders.
	These do not apply any validation to inputs, so can be used to generate malformed messages for testing Parse().
*/

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
	attrPasswordAlgorithm      attr = 0x001D
	attrUserHash               attr = 0x001E
	attrXorMappedAddress       attr = 0x0020
	attrReservationToken       attr = 0x0022
	attrPriority               attr = 0x0024
	attrUseCandidate           attr = 0x0025
	attrPadding                attr = 0x0026
	attrResponsePort           attr = 0x0027
	attrConnectionID           attr = 0x002A

	attrPasswordAlgorithms attr = 0x8002
	attrAlternateDomain    attr = 0x8003
	attrSoftware           attr = 0x8022
	attrAlternateServer    attr = 0x8023
	attrFingerprint        attr = 0x8028
	attrICEControlled      attr = 0x8029
	attrICEControlling     attr = 0x802A
)

type PasswordAlgorithm uint16

const (
	PasswordAlgorithmMD5    PasswordAlgorithm = 0x0001
	PasswordAlgorithmSHA256 PasswordAlgorithm = 0x0002
)

var zeroPad [4]byte

func newHeader(buf []byte, t Type, txID [12]byte) []byte {
	m := append(buf[:0], byte(t>>8), byte(t), 0, 0, byte(magicCookie>>24), byte(magicCookie>>16&0xFF), byte(magicCookie>>8&0xFF), byte(magicCookie&0xFF))
	return append(m, txID[:]...)
}

func appendAttribute(m []byte, a attr, b []byte) []byte {
	n := len(b)
	m = append(m, byte(a>>8), byte(a), byte(n>>8), byte(n))
	m = append(m, b...)
	if i := n % 4; i != 0 {
		m = append(m, zeroPad[i:4]...)
	}
	return m
}

func appendAttributeString(m []byte, a attr, s string) []byte {
	n := len(s)
	m = append(m, byte(a>>8), byte(a), byte(n>>8), byte(n))
	m = append(m, s...)
	if i := n % 4; i != 0 {
		m = append(m, zeroPad[i:4]...)
	}
	return m
}

func appendAttributeUint32(m []byte, a attr, x uint32) []byte {
	return append(m, byte(a>>8), byte(a), 0, 4, byte(x>>24), byte(x>>16), byte(x>>8), byte(x))
}

func appendAttributeUint64(m []byte, a attr, x uint64) []byte {
	return append(m, byte(a>>8), byte(a), 0, 8, byte(x>>56), byte(x>>48), byte(x>>40), byte(x>>32), byte(x>>24), byte(x>>16), byte(x>>8), byte(x))
}

func appendUsername(m []byte, username string) []byte {
	return appendAttributeString(m, attrUsername, username)
}

func appendSoftware(m []byte, s string) []byte {
	return appendAttributeString(m, attrSoftware, s)
}

func appendRealm(m []byte, r string) []byte {
	return appendAttributeString(m, attrRealm, r)
}

func appendNonce(m []byte, nonce []byte) []byte {
	return appendAttribute(m, attrNonce, nonce)
}

type Features uint32

const (
	FeaturePasswordAlgorithms Features = 1 << 0
	FeatureUserAnonyminity    Features = 1 << 1
)

func appendNonceWithSecurityFeatures(m []byte, features Features, nonce []byte) []byte {

	const b64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"

	n := len(nonce) + len(nonceSecurityFeaturesPrefix) + 4
	m = append(m, byte(attrNonce>>8), byte(attrNonce), byte(n>>8), byte(n))
	m = append(m, nonceSecurityFeaturesPrefix...)

	x := features
	m = append(m, b64[(x>>18)%64], b64[(x>>12)%64], b64[(x>>6)%64], b64[x%64])
	m = append(m, nonce...)

	if i := n % 4; i != 0 {
		return append(m, zeroPad[i:4]...)
	}
	return m
}

func appendUserHash(m []byte, userhash [sha256.Size]byte) []byte {
	return appendAttribute(m, attrUserHash, userhash[:])
}

//go:generate stringer -type ErrorCode -trimprefix ErrorCode

type ErrorCode uint16

const (
	ErrorCodeTryAlternate     ErrorCode = 300
	ErrorCodeBadRequest       ErrorCode = 400
	ErrorCodeUnauthenticated  ErrorCode = 401
	ErrorCodeUnknownAttribute ErrorCode = 420
	ErrorCodeStaleNonce       ErrorCode = 438
	ErrorCodeServerErrorRetry ErrorCode = 500
)

func appendErrorCode(m []byte, errorCode ErrorCode, reason string) []byte {
	n := 4 + len(reason)
	m = append(m, byte(attrErrorCode>>8), byte(attrErrorCode), byte(n>>8), byte(n),
		0, 0, byte(errorCode>>8), byte(errorCode))
	m = append(m, reason...)
	if i := n % 4; i != 0 {
		m = append(m, zeroPad[i:4]...)
	}
	return m
}

func appendPasswordAlgorithm(m []byte, passwordAlgorithm PasswordAlgorithm, parameters []byte) []byte {
	p := len(parameters)
	n := 4 + p
	m = append(m, byte(attrPasswordAlgorithm>>8), byte(attrPasswordAlgorithm), byte(n>>8), byte(n),
		byte(passwordAlgorithm>>8), byte(passwordAlgorithm), byte(p>>8), byte(p))
	m = append(m, parameters...)
	if i := n % 4; i != 0 {
		m = append(m, zeroPad[i:4]...)
	}
	return m
}

func appendUnknownAttributes(m []byte, attributes []uint16) []byte {
	n := len(attributes) * 2
	m = append(m, byte(attrUnknownAttributes>>8), byte(attrUnknownAttributes), byte(n>>8), byte(n))
	for _, a := range attributes {
		m = append(m, byte(a>>8), byte(a))
	}
	if i := n % 4; i != 0 {
		m = append(m, zeroPad[i:4]...)
	}
	return m
}

func appendAlternateDomain(m []byte, domain string) []byte {
	return appendAttributeString(m, attrAlternateDomain, domain)
}

func appendPriority(m []byte, typePref uint8, localPref uint16, componentID uint8) []byte {
	return appendAttributeUint32(m, attrPriority, uint32(typePref)<<24|uint32(localPref)<<8|(256-uint32(componentID)))
}

func appendICEControlled(m []byte, iceControlled uint64) []byte {
	return appendAttributeUint64(m, attrICEControlled, iceControlled)
}

//
