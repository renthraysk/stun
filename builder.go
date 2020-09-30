package stun

import (
	"crypto/sha256"
	"encoding/binary"
	"net"
)

const (
	maxUsernameByteLength = 513
	maxRealmByteLength    = 763
)

// @TODO Enforce attributes to each STUN message class they belong
// @TODO Check for duplicate attributes appended?

type Builder struct {
	err                          error
	msg                          []byte
	key                          []byte
	messageIntegritySHA256Length int
	messageIntegrity             bool
	fingerprint                  bool
}

func New(t Type, txID TxID) *Builder {
	return &Builder{msg: newHeader(make([]byte, 0, 512), t, txID)}
}

// See https://tools.ietf.org/html/rfc8489#section-14.1
func (b *Builder) SetMappingAddress(addr *net.UDPAddr) {
	if b.err != nil {
		return
	}
	if len(addr.IP) != net.IPv4len && len(addr.IP) != net.IPv6len {
		b.err = ErrInvalidIPAddress
		return
	}
	b.msg = appendMappedAddress(b.msg, addr.IP, uint16(addr.Port))
}

// https://tools.ietf.org/html/rfc8489#section-14.2
func (b *Builder) SetXorMappingAddress(addr *net.UDPAddr) {
	if b.err != nil {
		return
	}
	if len(addr.IP) != net.IPv4len && len(addr.IP) != net.IPv6len {
		b.err = ErrInvalidIPAddress
		return
	}
	b.msg = appendXorMappedAddress(b.msg, addr.IP, uint16(addr.Port))
}

// See https://tools.ietf.org/html/rfc8489#section-14.3
func (b *Builder) SetUsername(username string) {
	if b.err != nil {
		return
	}
	if len(username) > maxUsernameByteLength {
		b.err = ErrUsernameTooLong
		return
	}
	b.msg = appendUsername(b.msg, username)
}

// See https://tools.ietf.org/html/rfc8489#section-14.4
func (b *Builder) SetUserHash(username, realm string) {
	if b.err != nil {
		return
	}
	if len(username) > maxUsernameByteLength {
		b.err = ErrUsernameTooLong
		return
	}
	if len(realm) > maxRealmByteLength {
		b.err = ErrRealmTooLong
		return
	}
	b.msg = appendUserHash(b.msg, username, realm)
}

// See https://tools.ietf.org/html/rfc8489#section-14.5
func (b *Builder) AddMessageIntegrity() {
	b.messageIntegrity = true
}

// AddMessageIntegritySHA256 ensures a messageintegritysha256 attribute is added when message is built.
// See https://tools.ietf.org/html/rfc8489#section-14.6
func (b *Builder) AddMessageIntegritySHA256() {
	b.AddMessageIntegritySHA256Truncated(sha256.Size)
}

// AddMessageIntegritySHA256 ensures a messageintegritysha256 attribute is added when message is built.
// The length allows for a truncated messageintegritysha256 value to be used, must be > 16 and divisible by 4.
func (b *Builder) AddMessageIntegritySHA256Truncated(length int) {
	if b.err != nil {
		return
	}
	if length > sha256.Size || length < 16 || length%4 != 0 {
		b.err = ErrInvalidMessageIntegritySHA256Length
		return
	}
	b.messageIntegritySHA256Length = length
}

// AddFingerprint ensures a fingerprint attribute is added as the last attribute when message is built.
// See https://tools.ietf.org/html/rfc8489#section-14.7
func (b *Builder) AddFingerprint() {
	b.fingerprint = true
}

// See https://tools.ietf.org/html/rfc8489#section-14.8
func (b *Builder) SetErrorCode(errorCode ErrorCode, reason string) {
	const maxReasonByteLength = 763

	if b.err != nil {
		return
	}
	if errorCode < 300 || errorCode > 699 {
		b.err = ErrInvalidErrorCode
		return
	}
	if len(reason) > maxReasonByteLength {
		b.err = ErrReasonTooLong
		return
	}
	b.msg = appendErrorCode(b.msg, errorCode, reason)
}

// See https://tools.ietf.org/html/rfc8489#section-14.9
func (b *Builder) SetRealm(realm string) {
	if b.err != nil {
		return
	}
	if len(realm) > maxRealmByteLength {
		b.err = ErrRealmTooLong
		return
	}
	b.msg = appendRealm(b.msg, realm)
}

// See https://tools.ietf.org/html/rfc8489#section-14.10
func (b *Builder) SetNonce(nonce []byte) {
	const maxNonceByteLength = 763

	if b.err != nil {
		return
	}
	if len(nonce) > maxNonceByteLength {
		b.err = ErrNonceTooLong
		return
	}
	b.msg = appendNonce(b.msg, nonce)
}

// See https://tools.ietf.org/html/rfc8489#section-14.10
// & https://tools.ietf.org/html/rfc8489#section-9.2.1
func (b *Builder) SetNonceWithSecurityFeatures(features Features, nonce []byte) {
	const maxNonceByteLength = 763

	if b.err != nil {
		return
	}
	if len(nonce) > maxNonceByteLength-len(nonceSecurityFeaturesPrefix)-4 {
		b.err = ErrNonceTooLong
		return
	}
	b.msg = appendNonceWithSecurityFeatures(b.msg, features, nonce)
}

// See https://tools.ietf.org/html/rfc8489#section-14.11
func (b *Builder) SetPasswordAlgorithms() {
	// @TODO
}

// SetUnknownAttributes
// Adds an Error Code attribute of ErrorCodeUnknownAttribute and with the given reason
// See https://tools.ietf.org/html/rfc8489#section-14.13
func (b *Builder) SetUnknownAttributes(reason string, attributes ...uint16) {
	if b.err != nil {
		return
	}
	b.msg = appendErrorCode(b.msg, ErrorCodeUnknownAttribute, reason)
	b.msg = appendUnknownAttributes(b.msg, attributes)
}

// SetSoftware appends Software attribute to the STUN message
// See https://tools.ietf.org/html/rfc8489#section-14.14
func (b *Builder) SetSoftware(software string) {
	const maxSoftwareByteLength = 763

	if b.err != nil {
		return
	}
	if len(software) > maxSoftwareByteLength {
		b.err = ErrSoftwareTooLong
		return
	}
	b.msg = appendSoftware(b.msg, software)
}

// See https://tools.ietf.org/html/rfc8489#section-14.15
func (b *Builder) SetAlternateServer(ip net.IP, port uint16) {
	if b.err != nil {
		return
	}
	if len(ip) != net.IPv4len && len(ip) != net.IPv6len {
		b.err = ErrInvalidIPAddress
		return
	}
	b.msg = appendAlternateServer(b.msg, ip, port)
}

// See https://tools.ietf.org/html/rfc8489#section-14.16
func (b *Builder) SetAlternateDomain(domain string) {
	const maxAlternateDomainByteLength = 255

	if b.err != nil {
		return
	}
	if len(domain) > maxAlternateDomainByteLength {
		b.err = ErrDomainTooLong
		return
	}
	b.msg = appendAlternateDomain(b.msg, domain)
}

func (b *Builder) SetPriority(typePref uint8, localPref uint16, componentID uint8) {
	if b.err != nil {
		return
	}
	if componentID < 1 {
		b.err = ErrInvalidPriorityComponentID
		return
	}
	b.msg = appendPriority(b.msg, typePref, localPref, componentID)
}

func (b *Builder) SetICEControlled(iceControlled uint64) {
	if b.err != nil {
		return
	}
	b.msg = appendICEControlled(b.msg, iceControlled)
}

// SetKey sets the short term key used in computing the MessageIntegrity and MessageIntegritySHA256 attributes
func (b *Builder) SetPassword(password string) {
	if b.err != nil {
		return
	}
	if len(b.key) > 0 {
		b.err = ErrKeySet
		return
	}
	b.key = append(b.key[:0], password...)
}

// SetKeyLongTerm sets the long term key used in computing the MessageIntegrity and MessageIntegritySHA256 attributes
// Will automatically add PASSWORD-ALGORITHM attribute if passwordAlgorithm is anything other than PasswordAlgorithmMD5
func (b *Builder) SetKeyLongTerm(passwordAlgorithm PasswordAlgorithm, username, realm, password string) {
	if b.err != nil {
		return
	}
	if len(b.key) > 0 {
		b.err = ErrKeySet
		return
	}
	switch passwordAlgorithm {
	case PasswordAlgorithmMD5:
		b.key = appendLongTermKeyMD5String(b.key[:0], username, realm, password)
	case PasswordAlgorithmSHA256:
		b.msg = appendPasswordAlgorithm(b.msg, PasswordAlgorithmSHA256, nil)
		b.key = appendLongTermKeySHA256String(b.key[:0], username, realm, password)
	default:
		b.err = ErrUnknownPasswordAlgorithm
	}
}

// Build return the raw STUN message or an error if one occurred during it's building.
func (b *Builder) Build() ([]byte, error) {
	if b.err != nil {
		return nil, b.err
	}
	m := b.msg
	if b.messageIntegrity || b.messageIntegritySHA256Length > 0 {
		if len(b.key) == 0 {
			return nil, ErrMissingMessageIntegrityKey
		}
		if b.messageIntegrity {
			m = appendMessageIntegrity(m, b.key)
		}
		if b.messageIntegritySHA256Length > 0 {
			m = appendMessageIntegritySHA256(m, b.key, b.messageIntegritySHA256Length)
		}
	} else if len(b.key) > 0 {
		// SetPassword() or SetLongTermKey() was called but neither MessageIntegrity or MessageIntegritySHA256 used.
		return nil, ErrKeyNotUsed
	}
	if b.fingerprint {
		m = appendFingerprint(m)
	}
	binary.BigEndian.PutUint16(m[2:4], uint16(len(m)-headerSize))
	return m, nil
}
