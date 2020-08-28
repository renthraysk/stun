package stun

import (
	"crypto/md5"
	"crypto/sha256"
	"encoding/binary"
	"hash"
	"net"
)

const (
	maxUsernameByteLength = 513
	maxRealmByteLength    = 763
)

// @TODO Enforce attributes to each STUN message class they belong
// @TODO Check for duplicate attributes appended?

type Builder struct {
	err              error
	msg              []byte
	messageIntegrity struct {
		key []byte
	}
	messageIntegritySHA256 struct {
		key []byte
	}
	addFingerprint bool
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
	var buf [64]byte
	if len(username) > maxUsernameByteLength {
		b.err = ErrUsernameTooLong
		return
	}
	if len(realm) > maxRealmByteLength {
		b.err = ErrRealmTooLong
		return
	}
	data := append(buf[:0], username...)
	data = append(data, ':')
	data = append(data, realm...)
	b.msg = appendUserHash(b.msg, sha256.Sum256(data))
}

// See https://tools.ietf.org/html/rfc8489#section-14.5
func (b *Builder) AddMessageIntegrity(key []byte) {
	if b.err != nil {
		return
	}
	b.messageIntegrity.key = append(b.messageIntegrity.key[:0], key...)
}

// AddLongTermMessageIntegrity
// Will automatically add a PasswordAlgorithm attribute if passwordAlgorithm is anything other than PasswordAlgorithmMD5
func (b *Builder) AddLongTermMessageIntegrity(passwordAlgorithm PasswordAlgorithm, username, realm, password string) {
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

	var h hash.Hash
	switch passwordAlgorithm {
	case PasswordAlgorithmMD5:
		h = md5.New()

	case PasswordAlgorithmSHA256:
		h = sha256.New()
		b.msg = appendPasswordAlgorithm(b.msg, PasswordAlgorithmSHA256, nil)

	default:
		b.err = ErrUnknownPasswordAlgorithm
		return
	}

	data := make([]byte, 0, len(username)+1+len(realm)+1+len(password))
	data = append(data, username...)
	data = append(data, ':')
	data = append(data, realm...)
	data = append(data, ':')
	data = append(data, password...)
	h.Write(data)
	b.messageIntegrity.key = h.Sum(b.messageIntegrity.key[:0])
}

// SetMessageIntegritySHA256 appends a MessageIntegritySHA256 attribute.
func (b *Builder) AddMessageIntegritySHA256(key []byte) {
	b.AddMessageIntegritySHA256Truncated(key, sha256.Size)
}

// SetMessageIntegritySHA256Truncated appends an optionally truncated MessageIntegritySHA256 attribute.
// length the length of the attribute should be between 16 and 32 inclusive, and be divisible by 4.
// See https://tools.ietf.org/html/rfc8489#section-14.6
func (b *Builder) AddMessageIntegritySHA256Truncated(key []byte, length int) {
	if b.err != nil {
		return
	}
	if length > sha256.Size || length < 16 || length%4 != 0 {
		b.err = ErrInvalidMessageIntegritySHA256Length
		return
	}
	b.messageIntegritySHA256.key = append(b.messageIntegritySHA256.key[:0], key...)
}

// SetSoftware appends Software attribute to the STUN message.
// Must be the last attribute appended to a STUN message.
// See https://tools.ietf.org/html/rfc8489#section-14.7
func (b *Builder) AddFingerprint() {
	b.addFingerprint = true
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

// See https://tools.ietf.org/html/rfc8489#section-14.11
func (b *Builder) SetPasswordAlgorithms() {
	// @TODO
}

// See https://tools.ietf.org/html/rfc8489#section-14.13
func (b *Builder) SetUnknownAttributes(attributes ...uint16) {
	if b.err != nil {
		return
	}
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

func (b *Builder) SetICEControlled(r uint64) {
	if b.err != nil {
		return
	}
	b.msg = appendICEControlled(b.msg, r)
}

// Build return the raw STUN message or an error if one occurred during it's building.
func (b *Builder) Build() ([]byte, error) {
	if b.err != nil {
		return nil, b.err
	}
	m := b.msg
	if len(b.messageIntegrity.key) != 0 {
		m = appendMessageIntegrity(m, b.messageIntegrity.key)
	}
	if len(b.messageIntegritySHA256.key) != 0 {
		m = appendMessageIntegritySHA256(m, b.messageIntegritySHA256.key)
	}
	if b.addFingerprint {
		m = appendFingerprint(m)
	}
	binary.BigEndian.PutUint16(m[2:4], uint16(len(m)-headerSize))
	return m, nil
}
