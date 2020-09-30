package stun

import (
	"crypto/sha1"
	"crypto/sha256"
	"encoding/binary"
)

func attributeType(a []byte) attr { return attr(binary.BigEndian.Uint16(a[:2])) }
func attributeSize(a []byte) int  { return int(uint(binary.BigEndian.Uint16(a[2:4]))) }

type keyGenerator struct {
	password          string
	username          []byte
	realm             []byte
	userHash          []byte
	passwordAlgorithm PasswordAlgorithm
}

func (k *keyGenerator) GetPassword() ([]byte, error) {
	return []byte{15: 0}, nil
}

func (k *keyGenerator) GetPasswordByUserHash(userHash []byte) ([]byte, error) {
	return []byte{15: 0}, nil
}

func (k *keyGenerator) GetPasswordUsernameRealm(username, realm []byte) ([]byte, error) {
	return []byte{15: 0}, nil
}

func (k *keyGenerator) Generate(b []byte) ([]byte, error) {
	var (
		key []byte
		err error
	)

	if len(k.userHash) != 0 {
		key, err = k.GetPasswordByUserHash(k.userHash)
		if err != nil {
			return nil, err
		}
	} else {
		if len(k.realm) == 0 {
			return []byte(k.password), nil
		}
		if len(k.username) == 0 {
			return nil, ErrMissingUsername
		}
		key, err = k.GetPasswordUsernameRealm(k.username, k.realm)
		if err != nil {
			return nil, err
		}
	}
	switch k.passwordAlgorithm {
	case PasswordAlgorithmMD5:
		return appendLongTermKeyMD5(b, k.username, k.realm, key), nil
	case PasswordAlgorithmSHA256:
		return appendLongTermKeySHA256(b, k.username, k.realm, key), nil
	default:
		return nil, ErrUnknownPasswordAlgorithm
	}
}

type Parser struct {
	key []byte
}

func NewParser() (*Parser, error) {
	return &Parser{}, nil
}

func (p *Parser) SetPassword(password string) {
	p.key = append(p.key[:0], password...)
}

func (p *Parser) Parse(dst *Message, in []byte) error {
	if len(in) < headerSize {
		return ErrNotASTUNMessage
	}
	// Top two bits must be 0
	if in[0] > 0x3F {
		return ErrNotASTUNMessage
	}
	// Size (and should be multiple of 4)
	if s := int(binary.BigEndian.Uint16(in[2:4])); s+headerSize != len(in) || s%4 != 0 {
		return ErrNotASTUNMessage
	}
	// Magic Cookie
	if binary.BigEndian.Uint32(in[4:8]) != magicCookie {
		return ErrNotASTUNMessage
	}

	keyGen := keyGenerator{passwordAlgorithm: PasswordAlgorithmMD5}

	bytesParsed := headerSize
	for attrs := in[headerSize:]; len(attrs) > 4; attrs = in[bytesParsed:] {
		attrType, attrSize := attributeType(attrs), attributeSize(attrs)
		attrValue := attrs[4:]
		if len(attrValue) < attrSize {
			return ErrUnexpectedEOF
		}
		switch attrType {

		case attrUsername:
			if attrSize > maxUsernameByteLength {
				return ErrUsernameTooLong
			}
			keyGen.username = attrValue[:attrSize]

		case attrRealm:
			if attrSize > maxRealmByteLength {
				return ErrRealmTooLong
			}
			keyGen.realm = attrValue[:attrSize]

		case attrNonce:
			if attrSize < len(nonceSecurityFeaturesPrefix)+4 ||
				string(attrValue[:len(nonceSecurityFeaturesPrefix)]) != nonceSecurityFeaturesPrefix {
				break
			}
			// @TODO base64 decode security feature bits?

		case attrPasswordAlgorithm:
			if attrSize < 4 {
				return ErrUnexpectedEOF
			}
			switch a := PasswordAlgorithm(binary.BigEndian.Uint16(attrValue[:2])); a {
			case PasswordAlgorithmMD5, PasswordAlgorithmSHA256:
				keyGen.passwordAlgorithm = a
			default:
				return ErrUnknownPasswordAlgorithm
			}

		case attrUserHash:
			if attrSize != sha256.Size {
				return ErrInvalidUserHash
			}
			keyGen.userHash = attrValue[:sha256.Size]

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

			if !validateHMACSHA1(in[:bytesParsed], attrValue, keyGen) {
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
			if !validateHMACSHA256(in[:bytesParsed], attrValue, keyGen) {
				return ErrMessageIntegritySHA256
			}

		case attrFingerprint:
			if attrSize != 4 {
				return ErrFingerprint
			}
			// fingerprint must be the last attribute, len(attrValue) > 4 provides that condition
			if len(attrValue) > 4 {
				return ErrInvalidAttributeSequence
			}
			if !validateFingerprint(in[:bytesParsed], binary.BigEndian.Uint32(attrValue)) {
				return ErrFingerprint
			}
		}
		bytesParsed += (attrSize + 7) & ^3
	}

	dst.typ = Type(binary.BigEndian.Uint16(in[:2]))
	copy(dst.txID[:], in[8:])

	return nil
}
