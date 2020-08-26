package stun

type errorString string

func (e errorString) Error() string { return string(e) }

const (
	ErrMalformedAttribute       = errorString("malformed attribute")
	ErrNotASTUNMessage          = errorString("not a stun message")
	ErrFingerprint              = errorString("fingerprint check failed")
	ErrMessageIntegrity         = errorString("messageintegrity check failed")
	ErrMessageIntegritySHA256   = errorString("messageintegritysha256 check failed")
	ErrUnknownPasswordAlgorithm = errorString("unknown password algorithm")
	ErrUsernameTooLong          = errorString("username too long")
	ErrRealmTooLong             = errorString("realm too long")
	ErrMissingUsername          = errorString("missing username")
	ErrMissingRealm             = errorString("missing realm")

	ErrAttrInvalidAttributeAppend          = errorString("invalid attribute appended after MessageIntegrity, MessageIntegritySHA256 or Fingerprint")
	ErrInvalidMessageIntegritySHA256Length = errorString("invalid MessageIntegritySHA256 length")
)
