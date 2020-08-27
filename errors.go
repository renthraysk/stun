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

	ErrUnexpectedEOF = errorString("unexpected EOF")

	ErrUsernameTooLong       = errorString("username too long")
	ErrRealmTooLong          = errorString("realm too long")
	ErrNonceTooLong          = errorString("nonce too long")
	ErrSoftwareTooLong       = errorString("software too long")
	ErrMissingUsername       = errorString("missing username")
	ErrMissingRealm          = errorString("missing realm")
	ErrInvalidUserHashLength = errorString("invalid userhash length")
	ErrInvalidErrorCode      = errorString("invalid error code")
	ErrReasonTooLong         = errorString("reason too long")
	ErrDomainTooLong         = errorString("domain too long")

	ErrInvalidAttributeSequence            = errorString("invalid attribute sequence")
	ErrInvalidMessageIntegritySHA256Length = errorString("invalid MessageIntegritySHA256 length")
)
